"""Tests for the CMS / PKCS#7 signature builder."""

from __future__ import annotations

import datetime
import hashlib
import unittest

from asn1crypto import cms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ipasign.cms import CmsParts, build_cms
from ipasign.errors import BlobError

from . import fixtures

SIGNING_TIME = datetime.datetime(2026, 9, 23, 13, 0, 54, tzinfo=datetime.timezone.utc)


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


class CmsBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.identity = fixtures.test_identity()
        cls.code_directory = fixtures.test_code_directory()

    def build(self, **overrides) -> bytes:
        parts = CmsParts(
            code_directory=overrides.pop("code_directory", self.code_directory),
            cdhashes_plist=overrides.pop("cdhashes_plist", b"<plist/>"),
            apple_hash=overrides.pop("apple_hash", hashlib.sha256(self.code_directory).digest()),
            signing_time=overrides.pop("signing_time", SIGNING_TIME),
        )
        return build_cms(overrides.pop("identity", self.identity), parts)

    def test_content_type_is_detached_signed_data(self) -> None:
        info = cms.ContentInfo.load(self.build())
        self.assertEqual(info["content_type"].native, "signed_data")
        data = info["content"]
        self.assertIsNone(
            data["encap_content_info"]["content"].native, "the content must be detached"
        )

    def test_digest_algorithm_has_no_parameters(self) -> None:
        """A NULL parameter here would change the bytes and break parity."""
        info = cms.ContentInfo.load(self.build())
        digest_alg = info["content"]["signer_infos"][0]["digest_algorithm"]
        self.assertEqual(digest_alg.dump(), bytes.fromhex("300b0609608648016503040201"))

    def test_signature_algorithm_is_rsa_pkcs1v15(self) -> None:
        info = cms.ContentInfo.load(self.build())
        alg = info["content"]["signer_infos"][0]["signature_algorithm"]
        self.assertEqual(alg["algorithm"].native, "rsassa_pkcs1v15")

    def test_message_digest_is_sha256_of_the_code_directory(self) -> None:
        info = cms.ContentInfo.load(self.build())
        attrs = {a["type"].dotted: a for a in info["content"]["signer_infos"][0]["signed_attrs"]}
        self.assertEqual(
            attrs["1.2.840.113549.1.9.4"]["values"][0].native,
            hashlib.sha256(self.code_directory).digest(),
        )

    def test_signing_time_is_carried(self) -> None:
        info = cms.ContentInfo.load(self.build())
        attrs = {a["type"].dotted: a for a in info["content"]["signer_infos"][0]["signed_attrs"]}
        self.assertEqual(attrs["1.2.840.113549.1.9.5"]["values"][0].native, SIGNING_TIME)

    def test_apple_attributes_are_present(self) -> None:
        info = cms.ContentInfo.load(self.build())
        dotted = {a["type"].dotted for a in info["content"]["signer_infos"][0]["signed_attrs"]}
        self.assertIn("1.2.840.113635.100.9.1", dotted)
        self.assertIn("1.2.840.113635.100.9.2", dotted)

    def test_signed_attrs_are_strictly_ascending_over_der(self) -> None:
        """RFC 5652 requires SET OF order; Apple's verifier depends on it."""
        info = cms.ContentInfo.load(self.build())
        attrs = info["content"]["signer_infos"][0]["signed_attrs"]
        encodings = [attrs[i].dump() for i in range(len(attrs))]
        self.assertEqual(encodings, sorted(encodings), "DER SET OF must be sorted")

    def test_certificates_are_embedded_with_leaf_last(self) -> None:
        info = cms.ContentInfo.load(self.build())
        certs = info["content"]["certificates"]
        self.assertGreaterEqual(len(certs), 1)
        leaf = certs[-1].chosen
        expected = self.identity.certificate.subject.public_bytes()
        self.assertEqual(leaf.subject.dump(), expected, "the leaf must be the last certificate")


class CmsSignatureTests(unittest.TestCase):
    """The single most important detail: the SET tag, not the implicit [0]."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.identity = fixtures.test_identity()
        cls.der = build_cms(
            cls.identity,
            CmsParts(
                code_directory=fixtures.test_code_directory(),
                cdhashes_plist=b"<plist/>",
                apple_hash=b"\x11" * 32,
                signing_time=SIGNING_TIME,
            ),
        )

    def test_signature_verifies_over_the_set_form(self) -> None:
        signer = cms.ContentInfo.load(self.der)["content"]["signer_infos"][0]
        contents = signer["signed_attrs"].contents
        signed = b"\x31" + der_length(len(contents)) + contents

        self.identity.certificate.public_key().verify(
            signer["signature"].native, signed, padding.PKCS1v15(), hashes.SHA256()
        )

    def test_signature_does_not_verify_over_the_implicit_form(self) -> None:
        signer = cms.ContentInfo.load(self.der)["content"]["signer_infos"][0]
        implicit = signer["signed_attrs"].dump()
        self.assertEqual(implicit[0], 0xA0, "the wire form uses the implicit [0] tag")
        with self.assertRaises(Exception):
            self.identity.certificate.public_key().verify(
                signer["signature"].native, implicit, padding.PKCS1v15(), hashes.SHA256()
            )

    def test_signed_attrs_tag_is_set_not_implicit(self) -> None:
        signer = cms.ContentInfo.load(self.der)["content"]["signer_infos"][0]
        attrs = signer["signed_attrs"]
        # On the wire the attribute set carries the implicit [0] tag.
        self.assertEqual(attrs.dump()[0], 0xA0)
        # The value that was signed is the universal SET OF (identifier 0x31,
        # tag number 0x11), which asn1crypto reports without class bits.
        self.assertEqual(type(attrs).tag, 0x11, "the underlying type is SET OF")

        signed = b"\x31" + der_length(len(attrs.contents)) + attrs.contents
        # The wire form differs only in the tag byte, so the signed form itself
        # never appears in the encoding while its contents do.
        self.assertNotEqual(attrs.dump(), signed, "the two encodings differ")
        self.assertEqual(attrs.dump()[1:], signed[1:], "only the tag byte differs")
        self.assertIn(attrs.contents, self.der, "contents appear verbatim in the encoding")


class CmsAppleAttributeTests(unittest.TestCase):
    def test_cdhashes_attribute_shape(self) -> None:
        """9.2 is SEQUENCE { OID sha256, OCTET STRING digest }, no parameters."""
        identity = fixtures.test_identity()
        digest = b"\x22" * 32
        der = build_cms(
            identity,
            CmsParts(
                code_directory=fixtures.test_code_directory(),
                cdhashes_plist=b"<plist/>",
                apple_hash=digest,
                signing_time=SIGNING_TIME,
            ),
        )
        info = cms.ContentInfo.load(der)
        attrs = {a["type"].dotted: a for a in info["content"]["signer_infos"][0]["signed_attrs"]}
        value = attrs["1.2.840.113635.100.9.2"]["values"][0].parsed
        self.assertEqual(value[0].dotted, "2.16.840.1.101.3.4.2.1")
        self.assertEqual(value[1].native, digest)

    def test_cdhashes_plist_attribute_carries_the_bytes(self) -> None:
        identity = fixtures.test_identity()
        plist = b"<plist>cdhashes</plist>"
        der = build_cms(
            identity,
            CmsParts(
                code_directory=fixtures.test_code_directory(),
                cdhashes_plist=plist,
                apple_hash=b"\x33" * 32,
                signing_time=SIGNING_TIME,
            ),
        )
        info = cms.ContentInfo.load(der)
        attrs = {a["type"].dotted: a for a in info["content"]["signer_infos"][0]["signed_attrs"]}
        self.assertEqual(attrs["1.2.840.113635.100.9.1"]["values"][0].native, plist)


class CmsValidationTests(unittest.TestCase):
    def test_empty_code_directory_raises(self) -> None:
        with self.assertRaises(BlobError):
            build_cms(
                fixtures.test_identity(),
                CmsParts(code_directory=b"", cdhashes_plist=b"", apple_hash=b"\x00" * 32),
            )

    def test_short_apple_hash_raises(self) -> None:
        with self.assertRaises(BlobError):
            build_cms(
                fixtures.test_identity(),
                CmsParts(
                    code_directory=fixtures.test_code_directory(),
                    cdhashes_plist=b"",
                    apple_hash=b"\x00" * 20,
                ),
            )


if __name__ == "__main__":
    unittest.main()
