"""Tests for certificate inspection."""

from __future__ import annotations

import datetime
import shutil
import unittest
import zipfile
from pathlib import Path

from asn1crypto import algos, core
from asn1crypto import ocsp as asn1_ocsp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

import importlib

from ipasign.check import certificate_info
from ipasign.credentials import Identity
from ipasign.errors import CredentialError, InvalidInputError
from ipasign.signer import FileContext, Signer, sign_file_data

from . import fixtures

check = importlib.import_module("ipasign.check")

def _build_cert(
    cn: str,
    *,
    org: str | None = None,
    ou: str | None = None,
    days: int = 365,
    key: object | None = None,
) -> tuple[object, x509.Certificate]:
    """A self-signed certificate with the given subject fields.

    Used to exercise the field mapping without needing a real Apple chain.
    """
    key = key if key is not None else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org is not None:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if ou is not None:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    name = x509.Name(attributes)
    now = datetime.datetime.now(datetime.timezone.utc)
    # An expired certificate keeps a valid window; only its end moves into the
    # past, so the notBefore/notAfter pair stays ordered.
    start = now - datetime.timedelta(days=1)
    end = now + datetime.timedelta(days=days)
    if end <= start:
        start = end - datetime.timedelta(days=1)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x12DEFACE)
        .not_valid_before(start)
        .not_valid_after(end)
        .sign(key, hashes.SHA256())
    )
    return key, certificate

def _identity(cn: str = "Apple Distribution: Test Corp (ABCDE12345)", **kwargs) -> Identity:
    key, certificate = _build_cert(cn, org="Test Corp", ou="ABCDE12345", **kwargs)
    return Identity(private_key=key, certificate=certificate, chain=[certificate])

class TypeDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("check_type")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_extension_wins(self) -> None:
        _key, certificate = _build_cert("iPhone Developer: Test Corp", ou="ABCDE12345")
        path = self.root / "profile.mobileprovision"
        path.write_bytes(
            fixtures.mobileprovision(
                developer_certificates=[certificate.public_bytes(serialization.Encoding.DER)]
            )
        )
        self.assertEqual(check.check(path, ocsp=False).type, "Provision")

    def test_ipa_by_content(self) -> None:
        path = self.root / "bundle.bin"
        path.write_bytes(b"PK\x03\x04rest")
        result = check.check(path, ocsp=False)
        self.assertEqual(result.type, "IPA")
        self.assertFalse(result.signed)

    def test_macho_by_content(self) -> None:
        path = self.root / "Runner"
        path.write_bytes(fixtures.minimal_macho())
        result = check.check(path, ocsp=False)
        self.assertEqual(result.type, "Mach-O")
        self.assertFalse(result.signed)
        self.assertEqual(result.code, -2)

    def test_unknown_raises(self) -> None:
        path = self.root / "mystery"
        path.write_bytes(b"hello world, not any known format")
        with self.assertRaises(InvalidInputError):
            check.check(path)

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(InvalidInputError):
            check.check(self.root / "absent.bin")

class CertificateFieldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key, cls.certificate = _build_cert(
            "Apple Distribution: Test Corp (ABCDE12345)", org="Test Corp", ou="ABCDE12345"
        )

    def test_fields_are_mapped(self) -> None:
        info = certificate_info(self.certificate)
        self.assertEqual(info.name, "Apple Distribution: Test Corp (ABCDE12345)")
        self.assertEqual(info.type, "Apple Distribution")
        self.assertEqual(info.org, "Test Corp")
        self.assertEqual(info.team, "ABCDE12345")
        self.assertEqual(info.algorithm, "RSA 2048-bit")
        self.assertFalse(info.expired)
        self.assertGreater(info.days_remaining, 0)

    def test_serial_is_colon_separated_hex(self) -> None:
        info = certificate_info(self.certificate)
        self.assertEqual(info.serial, "12:DE:FA:CE")

    def test_issued_and_expires_are_iso_utc(self) -> None:
        info = certificate_info(self.certificate)
        self.assertRegex(info.issued, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertRegex(info.expires, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_absent_org_and_team_are_none(self) -> None:
        _key, certificate = _build_cert("iPhone Developer: Test")
        info = certificate_info(certificate)
        self.assertIsNone(info.org)
        self.assertIsNone(info.team)

    def test_expired_certificate(self) -> None:
        _key, certificate = _build_cert("Test", days=-10)
        info = certificate_info(certificate)
        self.assertTrue(info.expired)
        self.assertLess(info.days_remaining, 0)

    def test_type_falls_back_to_certificate(self) -> None:
        _key, certificate = _build_cert("Some Random Name")
        self.assertEqual(certificate_info(certificate).type, "Certificate")

    def test_ec_algorithm(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        _key, certificate = _build_cert("Test", key=key)
        self.assertEqual(certificate_info(certificate).algorithm, "EC 256-bit")

class FileLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("check_load")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_der_certificate(self) -> None:
        _key, certificate = _build_cert(
            "Apple Distribution: Test Corp", org="Test Corp", ou="ABCDE"
        )
        path = self.root / "leaf.cer"
        path.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
        result = check.check(path, ocsp=False)
        self.assertEqual(result.type, "DER")
        self.assertIsNone(result.signed)
        self.assertEqual(result.certificate.team, "ABCDE")

    def test_pem_certificate(self) -> None:
        _key, certificate = _build_cert("Apple Development: Test")
        path = self.root / "leaf.pem"
        path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        result = check.check(path, ocsp=False)
        self.assertEqual(result.type, "PEM")
        self.assertEqual(result.certificate.type, "Apple Development")

    def test_p13_with_password(self) -> None:
        _key, certificate = _build_cert(
            "Apple Distribution: Test Corp", org="Test Corp", ou="ABCDE"
        )
        identity = Identity(private_key=_key, certificate=certificate, chain=[certificate])
        path = self.root / "identity.p12"
        path.write_bytes(
            pkcs12.serialize_key_and_certificates(
                b"test",
                identity.private_key,
                identity.certificate,
                None,
                serialization.BestAvailableEncryption(b"secret"),
            )
        )
        result = check.check(path, "secret", ocsp=False)
        self.assertEqual(result.type, "PKCS#12")
        self.assertEqual(result.name, certificate_info(certificate).name)

    def test_p12_with_wrong_password_raises(self) -> None:
        _key, certificate = _build_cert("Test")
        path = self.root / "identity.p12"
        path.write_bytes(
            pkcs12.serialize_key_and_certificates(
                b"test",
                _key,
                certificate,
                None,
                serialization.BestAvailableEncryption(b"right"),
            )
        )
        with self.assertRaises(CredentialError):
            check.check(path, "wrong")

    def test_provision_profile(self) -> None:
        _key, certificate = _build_cert("iPhone Developer: Test Corp", ou="ABCDE12345")
        data = fixtures.mobileprovision(
            developer_certificates=[certificate.public_bytes(serialization.Encoding.DER)]
        )
        path = self.root / "profile.mobileprovision"
        path.write_bytes(data)
        result = check.check(path, ocsp=False)
        self.assertEqual(result.type, "Provision")
        self.assertEqual(result.team, "ABCDE12345")

class MachOExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("check_macho")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_unsigned_macho_reports_not_signed(self) -> None:
        path = self.root / "Runner"
        path.write_bytes(fixtures.minimal_macho())
        result = check.check(path, ocsp=False)
        self.assertFalse(result.signed)
        self.assertIsNone(result.certificate)
        self.assertEqual(result.status, "not_signed")

    def test_signed_macho_extracts_the_leaf(self) -> None:
        identity = _identity()
        signer = Signer(identity=identity, team_id="ABCDE12345", subject_cn=identity.subject_cn)
        signed, _ = sign_file_data(
            signer, fixtures.minimal_macho(), FileContext(bundle_id="com.example.test")
        )
        path = self.root / "Runner"
        path.write_bytes(signed)

        result = check.check(path, ocsp=False)
        self.assertTrue(result.signed)
        self.assertEqual(result.type, "Mach-O")
        self.assertEqual(result.name, "Apple Distribution: Test Corp (ABCDE12345)")
        self.assertEqual(result.certificate.team, "ABCDE12345")

class IpaExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("check_ipa")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _write_ipa(self, path: Path, executable: bytes) -> Path:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Payload/Test.app/Info.plist", fixtures.info_plist())
            archive.writestr("Payload/Test.app/Test", executable)
        return path

    def test_unsigned_ipa(self) -> None:
        path = self._write_ipa(self.root / "app.ipa", fixtures.minimal_macho())
        result = check.check(path, ocsp=False)
        self.assertEqual(result.type, "IPA")
        self.assertFalse(result.signed)
        self.assertEqual(result.code, -2)

    def test_signed_ipa(self) -> None:
        identity = _identity()
        signer = Signer(identity=identity, team_id="ABCDE12345", subject_cn=identity.subject_cn)
        signed, _ = sign_file_data(
            signer, fixtures.minimal_macho(), FileContext(bundle_id="com.example.test")
        )
        path = self._write_ipa(self.root / "signed.ipa", signed)

        result = check.check(path, ocsp=False)
        self.assertTrue(result.signed)
        self.assertEqual(result.name, "Apple Distribution: Test Corp (ABCDE12345)")

class OcspParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.identity = _identity()
        cls.certificate = cls.identity.certificate
        cls.name_hash, cls.key_hash = check._cert_id_hashes(cls.certificate, cls.certificate)

    def _response(self, status: str, cert_status: object) -> bytes:
        now = datetime.datetime.now(datetime.timezone.utc)
        basic = asn1_ocsp.BasicOCSPResponse(
            {
                "tbs_response_data": {
                    "responder_id": asn1_ocsp.ResponderId(
                        name="by_key", value=core.OctetString(b"\x01" * 20)
                    ),
                    "produced_at": now,
                    "responses": [
                        {
                            "cert_id": {
                                "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha1"}),
                                "issuer_name_hash": core.OctetString(self.name_hash),
                                "issuer_key_hash": core.OctetString(self.key_hash),
                                "serial_number": self.certificate.serial_number,
                            },
                            "cert_status": cert_status,
                            "this_update": now,
                        }
                    ],
                },
                "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
                "signature": core.OctetBitString(b"\x00" * 16),
            }
        )
        return asn1_ocsp.OCSPResponse(
            {
                "response_status": status,
                "response_bytes": {
                    "response_type": "basic_ocsp_response",
                    "response": basic,
                },
            }
        ).dump()

    def _parse(self, payload: bytes):
        return check._parse_ocsp(payload, self.certificate, self.name_hash, self.key_hash)

    def test_good_is_valid(self) -> None:
        payload = self._response("successful", asn1_ocsp.CertStatus(name="good", value=core.Null()))
        self.assertEqual(self._parse(payload).status, "Valid")

    def test_revoked_carries_the_time(self) -> None:
        when = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
        payload = self._response(
            "successful",
            asn1_ocsp.CertStatus(name="revoked", value={"revocation_time": when}),
        )
        result = self._parse(payload)
        self.assertEqual(result.status, "Revoked")
        self.assertEqual(result.revoked_time, "2026-01-02T03:04:05Z")

    def test_unknown_status(self) -> None:
        payload = self._response(
            "successful", asn1_ocsp.CertStatus(name="unknown", value=core.Null())
        )
        self.assertEqual(self._parse(payload).status, "Unknown")

    def test_non_successful_response_is_an_error(self) -> None:
        payload = asn1_ocsp.OCSPResponse({"response_status": "unauthorized"}).dump()
        result = self._parse(payload)
        self.assertEqual(result.status, "Error")
        self.assertIn("unauthorized", result.detail)

    def test_garbage_response_is_an_error(self) -> None:
        self.assertEqual(self._parse(b"not der at all").status, "Error")

    def test_unrelated_serial_is_unknown(self) -> None:
        payload = self._response("successful", asn1_ocsp.CertStatus(name="good", value=core.Null()))
        _key, other = _build_cert("Other")
        name_hash, key_hash = check._cert_id_hashes(other, other)
        result = check._parse_ocsp(payload, other, name_hash, key_hash)
        self.assertEqual(result.status, "Unknown")

class ResultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("check_result")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _der_path(self, cn: str = "Apple Distribution: Test Corp", days: int = 365) -> Path:
        _key, certificate = _build_cert(cn, org="Test Corp", ou="ABCDE12345", days=days)
        path = self.root / "leaf.cer"
        path.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
        return path

    def test_ocsp_disabled_is_skipped_and_valid(self) -> None:
        result = check.check(self._der_path(), ocsp=False)
        self.assertEqual(result.ocsp.status, "Skipped")
        self.assertEqual(result.code, 0)
        self.assertEqual(result.status, "valid")

    def test_expired_certificate_codes_to_expired(self) -> None:
        result = check.check(self._der_path(days=-5), ocsp=False)
        self.assertEqual(result.code, 2)
        self.assertEqual(result.status, "expired")
        self.assertTrue(result.expired)

    def test_str_is_the_json_document(self) -> None:
        result = check.check(self._der_path(), ocsp=False)
        self.assertEqual(str(result), result.to_json())
        self.assertIn('"type": "DER"', str(result))

    def test_document_shape(self) -> None:
        import json

        document = json.loads(check.check(self._der_path(), ocsp=False).to_json())
        self.assertEqual(set(document), {"check", "signed", "certificate", "ocsp", "result"})
        self.assertEqual(document["result"], {"code": 0, "status": "valid"})
        self.assertIsNone(document["signed"])
        self.assertEqual(document["ocsp"]["status"], "Skipped")

    def test_certificate_properties_forwarded(self) -> None:
        result = check.check(self._der_path(), ocsp=False)
        self.assertEqual(result.name, result.certificate.name)
        self.assertEqual(result.expires, result.certificate.expires)
        self.assertEqual(result.team, "ABCDE12345")
        self.assertEqual(result.type, "DER")

    def test_certificate_properties_are_none_without_a_certificate(self) -> None:
        path = self.root / "Runner"
        path.write_bytes(fixtures.minimal_macho())
        result = check.check(path, ocsp=False)
        self.assertIsNone(result.name)
        self.assertIsNone(result.expires)
        self.assertIsNone(result.certificate)

class IssuerResolutionTests(unittest.TestCase):
    def test_chain_member_that_issued_the_leaf_wins(self) -> None:
        issuer = _identity("Issuer").certificate
        _key, leaf = _build_cert("Leaf")
        # Rebuild the leaf so its issuer is the other certificate.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")]))
            .issuer_name(issuer.subject)
            .public_key(key.public_key())
            .serial_number(1234)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        self.assertIs(check._resolve_issuer(leaf, [issuer]), issuer)

    def test_public_key_bits_are_hashed_from_pkcs1(self) -> None:
        identity = _identity()
        bits = check._public_key_bits(identity.certificate)
        expected = identity.certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
        self.assertEqual(bits, expected)

if __name__ == "__main__":
    unittest.main()
