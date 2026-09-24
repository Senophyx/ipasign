"""CMS / PKCS#7 signature generation.

Apple seals a code signature with a detached CMS ``SignedData`` whose content is
the CodeDirectory. The structure carries a handful of signed attributes, three of
them standard and two Apple specific, and one detail decides whether the result
verifies at all: the RSA signature is computed over the signed attributes
encoded as a ``SET OF`` (tag ``0x31``), not over the ``[0]`` implicit form the
SignerInfo carries them in. RFC 5652 section 5.4 signs the SET value; signing the
implicit form produces a blob that parses cleanly and that ``codesign`` rejects
with "code or signature have been modified".
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass

from asn1crypto import algos, cms, core, x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .credentials import Identity
from .errors import BlobError

OID_APPLE_CDHASHES_PLIST = "1.2.840.113635.100.9.1"
OID_APPLE_CDHASHES = "1.2.840.113635.100.9.2"

# Content bytes of OID 2.16.840.1.101.3.4.2.1 (sha256). The wrapping SEQUENCE
# carries no parameters: adding a NULL there changes the bytes and breaks
# parity with Apple's own output.
_SHA256_OID_CONTENT = bytes.fromhex("608648016503040201")


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(body)) + body


def _apple_cdhash_attribute(digest: bytes) -> bytes:
    """``SEQUENCE { OID sha256, OCTET STRING <digest> }`` for attribute 9.2."""
    inner = _der_tlv(0x06, _SHA256_OID_CONTENT)
    return _der_tlv(0x30, inner + _der_tlv(0x04, digest))


def _asn1_certificate(cert: x509.Certificate) -> asn1x509.Certificate:
    return asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


@dataclass(slots=True)
class CmsParts:
    """The inputs the CMS builder needs, already hashed by the caller."""

    code_directory: bytes
    cdhashes_plist: bytes
    apple_hash: bytes
    signing_time: datetime.datetime | None = None


def build_cms(identity: Identity, parts: CmsParts) -> bytes:
    """Build the detached CMS ``SignedData`` for a signed CodeDirectory."""
    code_directory = parts.code_directory
    if not code_directory:
        raise BlobError("cannot sign an empty CodeDirectory")
    if len(parts.apple_hash) != hashes.SHA256.digest_size:
        raise BlobError("Apple cdhashes attribute needs a full SHA-256 digest")

    digest = hashlib.sha256(code_directory).digest()
    signing_time = parts.signing_time or datetime.datetime.now(datetime.timezone.utc)

    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
            cms.CMSAttribute(
                {
                    "type": "signing_time",
                    "values": [cms.Time({"utc_time": signing_time})],
                }
            ),
            cms.CMSAttribute(
                {"type": "message_digest", "values": [core.OctetString(digest)]}
            ),
            cms.CMSAttribute(
                {
                    "type": OID_APPLE_CDHASHES,
                    "values": [core.Any.load(_apple_cdhash_attribute(parts.apple_hash))],
                }
            ),
            cms.CMSAttribute(
                {
                    "type": OID_APPLE_CDHASHES_PLIST,
                    "values": [core.OctetString(parts.cdhashes_plist)],
                }
            ),
        ]
    )

    # RFC 5652: the signature covers the SET-encoded attributes, never the
    # implicit [0] form the SignerInfo stores them in.
    signature = identity.private_key.sign(
        signed_attrs.dump(), padding.PKCS1v15(), hashes.SHA256()
    )

    leaf = identity.certificate
    signer = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": asn1x509.Name.load(leaf.issuer.public_bytes()),
                            "serial_number": leaf.serial_number,
                        }
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm(
                {"algorithm": "sha256", "parameters": None}
            ),
            "signed_attrs": signed_attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {"algorithm": "rsassa_pkcs1v15"}
            ),
            "signature": signature,
        }
    )

    certificates = cms.CertificateSet(
        [cms.CertificateChoices({"certificate": _asn1_certificate(cert)}) for cert in identity.chain]
    )

    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": cms.DigestAlgorithms(
                [algos.DigestAlgorithm({"algorithm": "sha256", "parameters": None})]
            ),
            "encap_content_info": cms.ContentInfo({"content_type": "data"}),
            "certificates": certificates,
            "signer_infos": cms.SignerInfos([signer]),
        }
    )

    return cms.ContentInfo(
        {"content_type": "signed_data", "content": signed_data}
    ).dump()


def cms_content(cms_bytes: bytes) -> bytes | None:
    """Return the detached content of a CMS blob, or None when absent."""
    info = cms.ContentInfo.load(cms_bytes)
    content = info["content"]["encap_content_info"]["content"]
    return content.native if content.native else None


__all__ = ["CmsParts", "build_cms"]
