"""Certificate inspection.

Reads the certificate a signature was made with and reports whether it is
still usable: subject, team, validity window and OCSP revocation status.

The entry point is :func:`check`, which accepts anything that carries or is a
certificate: an ``.ipa``, a Mach-O binary, a ``.mobileprovision``, a ``.p12``,
a ``.cer``/``.der`` or a ``.pem``. Nothing here signs, and nothing here writes:
an archive is read straight out of the zip without unpacking it.

The result is a :class:`CertCheckResult`, a frozen dataclass with a
``to_json()``. ``str(result)`` is that JSON, so a caller can print it directly.
"""

from __future__ import annotations

import datetime
import hashlib
import http.client
import json
import socket
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

from asn1crypto import algos, cms, core
from asn1crypto import ocsp as asn1_ocsp
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from . import blobs, macho
from .credentials import _embedded_intermediate, _plist_from_cms
from .errors import CredentialError, InvalidInputError, MachOError

ZIP_MAGIC = b"PK\x03\x04"
MACHO_MAGICS = (
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)

# Extension to reported type, checked before any content sniffing.
_EXTENSION_TYPES = {
    ".mobileprovision": "Provision",
    ".provisionprofile": "Provision",
    ".p12": "PKCS#12",
    ".pfx": "PKCS#12",
    ".cer": "DER",
    ".der": "DER",
    ".crt": "DER",
    ".pem": "PEM",
    ".ipa": "IPA",
    ".zip": "IPA",
}

# Certificate kinds, matched against the subject common name as substrings.
_CERTIFICATE_TYPES = (
    "Apple Distribution",
    "iPhone Distribution",
    "Apple Development",
    "iPhone Developer",
    "Mac Developer",
    "Developer ID Application",
    "Developer ID Installer",
)

_STATUS_NAMES = {
    0: "valid",
    1: "revoked",
    2: "expired",
    -1: "error",
    -2: "not_signed",
}

@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """What the signing certificate says about itself."""

    name: str
    type: str
    org: str | None
    team: str | None
    serial: str
    issued: str
    expires: str
    days_remaining: int
    expired: bool
    algorithm: str
    issuer: str

@dataclass(frozen=True, slots=True)
class OcspResult:
    """The outcome of an OCSP revocation query.

    ``status`` is one of ``Valid``, ``Revoked``, ``Unknown``, ``Error`` or
    ``Skipped`` (the issuer is not a known Apple intermediate, so no network
    call was made).
    """

    status: str
    revoked_time: str | None = None
    detail: str | None = None

@dataclass(frozen=True, slots=True)
class CertCheckResult:
    """The whole report: what was checked, the certificate and its OCSP status.

    ``signed`` is ``True``/``False`` for an archive or a Mach-O, and ``None``
    for a credential file where the question does not apply. ``code`` keeps the
    reference's numeric outcome (``0`` valid, ``1`` revoked, ``2`` expired,
    ``-2`` not signed, ``-1`` error) and ``status`` is the same thing as a
    stable string.
    """

    path: str
    type: str
    signed: bool | None
    certificate: CertificateInfo | None
    ocsp: OcspResult | None
    code: int
    status: str

    def to_json(self, indent: int = 2) -> str:
        """The report as a JSON document."""
        document = {
            "check": {"path": self.path, "type": self.type},
            "signed": self.signed,
            "certificate": _certificate_document(self.certificate),
            "ocsp": _ocsp_document(self.ocsp),
            "result": {"code": self.code, "status": self.status},
        }
        return json.dumps(document, indent=indent, ensure_ascii=False)

    def __str__(self) -> str:
        return self.to_json()

    # Convenience access to the certificate fields, so a caller can read
    # ``result.expires`` without going through ``result.certificate``. The
    # certificate's own ``type`` is not forwarded: ``result.type`` already names
    # the file kind, which is what a caller reads there.

    @property
    def name(self) -> str | None:
        return self.certificate.name if self.certificate else None

    @property
    def org(self) -> str | None:
        return self.certificate.org if self.certificate else None

    @property
    def team(self) -> str | None:
        return self.certificate.team if self.certificate else None

    @property
    def serial(self) -> str | None:
        return self.certificate.serial if self.certificate else None

    @property
    def issued(self) -> str | None:
        return self.certificate.issued if self.certificate else None

    @property
    def expires(self) -> str | None:
        return self.certificate.expires if self.certificate else None

    @property
    def days_remaining(self) -> int | None:
        return self.certificate.days_remaining if self.certificate else None

    @property
    def expired(self) -> bool | None:
        return self.certificate.expired if self.certificate else None

    @property
    def algorithm(self) -> str | None:
        return self.certificate.algorithm if self.certificate else None

    @property
    def issuer(self) -> str | None:
        return self.certificate.issuer if self.certificate else None

def check(
    path: str | Path,
    password: str | None = None,
    *,
    ocsp: bool = True,
    timeout: float = 10.0,
) -> CertCheckResult:
    """Inspect the certificate at ``path`` and report its state.

    ``password`` is used only for a ``.p12``. ``ocsp`` turns the revocation
    query off, in which case the result carries ``ocsp.status == "Skipped"``
    and the numeric code still reflects expiry.
    """
    source = Path(path)
    if not source.is_file():
        raise InvalidInputError(f"cannot check a path that is not a file: {source}")

    kind = _EXTENSION_TYPES.get(source.suffix.lower())
    data: bytes | None = None
    if kind is None:
        data = _read(source)
        kind = _sniff(source, data, password)

    chain: list[x509.Certificate] = []
    if kind == "IPA":
        certificate = _certificate_from_ipa(source)
    else:
        if data is None:
            data = _read(source)
        if kind == "Mach-O":
            certificate = _certificate_from_macho(data)
        elif kind == "Provision":
            certificate = _certificate_from_provision(data)
        elif kind == "PKCS#12":
            certificate, chain = _certificate_from_p12(data, password)
        else:  # PEM or DER
            certificate = _certificate_from_der_or_pem(data)

    return _finish(
        str(source),
        kind,
        certificate,
        chain,
        ocsp=ocsp,
        timeout=timeout,
        signed_applicable=kind in ("IPA", "Mach-O"),
    )

def _check_identity(
    path: str,
    certificate: x509.Certificate,
    chain: list[x509.Certificate],
    *,
    ocsp: bool = True,
    timeout: float = 10.0,
) -> CertCheckResult:
    """Check an already-loaded identity. Used by :meth:`ipasign.Key.check`."""
    return _finish(
        path,
        "PKCS#12",
        certificate,
        chain,
        ocsp=ocsp,
        timeout=timeout,
        signed_applicable=False,
    )

def _finish(
    path: str,
    kind: str,
    certificate: x509.Certificate | None,
    chain: list[x509.Certificate],
    *,
    ocsp: bool,
    timeout: float,
    signed_applicable: bool,
) -> CertCheckResult:
    if certificate is None:
        if signed_applicable:
            return CertCheckResult(path, kind, False, None, None, -2, _STATUS_NAMES[-2])
        raise CredentialError(f"no certificate found in {path}")

    info = certificate_info(certificate)
    ocsp_result = _ocsp_for(certificate, chain, ocsp, timeout)
    code = _result_code(ocsp_result.status, info.expired)
    signed = True if signed_applicable else None
    return CertCheckResult(path, kind, signed, info, ocsp_result, code, _STATUS_NAMES[code])

def certificate_info(certificate: x509.Certificate) -> CertificateInfo:
    """The reportable fields of a certificate."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = certificate.not_valid_after_utc
    days = (expires - now).days
    common_name = _name_field(certificate.subject, NameOID.COMMON_NAME)

    return CertificateInfo(
        name=common_name,
        type=_certificate_type(common_name),
        org=_name_field(certificate.subject, NameOID.ORGANIZATION_NAME) or None,
        team=_name_field(certificate.subject, NameOID.ORGANIZATIONAL_UNIT_NAME) or None,
        serial=_serial_hex(certificate.serial_number),
        issued=_iso_utc(certificate.not_valid_before_utc),
        expires=_iso_utc(expires),
        days_remaining=days,
        expired=days < 0,
        algorithm=_algorithm(certificate),
        issuer=_name_field(certificate.issuer, NameOID.COMMON_NAME),
    )

def _sniff(source: Path, data: bytes, password: str | None) -> str:
    """The input kind, decided by content when the extension says nothing."""
    head = data[:4]
    if head == ZIP_MAGIC:
        return "IPA"
    if head in MACHO_MAGICS:
        return "Mach-O"
    if b"<?xml" in data and b"</plist>" in data:
        return "Provision"
    if b"-----BEGIN" in data:
        return "PEM"
    if data[:1] == b"\x30":
        secret = None if password is None else password.encode("utf-8")
        try:
            pkcs12.load_key_and_certificates(data, secret)
        except Exception:
            return "DER"
        return "PKCS#12"
    raise InvalidInputError(f"unknown file type: {source}")

def _read(source: Path) -> bytes:
    try:
        return source.read_bytes()
    except OSError as exc:
        raise InvalidInputError(f"cannot read {source}: {exc}") from exc

def _certificate_from_ipa(source: Path) -> x509.Certificate | None:
    """The leaf certificate sealed into an archive's main executable."""
    try:
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
            prefix = _app_prefix(names)
            if prefix is None:
                return None
            try:
                info = _load_plist(archive.read(prefix + "Info.plist"))
            except Exception:
                return None
            executable = info.get("CFBundleExecutable")
            if not executable:
                return None
            member = prefix + str(executable)
            if member not in names:
                return None
            return _certificate_from_macho(archive.read(member))
    except (OSError, zipfile.BadZipFile):
        return None

def _app_prefix(names: list[str]) -> str | None:
    """The ``Payload/<app>.app/`` prefix of a main bundle, or ``None``."""
    for name in names:
        parts = name.split("/")
        if (
            len(parts) == 3
            and parts[0] == "Payload"
            and parts[1].endswith(".app")
            and parts[2] == "Info.plist"
        ):
            return f"Payload/{parts[1]}/"
    return None

def _certificate_from_macho(data: bytes) -> x509.Certificate | None:
    """The leaf certificate in a Mach-O's embedded CMS signature."""
    try:
        parsed = macho.MachOFile.parse(data)
    except MachOError:
        return None

    for slc in parsed.slices:
        if slc.code_signature is None:
            continue
        offset = slc.base + slc.code_signature.data[0]
        cms_bytes = _superblob_cms(data, offset, slc.code_signature.data[1])
        if cms_bytes is None:
            continue
        certificate = _leaf_from_cms(cms_bytes)
        if certificate is not None:
            return certificate
    return None

def _superblob_cms(data: bytes, offset: int, length: int) -> bytes | None:
    """The CMS bytes of the signature slot in a SuperBlob, or ``None``."""
    if length < 12 or offset < 0 or offset + 12 > len(data):
        return None
    magic, _total, count = struct.unpack_from(">III", data, offset)
    if magic != blobs.CSMAGIC_EMBEDDED_SIGNATURE:
        return None

    cursor = offset + 12
    for _ in range(count):
        if cursor + 8 > len(data):
            return None
        kind, slot_offset = struct.unpack_from(">II", data, cursor)
        cursor += 8
        if kind != blobs.CSSLOT_SIGNATURESLOT:
            continue
        base = offset + slot_offset
        if base + 8 > len(data):
            return None
        blob_magic, blob_length = struct.unpack_from(">II", data, base)
        if blob_magic != blobs.CSMAGIC_BLOBWRAPPER or blob_length <= 8:
            return None
        if base + blob_length > len(data):
            return None
        return bytes(data[base + 8 : base + blob_length])
    return None

def _leaf_from_cms(cms_bytes: bytes) -> x509.Certificate | None:
    """The signing certificate from a CMS ``SignedData``, skipping CA certs."""
    try:
        info = cms.ContentInfo.load(cms_bytes)
        certificates = [
            x509.load_der_x509_certificate(choice.chosen.dump())
            for choice in info["content"]["certificates"]
        ]
    except Exception:
        return None

    if not certificates:
        return None
    if len(certificates) == 1:
        return certificates[0]
    for certificate in certificates:
        if not _is_ca(certificate):
            return certificate
    return certificates[-1]

def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    return bool(constraints.ca)

def _certificate_from_provision(data: bytes) -> x509.Certificate | None:
    """The first developer certificate in a provisioning profile."""
    try:
        profile = _plist_from_cms(data)
    except Exception:
        return None
    for blob in profile.get("DeveloperCertificates") or []:
        if not isinstance(blob, (bytes, bytearray)):
            continue
        try:
            return x509.load_der_x509_certificate(bytes(blob))
        except Exception:
            continue
    return None

def _certificate_from_p12(
    data: bytes, password: str | None
) -> tuple[x509.Certificate | None, list[x509.Certificate]]:
    """The leaf certificate and any chain carried in a ``.p12``."""
    secret = None if password is None else password.encode("utf-8")
    try:
        _key, certificate, extras = pkcs12.load_key_and_certificates(data, secret)
    except Exception as exc:
        raise CredentialError(
            f"cannot open the PKCS#12 file: wrong password or not a p12 ({exc})"
        ) from exc
    return certificate, list(extras or [])

def _certificate_from_der_or_pem(data: bytes) -> x509.Certificate | None:
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        pass
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        return None

def _load_plist(raw: bytes) -> dict:
    from . import _plist

    parsed = _plist.loads(raw)
    if not isinstance(parsed, dict):
        raise CredentialError("plist payload is not a dictionary")
    return parsed

def _name_field(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    attributes = name.get_attributes_for_oid(oid)
    if not attributes:
        return ""
    value = attributes[0].value
    return value if isinstance(value, str) else str(value)

def _certificate_type(common_name: str) -> str:
    for kind in _CERTIFICATE_TYPES:
        if kind in common_name:
            return kind
    return "Certificate"

def _serial_hex(value: int) -> str:
    """Serial as uppercase hex, colon-separated every two digits."""
    if value <= 0:
        raw = "00"
    else:
        raw = format(value, "x")
        if len(raw) % 2:
            raw = "0" + raw
        raw = raw.upper()
    return ":".join(raw[index : index + 2] for index in range(0, len(raw), 2))

def _iso_utc(when: datetime.datetime) -> str:
    return when.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _algorithm(certificate: x509.Certificate) -> str:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size}-bit"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC {public_key.key_size}-bit"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519 256-bit"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448 456-bit"
    return "Unknown"

def _ocsp_for(
    certificate: x509.Certificate,
    chain: list[x509.Certificate],
    ocsp: bool,
    timeout: float,
) -> OcspResult:
    if not ocsp:
        return OcspResult("Skipped")
    issuer = _resolve_issuer(certificate, chain)
    if issuer is None:
        return OcspResult("Skipped")
    return _perform_ocsp(certificate, issuer, timeout)

def _resolve_issuer(
    certificate: x509.Certificate, chain: list[x509.Certificate]
) -> x509.Certificate | None:
    """The intermediate that issued ``certificate``, or ``None``.

    A chain carried by the input wins; otherwise the embedded Apple
    intermediates are consulted by subject name.
    """
    for candidate in chain:
        if candidate.subject == certificate.issuer:
            return candidate
    return _embedded_intermediate(certificate)

def _perform_ocsp(
    certificate: x509.Certificate, issuer: x509.Certificate, timeout: float
) -> OcspResult:
    """Query the certificate's OCSP responder and report the status."""
    try:
        name_hash, key_hash = _cert_id_hashes(certificate, issuer)
        body = _ocsp_request(certificate, name_hash, key_hash)
    except Exception:
        return OcspResult("Error", detail="Request failed")

    location = _ocsp_location(certificate, issuer)
    host, port, path = location

    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return OcspResult("Error", detail="DNS failed")

    try:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request(
            "POST",
            path,
            body,
            {"Content-Type": "application/ocsp-request", "Content-Length": str(len(body))},
        )
        response = connection.getresponse()
        payload = response.read()
    except OSError:
        return OcspResult("Error", detail="Connect failed")
    except http.client.HTTPException:
        return OcspResult("Error", detail="Invalid response")
    finally:
        try:
            connection.close()
        except Exception:
            pass

    if not payload:
        return OcspResult("Error", detail="Empty body")
    return _parse_ocsp(payload, certificate, name_hash, key_hash)

def _cert_id_hashes(
    certificate: x509.Certificate, issuer: x509.Certificate
) -> tuple[bytes, bytes]:
    """SHA-1 of the issuer's DER name and of its public key bits.

    The key hash covers the key's BIT STRING contents: the PKCS#1 DER for RSA,
    the uncompressed point for EC. Hashing the whole SubjectPublicKeyInfo
    instead yields a CertId the responder rejects as unauthorized.
    """
    name_hash = hashlib.sha1(issuer.subject.public_bytes()).digest()
    key_hash = hashlib.sha1(_public_key_bits(issuer)).digest()
    return name_hash, key_hash

def _public_key_bits(certificate: x509.Certificate) -> bytes:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

def _ocsp_request(certificate: x509.Certificate, name_hash: bytes, key_hash: bytes) -> bytes:
    request = asn1_ocsp.OCSPRequest(
        {
            "tbs_request": {
                "request_list": [
                    {
                        "req_cert": {
                            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha1"}),
                            "issuer_name_hash": core.OctetString(name_hash),
                            "issuer_key_hash": core.OctetString(key_hash),
                            "serial_number": certificate.serial_number,
                        }
                    }
                ]
            }
        }
    )
    return request.dump()

def _ocsp_location(certificate: x509.Certificate, issuer: x509.Certificate) -> tuple[str, int, str]:
    """(host, port, path) for the OCSP query.

    The certificate's AIA extension wins; without one, Apple's responder is
    used with a path chosen by the issuer's generation.
    """
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        )
        access = extension.value
    except x509.ExtensionNotFound:
        access = None

    if access is not None:
        for description in access:
            if description.access_method != x509.oid.AuthorityInformationAccessOID.OCSP:
                continue
            location = _parse_http_url(description.access_location.value)
            if location is not None:
                return location

    return "ocsp.apple.com", 80, _fallback_ocsp_path(issuer)

def _parse_http_url(url: str) -> tuple[str, int, str] | None:
    if "://" not in url:
        return None
    scheme, rest = url.split("://", 1)
    if scheme != "http":
        return None
    slash = rest.find("/")
    host_port = rest if slash < 0 else rest[:slash]
    path = "/" if slash < 0 else rest[slash:]
    if ":" in host_port:
        host, _, port = host_port.partition(":")
        try:
            return host, int(port), path
        except ValueError:
            return None
    return host_port, 80, path

def _fallback_ocsp_path(issuer: x509.Certificate) -> str:
    common_name = _name_field(issuer.subject, NameOID.COMMON_NAME)
    if "G6" in common_name:
        return "/ocsp03-wwdrg6"
    if "G3" in common_name:
        return "/ocsp03-wwdrg3"
    if "G2" in common_name:
        return "/ocsp03-wwdrg2"
    return "/ocsp03-wwdr01"

def _parse_ocsp(
    payload: bytes,
    certificate: x509.Certificate,
    name_hash: bytes,
    key_hash: bytes,
) -> OcspResult:
    try:
        response = asn1_ocsp.OCSPResponse.load(payload)
    except Exception:
        return OcspResult("Error", detail="Parse failed")

    response_status = response["response_status"].native
    if response_status != "successful":
        return OcspResult("Error", detail=f"OCSP response status: {response_status}")

    try:
        # ``response`` is the DER bytes here, not the parsed object.
        basic = asn1_ocsp.BasicOCSPResponse.load(response["response_bytes"]["response"].contents)
    except Exception:
        return OcspResult("Error", detail="Parse failed")

    for single in basic["tbs_response_data"]["responses"]:
        cert_id = single["cert_id"]
        if cert_id["serial_number"].native != certificate.serial_number:
            continue
        if cert_id["issuer_name_hash"].native != name_hash:
            continue
        if cert_id["issuer_key_hash"].native != key_hash:
            continue
        return _ocsp_cert_status(single["cert_status"])

    return OcspResult("Unknown", detail="Not in response")

def _ocsp_cert_status(cert_status: object) -> OcspResult:
    name = cert_status.name
    if name == "good":
        return OcspResult("Valid")
    if name == "revoked":
        revoked = cert_status.chosen["revocation_time"].native
        return OcspResult("Revoked", revoked_time=_iso_utc(revoked))
    return OcspResult("Unknown")

def _result_code(ocsp_status: str, expired: bool) -> int:
    if ocsp_status == "Revoked":
        return 1
    if ocsp_status in ("Unknown", "Error"):
        return -1
    return 2 if expired else 0

def _certificate_document(info: CertificateInfo | None) -> dict | None:
    if info is None:
        return None
    return {
        "name": info.name,
        "type": info.type,
        "org": info.org,
        "team": info.team,
        "serial": info.serial,
        "issued": info.issued,
        "expires": info.expires,
        "days_remaining": info.days_remaining,
        "expired": info.expired,
        "algorithm": info.algorithm,
        "issuer": info.issuer,
    }

def _ocsp_document(result: OcspResult | None) -> dict | None:
    if result is None:
        return None
    return {
        "status": result.status,
        "revoked_time": result.revoked_time,
        "detail": result.detail,
    }

__all__ = [
    "CertCheckResult",
    "CertificateInfo",
    "OcspResult",
    "check",
    "certificate_info",
]
