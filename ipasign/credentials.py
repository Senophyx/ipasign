"""Signing identity and provisioning profile loading.

A ``.p12`` holds the private key and the leaf certificate. A
``.mobileprovision`` is a CMS-signed plist carrying the entitlements to seal and
the team identifier. This module turns both into the pieces the signature
builders want, and picks the intermediate certificate that completes the chain.
"""

from __future__ import annotations

import plistlib
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from . import _apple_ca
from .errors import CredentialError, ProfileError


@dataclass(slots=True)
class ProvisioningProfile:
    """The parts of a provisioning profile signing needs."""

    data: bytes
    entitlements: dict
    entitlements_plist: bytes
    team_id: str
    application_id: str
    developer_certificates: list[bytes] = field(default_factory=list)

    @property
    def get_task_allow(self) -> bool:
        """True only when ``get-task-allow`` is present and set to a true value."""
        return bool(self.entitlements.get("get-task-allow", False))

    def matches(self, bundle_id: str) -> bool:
        """Whether this profile was issued for ``bundle_id``."""
        return bool(self.application_id) and self.application_id.endswith(bundle_id)


def _plist_from_cms(data: bytes) -> dict:
    """Pull the plist payload out of a CMS-wrapped provisioning profile."""
    from asn1crypto import cms

    try:
        info = cms.ContentInfo.load(data)
    except Exception as exc:  # asn1crypto raises several unrelated types
        raise ProfileError(f"provisioning profile is not a CMS structure: {exc}") from exc

    if info["content_type"].native != "signed_data":
        raise ProfileError(f"provisioning profile content is {info['content_type'].native}")

    content = info["content"]["encap_content_info"]["content"]
    if content.native is None:
        raise ProfileError("provisioning profile has no plist payload")

    payload = content.native
    try:
        parsed = plistlib.loads(payload)
    except Exception as exc:
        raise ProfileError(f"provisioning profile payload is not a plist: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProfileError("provisioning profile payload is not a dictionary")
    return parsed


def load_profile(path: str | Path) -> ProvisioningProfile:
    """Read a ``.mobileprovision`` file and pull out the signing inputs."""
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError as exc:
        raise ProfileError(f"provisioning profile not found: {path}") from exc
    except OSError as exc:
        raise ProfileError(f"cannot read provisioning profile {path}: {exc}") from exc

    if not data:
        raise ProfileError(f"provisioning profile is empty: {path}")

    plist = _plist_from_cms(data)

    team_ids = plist.get("TeamIdentifier") or []
    if not team_ids:
        raise ProfileError("provisioning profile carries no TeamIdentifier")
    team_id = team_ids[0]

    entitlements = plist.get("Entitlements")
    if not isinstance(entitlements, dict):
        raise ProfileError("provisioning profile carries no Entitlements dictionary")

    certificates = [
        cert
        for cert in (plist.get("DeveloperCertificates") or [])
        if isinstance(cert, (bytes, bytearray))
    ]

    return ProvisioningProfile(
        data=data,
        entitlements=entitlements,
        entitlements_plist=plistlib.dumps(entitlements, fmt=plistlib.FMT_XML, sort_keys=False),
        team_id=team_id,
        application_id=str(entitlements.get("application-identifier", "")),
        developer_certificates=certificates,
    )


def _embedded_intermediate(leaf: x509.Certificate) -> x509.Certificate | None:
    """The known Apple intermediate that issued ``leaf``, if any."""
    for pem in _apple_ca.WWDR_BY_ISSUER_HASH.values():
        candidate = x509.load_pem_x509_certificate(pem.encode("ascii"))
        if candidate.subject == leaf.issuer:
            return candidate
    return None


@dataclass(slots=True)
class Identity:
    """A loaded signing identity and the chain that completes it."""

    private_key: rsa.RSAPrivateKey
    certificate: x509.Certificate
    chain: list[x509.Certificate]

    @property
    def subject_cn(self) -> str:
        """The leaf certificate's common name, pinned by the requirement."""
        for attr in self.certificate.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                return attr.value
        raise CredentialError("leaf certificate has no subject common name")

    @property
    def intermediates(self) -> list[x509.Certificate]:
        """Chain members above the leaf, leaf excluded."""
        return [cert for cert in self.chain if cert != self.certificate]


def _load_der_certificates(blobs: list[bytes]) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    for blob in blobs:
        try:
            certs.append(x509.load_der_x509_certificate(blob))
        except Exception:
            continue
    return certs


def _select_chain(
    leaf: x509.Certificate,
    from_p12: list[x509.Certificate],
    from_profile: list[x509.Certificate],
) -> list[x509.Certificate]:
    """Pick the certificates to embed, intermediates first and the leaf last.

    A chain carried inside the p12 is preferred, but only when it actually
    contains the leaf's issuer. A p12 holding an unrelated or root-only chain
    must not shadow the intermediate that matches the leaf.
    """
    candidates = from_p12 or from_profile
    chain: list[x509.Certificate] = []
    for cert in candidates:
        if cert == leaf:
            continue
        if cert not in chain:
            chain.append(cert)

    issuer = leaf.issuer
    if not any(cert.subject == issuer for cert in chain):
        chain = []

    if not chain:
        embedded = _embedded_intermediate(leaf)
        if embedded is None:
            raise CredentialError(
                "no certificate in the p12 or profile issued the leaf, and no "
                f"known Apple intermediate matches its issuer ({issuer.rfc4514_string()})"
            )
        chain = [embedded]

    # Terminate the chain with the Apple root that issued one of its members.
    for pem in _apple_ca.ROOTS:
        root = x509.load_pem_x509_certificate(pem.encode("ascii"))
        if root in chain:
            continue
        if any(cert.issuer == root.subject for cert in chain):
            chain.append(root)

    chain.append(leaf)
    return chain


def load_identity(
    p12_path: str | Path,
    password: str | None,
    profile: ProvisioningProfile | None = None,
) -> Identity:
    """Read a ``.p12`` and build the signing chain.

    The key and leaf come from the p12. Intermediates come from the p12 when it
    carries a usable chain, otherwise from the profile's developer certificates,
    otherwise from the embedded Apple intermediates.
    """
    try:
        data = Path(p12_path).read_bytes()
    except FileNotFoundError as exc:
        raise CredentialError(f"identity file not found: {p12_path}") from exc
    except OSError as exc:
        raise CredentialError(f"cannot read identity file {p12_path}: {exc}") from exc

    secret = None if password is None else password.encode("utf-8")
    try:
        key, leaf, extras = pkcs12.load_key_and_certificates(data, secret)
    except Exception as exc:
        raise CredentialError(
            f"cannot open {p12_path}: wrong password or not a PKCS#12 file ({exc})"
        ) from exc

    if key is None:
        raise CredentialError(f"{p12_path} carries no private key")
    if leaf is None:
        raise CredentialError(f"{p12_path} carries no certificate")
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CredentialError(f"only RSA signing keys are supported, got {type(key).__name__}")

    if leaf.public_key().public_numbers() != key.public_key().public_numbers():
        raise CredentialError(f"private key in {p12_path} does not match its certificate")

    from_profile = _load_der_certificates(profile.developer_certificates) if profile else []
    chain = _select_chain(leaf, list(extras or []), from_profile)
    return Identity(private_key=key, certificate=leaf, chain=chain)


def load_entitlements(path: str | Path) -> tuple[dict, bytes]:
    """Read an entitlements plist supplied by the caller.

    Returns the parsed dictionary and the plist bytes to seal, with the caller's
    key order preserved.
    """
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError as exc:
        raise CredentialError(f"entitlements file not found: {path}") from exc
    except OSError as exc:
        raise CredentialError(f"cannot read entitlements file {path}: {exc}") from exc

    try:
        parsed = plistlib.loads(raw)
    except Exception as exc:
        raise CredentialError(f"entitlements file {path} is not a plist: {exc}") from exc
    if not isinstance(parsed, dict):
        raise CredentialError(f"entitlements file {path} is not a dictionary")

    return parsed, plistlib.dumps(parsed, fmt=plistlib.FMT_XML, sort_keys=False)


def export_public_key_pem(cert: x509.Certificate) -> bytes:
    """The certificate's public key in SubjectPublicKeyInfo PEM form."""
    return cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


__all__ = [
    "Identity",
    "ProvisioningProfile",
    "load_entitlements",
    "load_identity",
    "load_profile",
]
