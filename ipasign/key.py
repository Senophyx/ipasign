"""The signing identity: :class:`Key`.

A ``Key`` holds what it takes to sign: the private key, the certificate chain,
the team identifier and the entitlements to seal. It performs no file I/O. What
to sign and where to put it is :class:`ipasign.app.App`'s job.

    key = ipasign.Key("identity.p12", "profile.mobileprovision", "password")
    app = ipasign.App("input.ipa")
    signed = app.sign(key)

``Key.signer()`` exposes the credential-derived :class:`~ipasign.signer.Signer`
that the signing paths consume, for callers working at that level.
"""

from __future__ import annotations

import datetime
import os

from . import check as _check
from .check import CertCheckResult
from .credentials import ProvisioningProfile, load_entitlements, load_identity, load_profile
from .errors import InvalidInputError
from .result import SignResult
from .signer import Signer

class Key:
    """A signing identity plus the entitlements to seal.

    ``pkey`` is a ``.p12`` path and ``prov`` a ``.mobileprovision`` path. Pass
    ``adhoc=True`` for a credential-less ad-hoc key, in which case both may be
    ``None``. ``entitlements`` replaces the profile's entitlements with a plist
    file of the caller's own.
    """

    def __init__(
        self,
        pkey: str | os.PathLike | None = None,
        prov: str | os.PathLike | None = None,
        password: str | None = None,
        *,
        adhoc: bool = False,
        entitlements: str | os.PathLike | None = None,
        team_id: str | None = None,
        subject_cn: str | None = None,
    ) -> None:
        self.adhoc = bool(adhoc)
        self.password = password
        self.profile: ProvisioningProfile | None = None
        self.identity = None
        self._p12_path = None if pkey is None else os.fspath(pkey)
        self._entitlements_override = entitlements
        self._team_id_override = team_id
        self._subject_cn_override = subject_cn

        if self.adhoc:
            if pkey is not None or prov is not None:
                raise InvalidInputError("an ad-hoc key takes no p12 or profile")
        else:
            if pkey is None:
                raise InvalidInputError("a signing key needs a .p12 path")
            if prov is None:
                raise InvalidInputError("a signing key needs a .mobileprovision path")

        if prov is not None:
            self.profile = load_profile(prov)

        if not self.adhoc:
            self.identity = load_identity(pkey, password, self.profile)

    @property
    def team_id(self) -> str:
        """Team identifier sealed into the CodeDirectory."""
        if self._team_id_override is not None:
            return self._team_id_override
        return self.profile.team_id if self.profile else ""

    @property
    def subject_cn(self) -> str:
        """Leaf certificate common name, pinned by the designated requirement."""
        if self._subject_cn_override is not None:
            return self._subject_cn_override
        return self.identity.subject_cn if self.identity else ""

    def entitlements(self) -> tuple[dict, bytes]:
        """(entitlements mapping, plist bytes) this key seals."""
        if self._entitlements_override is not None:
            return load_entitlements(self._entitlements_override)
        if self.profile is not None:
            return self.profile.entitlements, self.profile.entitlements_plist
        return {}, b""

    def signer(self) -> Signer:
        """The credential-derived material every file in one run shares."""
        entitlements, plist_bytes = self.entitlements()
        return Signer(
            identity=self.identity,
            adhoc=self.adhoc,
            entitlements=entitlements,
            entitlements_plist=plist_bytes,
            team_id=self.team_id,
            subject_cn=self.subject_cn,
            signing_time=datetime.datetime.now(datetime.timezone.utc),
        )

    def check(self, *, ocsp: bool = True, timeout: float = 10.0) -> CertCheckResult:
        """Report the identity's certificate and its OCSP revocation status.

        An ad-hoc key has no certificate, so it reports ``not_signed`` rather
        than raising. ``ocsp=False`` skips the revocation query.
        """
        if self.identity is None:
            return CertCheckResult(
                path=self._p12_path or "",
                type="PKCS#12",
                signed=None,
                certificate=None,
                ocsp=None,
                code=-2,
                status="not_signed",
            )
        return _check._check_identity(
            self._p12_path or "",
            self.identity.certificate,
            self.identity.chain,
            ocsp=ocsp,
            timeout=timeout,
        )

__all__ = ["Key", "SignResult"]
