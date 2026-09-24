"""The public entry point: :class:`Key` and :meth:`Key.sign`.

A ``Key`` holds a signing identity and the entitlements to seal. ``sign``
dispatches on what it is handed: an ``.ipa`` archive, an ``.app`` bundle folder,
or a bare Mach-O file. Failures raise; a completed run returns a
:class:`SignResult`.
"""

from __future__ import annotations

import datetime
import os
from dataclasses import dataclass
from pathlib import Path

from . import archive, bundle, signer
from .credentials import ProvisioningProfile, load_entitlements, load_identity, load_profile
from .errors import InvalidInputError
from .signer import FileContext, Signer, bundle_id_fallback, embedded_info_plist_hash, sign_macho_file
from . import macho

APP_SUFFIXES = (".app", ".appex")


@dataclass(frozen=True, slots=True)
class SignResult:
    """What a completed signing run produced.

    ``output_path`` is where the artifact actually landed, ``bundle_id`` the
    identifier sealed into the CodeDirectory, and ``signed_count`` how many
    Mach-O files were signed.
    """

    output_path: str
    bundle_id: str
    signed_count: int


def _looks_like_macho(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) in bundle._MACHO_MAGICS
    except OSError:
        return False


class Key:
    """A signing identity plus the entitlements to seal.

    ``pkey`` is a ``.p12`` path and ``prov`` a ``.mobileprovision`` path. Pass
    ``adhoc=True`` for a credential-less ad-hoc key, in which case both may be
    ``None``. ``entitlements`` overrides the profile's entitlements with a plist
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

    # credential derived material
    @property
    def team_id(self) -> str:
        if self._team_id_override is not None:
            return self._team_id_override
        return self.profile.team_id if self.profile else ""

    @property
    def subject_cn(self) -> str:
        if self._subject_cn_override is not None:
            return self._subject_cn_override
        return self.identity.subject_cn if self.identity else ""

    def _entitlements(self) -> tuple[dict, bytes]:
        if self._entitlements_override is not None:
            return load_entitlements(self._entitlements_override)
        if self.profile is not None:
            return self.profile.entitlements, self.profile.entitlements_plist
        return {}, b""

    def _signer(self) -> Signer:
        entitlements, plist_bytes = self._entitlements()
        return Signer(
            identity=self.identity,
            adhoc=self.adhoc,
            entitlements=entitlements,
            entitlements_plist=plist_bytes,
            team_id=self.team_id,
            subject_cn=self.subject_cn,
            signing_time=datetime.datetime.now(datetime.timezone.utc),
        )

    # the single entry point
    def sign(
        self,
        input_path: str | os.PathLike,
        output_path: str | os.PathLike | None = None,
        *,
        keep_work_dir: bool = False,
        tmp_folder: str | os.PathLike | None = None,
        bundle_id: str | None = None,
    ) -> SignResult:
        """Sign ``input_path`` and return where the result landed.

        An ``.ipa`` unpacks into ``.ipasign_tmp`` beside the input, signs the
        bundle and repacks into ``output_path``. A ``.app`` folder is signed in
        place. A bare Mach-O is signed in place, so passing ``output_path`` for
        one is an error rather than a parameter that quietly does nothing.
        """
        path = Path(input_path)
        if not path.exists():
            raise InvalidInputError(f"input does not exist: {path}")

        if path.is_dir():
            return self._sign_folder(path, output_path)

        if path.suffix.lower() == ".ipa":
            return self._sign_ipa(path, output_path, keep_work_dir, tmp_folder, bundle_id)

        if _looks_like_macho(path):
            if output_path is not None:
                raise InvalidInputError(
                    "a bare Mach-O is signed in place; an output path would be ignored"
                )
            return self._sign_macho(path, bundle_id)

        raise InvalidInputError(f"do not know how to sign: {path}")

    # per input type
    def _sign_ipa(
        self,
        ipa: Path,
        output: str | os.PathLike | None,
        keep_work_dir: bool,
        tmp_folder: str | os.PathLike | None,
        bundle_id: str | None,
    ) -> SignResult:
        if output is None:
            raise InvalidInputError("signing an .ipa needs an output path")

        work = Path(tmp_folder) if tmp_folder is not None else None
        # A caller-named directory implies wanting to look inside it.
        keep = keep_work_dir or tmp_folder is not None

        unpacked = archive.unpack(ipa, work)
        try:
            result = bundle.sign_bundle(self._signer(), unpacked.app, self.profile)
            target = Path(output)
            archive.pack(unpacked.root, target)
            return SignResult(
                output_path=str(target),
                bundle_id=bundle_id or result.bundle_id,
                signed_count=result.signed_count,
            )
        finally:
            if not keep:
                archive.cleanup(unpacked.root)

    def _sign_folder(self, folder: Path, output: str | os.PathLike | None) -> SignResult:
        if output is not None and Path(output) != folder:
            raise InvalidInputError(
                "a bundle is signed in place; move the folder first if you want a copy"
            )
        result = bundle.sign_bundle(self._signer(), folder, self.profile)
        return SignResult(
            output_path=str(folder),
            bundle_id=result.bundle_id,
            signed_count=result.signed_count,
        )

    def _sign_macho(self, path: Path, bundle_id: str | None) -> SignResult:
        parsed = macho.MachOFile.parse(path.read_bytes())
        slc = parsed.slices[0]
        resolved_id = bundle_id or bundle_id_fallback(slc, path)
        ctx = FileContext(
            bundle_id=resolved_id,
            info_plist_hash=embedded_info_plist_hash(slc),
        )
        count = sign_macho_file(self._signer(), path, ctx)
        return SignResult(output_path=str(path), bundle_id=resolved_id, signed_count=count)


__all__ = ["Key", "SignResult"]
