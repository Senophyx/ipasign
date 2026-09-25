"""The :class:`App` facade: name what to sign, then sign it.

``App`` is the entry point for signing. It accepts anything this library knows
how to sign and dispatches on what it finds:

    key = ipasign.Key("identity.p12", "profile.mobileprovision", "password")

    ipasign.App("test.ipa").sign(key)          # -> test-signed.ipa
    ipasign.App("Test.app").sign(key)          # signed in place
    ipasign.App("libX.dylib").sign(key)        # signed in place

An ``.ipa`` is unpacked, signed and repacked, so it gets a default output named
after the input. A bundle folder and a bare Mach-O are signed where they are,
so ``output`` is refused for them rather than accepted and ignored.

Every call returns a :class:`~ipasign.result.SignResult`. :meth:`App.metadata`
reads the same input without signing it.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import archive, bundle, macho, metadata
from . import check as _check
from .check import CertCheckResult
from .errors import BundleError, InvalidInputError, MachOError
from .key import Key
from .metadata import Metadata
from .result import SignResult
from .signer import (
    FileContext,
    bundle_id_fallback,
    embedded_info_plist_hash,
    sign_macho_file,
)

def _looks_like_macho(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) in bundle.MACHO_MAGICS
    except OSError:
        return False

class App:
    """Something signable: an ``.ipa``, a bundle folder, or a bare Mach-O.

    The input is validated here. An archive is unpacked later, when :meth:`sign`
    runs, so constructing an ``App`` never touches the file.
    """

    def __init__(self, path: str | os.PathLike) -> None:
        source = Path(path)
        if not source.exists():
            raise InvalidInputError(f"input does not exist: {source}")
        if not (source.is_dir() or source.suffix.lower() == ".ipa" or _looks_like_macho(source)):
            raise InvalidInputError(f"do not know how to sign: {source}")
        self.path = source

    @property
    def is_archive(self) -> bool:
        """Whether this is an ``.ipa`` that gets unpacked and repacked."""
        return self.path.is_file() and self.path.suffix.lower() == ".ipa"

    @property
    def default_output(self) -> Path:
        """Where :meth:`sign` writes an archive when the caller names no output.

        ``test.ipa`` becomes ``test-signed.ipa`` beside it. An input that
        already ends in ``-signed`` simply gains another suffix.
        """
        return self.path.with_name(f"{self.path.stem}-signed{self.path.suffix}")

    def sign(
        self,
        key: Key,
        output: str | os.PathLike | None = None,
        *,
        keep_work_dir: bool = False,
        tmp_folder: str | os.PathLike | None = None,
        bundle_id: str | None = None,
    ) -> SignResult:
        """Sign what this ``App`` names and report where the result landed.

        ``output`` defaults to :attr:`default_output` for an archive. It is
        refused for a bundle folder and a bare Mach-O, which are signed where
        they are: an output path there would be silently ignored otherwise.

        ``bundle_id`` names the identifier to seal for a bare Mach-O, which has
        no bundle to read one from. Bundles keep the identifier in their own
        ``Info.plist``.
        """
        if self.path.is_dir():
            return self._sign_folder(key, output)

        if self.path.suffix.lower() == ".ipa":
            return self._sign_ipa(key, output, keep_work_dir, tmp_folder)

        if _looks_like_macho(self.path):
            return self._sign_macho(key, output, bundle_id)

        raise InvalidInputError(f"do not know how to sign: {self.path}")

    def metadata(self, save_to: str | os.PathLike | None = None) -> Metadata:
        """Read what this app says about itself.

        An archive is unpacked for the read and cleaned up again, so this never
        modifies it. ``save_to`` additionally writes ``metadata.json`` and the
        primary icon into that directory, creating it when missing.

        ``size`` and ``file_name`` describe an ``.ipa``, so both are empty for a
        bundle folder and for a bare Mach-O. Every field is read from what the
        app declares, so a bare Mach-O with no embedded ``Info.plist`` reports
        empty values throughout.
        """
        if self.path.is_dir():
            return self._metadata_for(bundle.read_info_plist(self.path), self.path, save_to)

        if self.path.suffix.lower() == ".ipa":
            unpacked = archive.unpack(self.path)
            try:
                return self._metadata_for(
                    bundle.read_info_plist(unpacked.app), unpacked.app, save_to, self.path
                )
            finally:
                archive.cleanup(unpacked.root)

        # A bare Mach-O has no bundle root, so the only place its name and
        # version could come from is the plist embedded in the file itself.
        slc = macho.MachOFile.parse(self.path.read_bytes()).slices[0]
        info = bundle.parse_info_plist(slc.info_plist) if slc.info_plist else {}
        return self._metadata_for(info, None, save_to)

    @staticmethod
    def _metadata_for(
        info: dict,
        icon_folder: Path | None,
        save_to: str | os.PathLike | None,
        ipa_file: Path | None = None,
    ) -> Metadata:
        output = Path(save_to) if save_to is not None else None
        return metadata.from_info(info, icon_folder, ipa_file, output)

    def check(self, *, ocsp: bool = True, timeout: float = 10.0) -> CertCheckResult:
        """Report the certificate this app is signed with.

        A bundle folder is resolved to its ``CFBundleExecutable`` and that
        binary is checked, so the reported path is the executable. An archive
        or a bare Mach-O is checked directly. ``ocsp=False`` skips the
        revocation query.
        """
        if not self.path.is_dir():
            return _check.check(self.path, ocsp=ocsp, timeout=timeout)

        info = bundle.read_info_plist(self.path)
        executable = info.get("CFBundleExecutable")
        if not executable:
            raise InvalidInputError(f"{self.path}/Info.plist has no CFBundleExecutable")
        binary = self.path / str(executable)
        if not binary.is_file():
            raise InvalidInputError(f"bundle executable not found: {binary}")
        return _check.check(binary, ocsp=ocsp, timeout=timeout)

    def _sign_ipa(
        self,
        key: Key,
        output: str | os.PathLike | None,
        keep_work_dir: bool,
        tmp_folder: str | os.PathLike | None,
    ) -> SignResult:
        target = Path(output) if output is not None else self.default_output
        work = Path(tmp_folder) if tmp_folder is not None else None
        # A caller-named directory implies wanting to look inside it.
        keep = keep_work_dir or tmp_folder is not None

        unpacked = archive.unpack(self.path, work)
        try:
            result = bundle.sign_bundle(key.signer(), unpacked.app, key.profile)
            archive.pack(unpacked.root, target)
            return SignResult(
                output_path=str(target),
                bundle_id=result.bundle_id,
                signed_count=result.signed_count,
                app_name=result.app_name,
                app_version=result.app_version,
            )
        finally:
            if not keep:
                archive.cleanup(unpacked.root)

    def _sign_folder(self, key: Key, output: str | os.PathLike | None) -> SignResult:
        if output is not None:
            raise InvalidInputError(
                "a bundle is signed in place; move the folder first if you want a copy"
            )
        result = bundle.sign_bundle(key.signer(), self.path, key.profile)
        return SignResult(
            output_path=str(self.path),
            bundle_id=result.bundle_id,
            signed_count=result.signed_count,
            app_name=result.app_name,
            app_version=result.app_version,
        )

    def _sign_macho(
        self,
        key: Key,
        output: str | os.PathLike | None,
        bundle_id: str | None,
    ) -> SignResult:
        if output is not None:
            raise InvalidInputError(
                "a bare Mach-O is signed in place; an output path would be ignored"
            )

        try:
            data = self.path.read_bytes()
        except OSError as exc:
            raise MachOError(f"cannot read {self.path}: {exc}") from exc

        slc = macho.MachOFile.parse(data).slices[0]
        resolved_id = bundle_id or bundle_id_fallback(slc, self.path)
        ctx = FileContext(
            bundle_id=resolved_id,
            info_plist_hash=embedded_info_plist_hash(slc),
        )
        count = sign_macho_file(key.signer(), self.path, ctx)

        # A bare Mach-O may still carry an embedded Info.plist, which is the only
        # place its name and version could come from.
        name = version = ""
        if slc.info_plist:
            try:
                info = bundle.parse_info_plist(slc.info_plist)
            except BundleError:
                info = {}
            name = bundle.display_name(info)
            version = bundle.app_version(info)

        return SignResult(
            output_path=str(self.path),
            bundle_id=resolved_id,
            signed_count=count,
            app_name=name,
            app_version=version,
        )

__all__ = ["App"]
