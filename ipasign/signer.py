"""Per-file code signing.

Ties the blob builders, the CMS builder and the Mach-O writer together for a
single binary. A ``Signer`` holds the credential-derived material that is the
same for every file in a run; a ``FileContext`` holds what differs per file
(bundle id, info plist hash, CodeResources hash).
"""

from __future__ import annotations

import datetime
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import _plist, blobs, macho
from .cms import CmsParts, build_cms
from .credentials import Identity
from .errors import BundleError, MachOError

EMPTY_ENTITLEMENTS_PLIST = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    b'<plist version="1.0">\n'
    b"<dict/>\n"
    b"</plist>\n"
)


@dataclass(slots=True)
class Signer:
    """Credential-derived material shared by every file in one signing run."""

    identity: Identity | None = None
    adhoc: bool = False
    entitlements: dict = field(default_factory=dict)
    entitlements_plist: bytes = b""
    team_id: str = ""
    subject_cn: str = ""
    signing_time: datetime.datetime | None = None

    @property
    def get_task_allow(self) -> bool:
        value = self.entitlements.get("get-task-allow")
        return value is True

    def entitlements_for(self, is_execute: bool) -> tuple[bytes, bytes]:
        """(XML blob, DER blob) for a slice, empty when nothing applies."""
        if not is_execute:
            return blobs.entitlements_xml(EMPTY_ENTITLEMENTS_PLIST), b""
        if not self.entitlements_plist:
            return b"", b""
        return (
            blobs.entitlements_xml(self.entitlements_plist),
            blobs.entitlements_der(self.entitlements),
        )

    def build_leaf_code_directory(self, slc: macho.Slice, ctx: "FileContext", code_length: int) -> bytes:
        """The SHA-256 CodeDirectory for one slice at ``code_length``."""
        req = blobs.requirements(ctx.bundle_id, self.subject_cn)
        ent_xml, ent_der = self.entitlements_for(slc.is_execute)

        spec = blobs.CodeDirectorySpec(
            bundle_id=ctx.bundle_id,
            team_id=self.team_id,
            code_limit=code_length,
            exec_seg_limit=slc.exec_seg_limit,
            is_execute=slc.is_execute,
            adhoc=self.adhoc,
            info_plist_hash=ctx.info_plist_hash,
            requirements_hash=hashlib.sha256(req).digest() if req else b"",
            code_resources_hash=ctx.code_resources_hash,
            entitlements_hash=hashlib.sha256(ent_xml).digest() if ent_xml else b"",
            der_entitlements_hash=hashlib.sha256(ent_der).digest() if ent_der else b"",
            get_task_allow=self.get_task_allow,
            code_slots=blobs.hash_pages(slc.view, code_length),
        )
        return blobs.code_directory(spec)

    def build_signature(self, slc: macho.Slice, ctx: "FileContext") -> bytes:
        """The whole SuperBlob for one slice."""
        code_length = slc.code_length
        cd = self.build_leaf_code_directory(slc, ctx, code_length)

        req = blobs.requirements(ctx.bundle_id, self.subject_cn)
        ent_xml, ent_der = self.entitlements_for(slc.is_execute)

        if self.adhoc:
            cms_blob = blobs.blob_wrapper(b"")
        else:
            if self.identity is None:
                raise BundleError("a non-ad-hoc signature needs an identity")
            cd_hash = hashlib.sha256(cd).digest()
            cdhashes = _plist.dumps({"cdhashes": [cd_hash[:20]]})
            payload = build_cms(
                self.identity,
                CmsParts(
                    code_directory=cd,
                    cdhashes_plist=cdhashes,
                    apple_hash=cd_hash,
                    signing_time=self.signing_time,
                ),
            )
            cms_blob = blobs.blob_wrapper(payload)

        return blobs.superblob(
            [
                (blobs.CSSLOT_CODEDIRECTORY, cd),
                (blobs.CSSLOT_REQUIREMENTS, req),
                (blobs.CSSLOT_ENTITLEMENTS, ent_xml),
                (blobs.CSSLOT_DER_ENTITLEMENTS, ent_der),
                (blobs.CSSLOT_SIGNATURESLOT, cms_blob),
            ]
        )


@dataclass(slots=True)
class FileContext:
    """What differs per signed file."""

    bundle_id: str
    info_plist_hash: bytes = b""
    code_resources_hash: bytes = b""


def _temp_path(target: Path) -> Path:
    """A sibling temp name that keeps the target's basename.

    ``Runner`` becomes ``Runner.is_tmp``; two binaries in one directory cannot
    collide because their target names differ.
    """
    return target.with_name(target.name + ".is_tmp")


def write_atomic(target: Path, data: bytes) -> None:
    """Write ``data`` next to ``target`` and rename over it.

    A crash leaves the original file untouched rather than a truncated binary.
    """
    temp = _temp_path(target)
    try:
        with open(temp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except OSError:
        try:
            temp.unlink()
        except OSError:
            pass
        raise


def sign_slice(signer: Signer, slc: macho.Slice, ctx: FileContext) -> bytes:
    """Sign one slice, growing the file when the current region is too small.

    An unsigned slice has no region to reuse, so it grows first and the blob is
    built once against the final layout. A slice that already carries a
    signature is signed in place when the existing region can hold the new blob,
    and regrown when it cannot.
    """
    code_length = slc.code_length

    if slc.code_signature is not None:
        signature = signer.build_signature(slc, ctx)
        if slc.size - code_length >= len(signature):
            return macho.place_signature(slc, slc.view.tobytes(), code_length, signature)

    new_length = code_length + macho.signature_region_size(code_length)
    if new_length <= slc.size:
        raise MachOError(
            f"cannot fit a signature for {slc.size} bytes at {code_length} in {slc.size} bytes"
        )

    grown = macho.grow_slice(slc, new_length)
    grown_slice = macho.MachOFile.parse(grown).slices[0]
    signature = signer.build_signature(grown_slice, ctx)
    if code_length + len(signature) > new_length:
        raise MachOError("signature region is smaller than the signature it must hold")
    return macho.place_signature(grown_slice, grown, code_length, signature)


def _needs_growth(slc: macho.Slice, signer: Signer, ctx: FileContext) -> bool:
    """Whether the existing signature region is too small for the new blob."""
    if slc.code_signature is None:
        return True
    return slc.size - slc.code_length < len(signer.build_signature(slc, ctx))


def sign_file_data(signer: Signer, data: bytes, ctx: FileContext) -> tuple[bytes, int]:
    """Sign every slice of an in-memory Mach-O file.

    A file whose existing signature regions all have room is patched in place,
    so the container layout, alignment and trailing padding are left exactly as
    they were. Only a slice that must grow triggers a re-layout, and then the
    fat container is rebuilt with every slice aligned.
    """
    parsed = macho.MachOFile.parse(data)

    if not any(_needs_growth(slc, signer, ctx) for slc in parsed.slices):
        out = bytearray(data)
        for slc in parsed.slices:
            signed = sign_slice(signer, slc, ctx)
            if len(signed) != slc.size:
                raise MachOError("in-place signing changed a slice's length")
            out[slc.base : slc.base + slc.size] = signed
        return bytes(out), len(parsed.slices)

    signed_slices = [sign_slice(signer, slc, ctx) for slc in parsed.slices]
    if not parsed.is_fat:
        return signed_slices[0], 1
    return macho.build_fat(signed_slices, parsed.archs, parsed.fat_big_endian), len(signed_slices)


def bundle_id_fallback(slc: macho.Slice, path: Path) -> str:
    """Bundle id for a file signed outside a bundle.

    The embedded ``__info_plist`` section wins; the file name is the last
    resort.
    """
    if slc.info_plist:
        try:
            parsed = _plist.loads(slc.info_plist)
            if isinstance(parsed, dict) and parsed.get("CFBundleIdentifier"):
                return str(parsed["CFBundleIdentifier"])
        except Exception:
            pass
    return path.stem


def embedded_info_plist_hash(slc: macho.Slice) -> bytes:
    """SHA-256 of the embedded ``__info_plist`` section, zeros when absent."""
    if not slc.info_plist:
        return b"\0" * 32
    return hashlib.sha256(slc.info_plist).digest()


def sign_macho_file(signer: Signer, path: Path, ctx: FileContext | None = None) -> int:
    """Sign a Mach-O file in place and return the number of slices signed."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise MachOError(f"cannot read {path}: {exc}") from exc

    parsed = macho.MachOFile.parse(data)
    if ctx is None:
        bundle_id = ""
        info_hash = b""
        for slc in parsed.slices:
            bundle_id = bundle_id or bundle_id_fallback(slc, path)
            info_hash = info_hash or embedded_info_plist_hash(slc)
            break
        ctx = FileContext(bundle_id=bundle_id, info_plist_hash=info_hash)

    signed, count = sign_file_data(signer, data, ctx)
    write_atomic(path, signed)
    return count


__all__ = [
    "Signer",
    "FileContext",
    "sign_slice",
    "sign_file_data",
    "sign_macho_file",
    "write_atomic",
    "bundle_id_fallback",
    "embedded_info_plist_hash",
    "EMPTY_ENTITLEMENTS_PLIST",
]
