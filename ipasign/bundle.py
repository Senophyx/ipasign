"""Bundle traversal, sealing and signing order.

An app bundle is signed from the leaves up: every Mach-O in the tree is signed
bare first, then each nested bundle is re-signed with its own identifier and
CodeResources, and the root executable comes last. The order matters because a
parent's seal hashes the child's already-signed binary, and because anything
written after a seal invalidates it.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from . import _plist, edit
from .credentials import ProvisioningProfile
from .errors import BundleError
from .signer import FileContext, Signer, sign_macho_file, write_atomic

BUNDLE_SUFFIXES = (".app", ".appex", ".framework", ".xctest")
# Discovery looks for an app bundle only: a framework or an xctest is signed
# where it is, never searched for.
APP_SUFFIXES = (".app", ".appex")
CODE_RESOURCES = "_CodeSignature/CodeResources"

MACHO_MAGICS = (
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)


def is_macho_file(path: Path) -> bool:
    """Whether ``path`` starts with a thin or fat Mach-O magic."""
    try:
        with open(path, "rb") as handle:
            return handle.read(4) in MACHO_MAGICS
    except OSError:
        return False


def parse_info_plist(raw: bytes) -> dict:
    """Parse ``Info.plist`` bytes into a dictionary."""
    try:
        parsed = _plist.loads(raw)
    except Exception as exc:
        raise BundleError(f"Info.plist is not a plist: {exc}") from exc
    if not isinstance(parsed, dict):
        raise BundleError("Info.plist is not a dictionary")
    return parsed


def display_name(info: dict) -> str:
    """The name a user recognises, falling back until one is found.

    Most bundles carry ``CFBundleDisplayName``, some only ``CFBundleName``, and
    a few neither, in which case the executable name is the best available.
    """
    for key in ("CFBundleDisplayName", "CFBundleName", "CFBundleExecutable"):
        value = info.get(key)
        if value:
            return str(value)
    return ""


def app_version(info: dict) -> str:
    """The release version, with the build number as a fallback."""
    for key in ("CFBundleShortVersionString", "CFBundleVersion"):
        value = info.get(key)
        if value:
            return str(value)
    return ""


def read_info_plist(bundle: Path) -> dict:
    """Parse a bundle's ``Info.plist``."""
    info_path = bundle / "Info.plist"
    try:
        raw = info_path.read_bytes()
    except FileNotFoundError as exc:
        raise BundleError(f"bundle has no Info.plist: {bundle}") from exc
    except OSError as exc:
        raise BundleError(f"cannot read {info_path}: {exc}") from exc

    return parse_info_plist(raw)


def bundle_details(bundle: Path) -> tuple[str, str, bytes]:
    """(bundle id, executable name, Info.plist bytes) for a bundle."""
    info = read_info_plist(bundle)
    bundle_id = str(info.get("CFBundleIdentifier", ""))
    executable = str(info.get("CFBundleExecutable", ""))
    if not bundle_id or not executable:
        raise BundleError(f"{bundle}/Info.plist has no CFBundleIdentifier or CFBundleExecutable")
    return bundle_id, executable, (bundle / "Info.plist").read_bytes()


def collect_macho_files(root: Path) -> list[Path]:
    """Every Mach-O file under ``root``, dSYM and WatchKit stubs excluded."""
    found: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            if ".dSYM" in relative or "_WatchKitStub" in relative:
                continue
            if is_macho_file(path):
                found.append(path)
    found.sort()
    return found


def collect_nested_bundles(root: Path) -> list[Path]:
    """Nested bundles under ``root``, deepest first.

    ``root`` itself is not included; the caller signs it separately and last.
    """
    found: list[Path] = []
    for dirpath, dirnames, _filenames in os.walk(root):
        for name in dirnames:
            path = Path(dirpath) / name
            if path.name.endswith(BUNDLE_SUFFIXES):
                found.append(path)
    found.sort(key=lambda path: len(path.relative_to(root).parts), reverse=True)
    return found


def find_app_folder(folder: Path) -> Path | None:
    """The first ``.app`` or ``.appex`` inside ``folder``, or ``None``.

    A caller who unpacks an archive by hand should not have to know where the
    bundle landed, so the whole tree is searched. Entries are visited in sorted
    order rather than the order the filesystem happens to return them, so the
    same tree always resolves to the same bundle. ``__MACOSX`` is zip metadata,
    not app content, and is skipped, and a symlinked directory is never
    descended into, so a loop in the tree cannot run away.
    """
    for entry in sorted(folder.iterdir()):
        if not entry.is_dir() or entry.is_symlink() or entry.name == "__MACOSX":
            continue
        if entry.name.endswith(APP_SUFFIXES):
            return entry
        found = find_app_folder(entry)
        if found is not None:
            return found
    return None

def _file_digests(path: Path) -> tuple[bytes, bytes]:
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            sha1.update(chunk)
            sha256.update(chunk)
    return sha1.digest(), sha256.digest()


def _is_lproj(key: str) -> bool:
    return ".lproj/" in key


def generate_code_resources(bundle: Path, executable: str) -> bytes:
    """Build the ``CodeResources`` plist sealing every file in ``bundle``."""
    keys: set[str] = set()
    for dirpath, _dirnames, filenames in os.walk(bundle):
        for name in filenames:
            relative = (Path(dirpath) / name).relative_to(bundle).as_posix()
            keys.add(relative)

    keys.discard(CODE_RESOURCES)
    keys.discard(executable)

    files: dict[str, object] = {}
    files2: dict[str, object] = {}

    for key in sorted(keys):
        sha1, sha256 = _file_digests(bundle / key)

        omit_files = key.endswith(".lproj/locversion.plist")
        # rules2 omits .DS_Store at any depth (^(.*/)?\.DS_Store$); sealing a nested one
        # makes the verifier report it as a missing resource.
        is_ds_store = key.rsplit("/", 1)[-1] == ".DS_Store"
        omit_files2 = omit_files or is_ds_store or key == "Info.plist" or key == "PkgInfo"

        if not omit_files:
            if _is_lproj(key):
                files[key] = {"hash": sha1, "optional": True}
            else:
                files[key] = sha1

        if not omit_files2:
            entry: dict[str, object] = {"hash": sha1, "hash2": sha256}
            if _is_lproj(key):
                entry["optional"] = True
            files2[key] = entry

    resources: dict[str, object] = {
        "files": files,
        "files2": files2,
        "rules": {
            "^.*": True,
            "^.*\\.lproj/": {"optional": True, "weight": 1000.0},
            "^.*\\.lproj/locversion.plist$": {"omit": True, "weight": 1100.0},
            "^Base\\.lproj/": {"weight": 1010.0},
            "^version.plist$": True,
        },
        "rules2": {
            "^.*": True,
            ".*\\.dSYM($|/)": {"weight": 11.0},
            "^(.*/)?\\.DS_Store$": {"omit": True, "weight": 2000.0},
            "^.*\\.lproj/": {"optional": True, "weight": 1000.0},
            "^.*\\.lproj/locversion.plist$": {"omit": True, "weight": 1100.0},
            "^Base\\.lproj/": {"weight": 1010.0},
            "^Info\\.plist$": {"omit": True, "weight": 20.0},
            "^PkgInfo$": {"omit": True, "weight": 20.0},
            "^embedded\\.provisionprofile$": {"weight": 20.0},
            "^version\\.plist$": {"weight": 20.0},
        },
    }
    return _plist.dumps(resources)


@dataclass(slots=True)
class BundleResult:
    """Outcome of signing one bundle tree."""

    bundle_id: str
    signed_count: int
    app_name: str = ""
    app_version: str = ""


def _write_code_resources(bundle: Path, data: bytes) -> None:
    target = bundle / CODE_RESOURCES
    target.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(target, data)


def sign_bundle_member(signer: Signer, bundle: Path) -> int:
    """Sign a bundle's executable with its own id, Info.plist and CodeResources."""
    bundle_id, executable, info_plist = bundle_details(bundle)
    resources = generate_code_resources(bundle, executable)
    _write_code_resources(bundle, resources)

    ctx = FileContext(
        bundle_id=bundle_id,
        info_plist_hash=hashlib.sha256(info_plist).digest(),
        code_resources_hash=hashlib.sha256(resources).digest(),
    )
    return sign_macho_file(signer, bundle / executable, ctx)


def sign_bundle(
    signer: Signer,
    root: Path,
    profile: ProvisioningProfile | None = None,
    edits: edit.BundleEdits | None = None,
) -> BundleResult:
    """Sign an app bundle tree in place, deepest bundle first.

    ``edits`` are applied once, after the profile lands and before any seal is
    generated, so an edited file is always covered by the ``CodeResources``
    that follows it. A recorded edit that deletes a folder therefore removes it
    from the traversal too.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise BundleError(f"not a directory: {root}")

    if profile is not None and profile.data:
        write_atomic(root / "embedded.mobileprovision", profile.data)

    if edits is not None:
        edit.apply_edits(root, edits)

    # Every bundle executable is also a Mach-O in this list and is signed twice,
    # bare here and again with its seal below, so the files are counted once.
    macho_files = collect_macho_files(root)
    for path in macho_files:
        sign_macho_file(signer, path)

    for bundle in collect_nested_bundles(root):
        try:
            sign_bundle_member(signer, bundle)
        except BundleError:
            # Not a signable bundle (no Info.plist or no executable), so it is left unsigned.
            continue

    bundle_id, _executable, info = bundle_details(root)
    parsed = parse_info_plist(info)
    sign_bundle_member(signer, root)
    return BundleResult(
        bundle_id=bundle_id,
        signed_count=len(macho_files),
        app_name=display_name(parsed),
        app_version=app_version(parsed),
    )


__all__ = [
    "BundleResult",
    "MACHO_MAGICS",
    "app_version",
    "bundle_details",
    "collect_macho_files",
    "collect_nested_bundles",
    "display_name",
    "find_app_folder",
    "generate_code_resources",
    "is_macho_file",
    "parse_info_plist",
    "read_info_plist",
    "sign_bundle",
    "sign_bundle_member",
]
