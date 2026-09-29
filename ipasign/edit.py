"""Bundle edits, applied in one pass before the seal.

Editing and signing are separate verbs, so they are separate calls. Every edit
is recorded on a :class:`BundleEdits` instance, and :func:`apply_edits` runs the
whole queue in one pass over a bundle root.
:func:`ipasign.bundle.sign_bundle` calls it after the provisioning profile lands
and before ``CodeResources`` is generated, which is the only ordering that keeps
the seal valid.

Nothing here signs, and nothing here needs a credential.

``bundle`` imports this module for its pre-seal pass, and ``metadata`` imports
``bundle``, so the two imports that would close that loop (``bundle`` and
``metadata``) are made inside the functions that need them.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, fields
from pathlib import Path

from . import _plist
from .errors import BundleError
from .signer import write_atomic

EXTENSION_FOLDERS = ("PlugIns", "Extensions")
WATCH_FOLDERS = ("Watch", "WatchKit", "com.apple.WatchPlaceholder")
STRINGS_FOLDERS = ("zh_CN.lproj", "zh-Hans.lproj")
ICON_KEYS = ("CFBundleIcons", "CFBundleIcons~ipad")
DEFAULT_ICON_NAME = "AppIcon60x60"
PROVISION_FILE = "embedded.mobileprovision"

@dataclass(slots=True)
class BundleEdits:
    """Recorded bundle modifications, applied by :func:`apply_edits`.

    One field per option. A field left at its default means "not requested", so
    a fresh instance applies nothing and an empty string is a no-op rather than
    a request to blank a key out.
    """

    # Identity: the root plist, and every nested .app/.appex for the id.
    bundle_id: str | None = None
    name: str | None = None
    version: str | None = None

    # Icon replacement.
    icon: Path | None = None

    # Independent toggles.
    minimum_os: str | None = None
    documents: bool = False
    drop_supported_devices: bool = False
    drop_extensions: bool = False
    drop_watch: bool = False
    drop_provision: bool = False

    @property
    def empty(self) -> bool:
        """Whether nothing was recorded."""
        return not any(getattr(self, field.name) for field in fields(self))

def apply_edits(root: Path, edits: BundleEdits) -> None:
    """Apply every recorded edit to the bundle at ``root``.

    Folder deletions run first, then the ``Info.plist`` edits, which are written
    back once so the plist keeps its original key order. The file is only
    rewritten when a requested edit actually applies, so a request that turns
    out to be a no-op leaves the bytes, and any seal over them, untouched.
    """
    if edits.empty:
        return

    if edits.drop_extensions:
        _drop_folders(root, EXTENSION_FOLDERS)
    if edits.drop_watch:
        _drop_folders(root, WATCH_FOLDERS)
    if edits.drop_provision:
        _drop_provision(root)

    if not _edits_info_plist(edits):
        return

    from .bundle import read_info_plist

    info = read_info_plist(root)
    if _apply_plist_edits(root, info, edits):
        write_atomic(root / "Info.plist", _plist.dumps(info))

def _edits_info_plist(edits: BundleEdits) -> bool:
    """Whether any recorded edit touches ``Info.plist``."""
    return bool(
        edits.bundle_id
        or edits.name
        or edits.version
        or edits.icon is not None
        or edits.minimum_os
        or edits.documents
        or edits.drop_supported_devices
    )

def _apply_plist_edits(root: Path, info: dict, edits: BundleEdits) -> bool:
    """Mutate ``info`` in place and report whether it must be written back.

    The order is the reference's: toggles, then the icon, then the identity
    keys. New keys are appended in insertion order, so the order decides where
    they land in the written plist.
    """
    changed = False

    if edits.documents:
        info["UISupportsDocumentBrowser"] = True
        info["UIFileSharingEnabled"] = True
        changed = True

    if edits.minimum_os:
        info["MinimumOSVersion"] = edits.minimum_os
        changed = True

    if edits.drop_supported_devices and "UISupportedDevices" in info:
        del info["UISupportedDevices"]
        changed = True

    if edits.icon is not None:
        _replace_icon(root, edits.icon, info)
        changed = True

    if edits.bundle_id and str(info.get("CFBundleIdentifier", "")) != edits.bundle_id:
        old_id = str(info.get("CFBundleIdentifier", ""))
        info["CFBundleIdentifier"] = edits.bundle_id
        if old_id:
            _rename_plugins(root, old_id, edits.bundle_id)
        changed = True

    if edits.name and (
        info.get("CFBundleName") != edits.name or info.get("CFBundleDisplayName") != edits.name
    ):
        info["CFBundleName"] = edits.name
        info["CFBundleDisplayName"] = edits.name
        _rewrite_strings(root, edits.name)
        changed = True

    if edits.version and info.get("CFBundleVersion") != edits.version:
        info["CFBundleVersion"] = edits.version
        info["CFBundleShortVersionString"] = edits.version
        changed = True

    return changed

def _drop_folders(root: Path, names: tuple[str, ...]) -> None:
    """Delete the named root-level folders that exist."""
    for name in names:
        target = root / name
        if not target.is_dir():
            continue
        try:
            shutil.rmtree(target)
        except OSError as exc:
            raise BundleError(f"cannot remove {target}: {exc}") from exc

def _drop_provision(root: Path) -> None:
    """Delete every embedded profile in the tree, root and nested bundles.

    The reference drops each one while it builds that bundle's seal; doing it
    here is the same point in the order, since the seal comes after this pass.
    """
    for path in root.rglob(PROVISION_FILE):
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise BundleError(f"cannot remove {path}: {exc}") from exc

def _rename_plugins(root: Path, old_id: str, new_id: str) -> None:
    """Carry a bundle id change into every nested ``.app`` and ``.appex``.

    Only those two kinds are touched, matching the reference: a framework or an
    ``.xctest`` carries no identifier of its own. A plugin whose plist cannot be
    read is left alone rather than failing the whole run, and one that carries
    none of the three keys keeps its bytes exactly as they were.
    """
    from .bundle import collect_nested_bundles, read_info_plist

    for path in collect_nested_bundles(root):
        if not path.name.endswith((".app", ".appex")):
            continue
        try:
            info = read_info_plist(path)
        except BundleError:
            continue

        changed = _replace_plugin_id(info, old_id, new_id)
        if changed:
            write_atomic(path / "Info.plist", _plist.dumps(info))


def _replace_plugin_id(info: dict, old_id: str, new_id: str) -> bool:
    """String-replace the identifier in the three keys a plugin may carry."""
    changed = False

    identifier = info.get("CFBundleIdentifier")
    if isinstance(identifier, str):
        info["CFBundleIdentifier"] = identifier.replace(old_id, new_id)
        changed = True

    companion = info.get("WKCompanionAppBundleIdentifier")
    if isinstance(companion, str):
        info["WKCompanionAppBundleIdentifier"] = companion.replace(old_id, new_id)
        changed = True

    extension = info.get("NSExtension")
    if isinstance(extension, dict):
        attributes = extension.get("NSExtensionAttributes")
        if isinstance(attributes, dict):
            watch_id = attributes.get("WKAppBundleIdentifier")
            if isinstance(watch_id, str):
                attributes["WKAppBundleIdentifier"] = watch_id.replace(old_id, new_id)
                changed = True

    return changed

def _rewrite_strings(root: Path, name: str) -> None:
    """Update the localised ``InfoPlist.strings`` files that are present.

    A ``.strings`` file is a plist despite the extension. Only the XML ones are
    rewritten: ``plistlib`` cannot read the legacy ASCII format, and a file that
    does not parse is skipped rather than failing the edit.
    """
    for folder in STRINGS_FOLDERS:
        path = root / folder / "InfoPlist.strings"
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        try:
            strings = _plist.loads(raw)
        except Exception:
            continue
        if not isinstance(strings, dict):
            continue

        strings["CFBundleName"] = name
        strings["CFBundleDisplayName"] = name
        write_atomic(path, _plist.dumps(strings))

def _replace_icon(root: Path, icon: Path, info: dict) -> None:
    """Overwrite every bundle-root PNG the declared icon names cover.

    ``Info.plist`` is mutated in place: ``CFBundleIconName`` is dropped so the
    ``Assets.car`` icon does not win on iOS 11+, and fresh entries are created
    when the plist declares no icon at all.
    """
    try:
        data = Path(icon).read_bytes()
    except OSError as exc:
        raise BundleError(f"cannot read the replacement icon {icon}: {exc}") from exc

    if _png_size(data) is None:
        raise BundleError(f"the replacement icon is not a PNG file: {icon}")

    names = _declared_icon_names(info)
    targets = [
        entry
        for entry in sorted(root.iterdir())
        if entry.is_file()
        and entry.name.endswith(".png")
        and any(entry.name.startswith(name) for name in names)
    ]
    if not targets:
        # Declared but missing on disk: create the icon instead of doing nothing.
        targets = [root / f"{names[0]}@2x.png"]

    written = 0
    for target in targets:
        try:
            write_atomic(target, data)
        except OSError:
            continue
        written += 1
    if not written:
        raise BundleError(f"cannot write any icon file in {root}")

def _png_size(data: bytes) -> tuple[int, int] | None:
    """(width, height) from the ``IHDR`` chunk, or ``None`` when there is none.

    A file that does not start with the PNG signature, or that carries no
    ``IHDR``, is not a PNG. The chunk is located rather than assumed at offset
    12, because Apple's crushed variant puts a ``CgBI`` chunk in front of it.
    """
    from .metadata import PNG_MAGIC

    if not data.startswith(PNG_MAGIC):
        return None

    pos = len(PNG_MAGIC)
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos : pos + 4], "big")
        if length > len(data) - pos - 12:
            return None
        if data[pos + 4 : pos + 8] == b"IHDR":
            if length != 13:
                return None
            width = int.from_bytes(data[pos + 8 : pos + 12], "big")
            height = int.from_bytes(data[pos + 12 : pos + 16], "big")
            return (width, height) if width and height else None
        pos += 12 + length
    return None


def _declared_icon_names(info: dict) -> list[str]:
    """The icon names the plist declares, in resolution order.

    ``CFBundleIcons`` and ``CFBundleIcons~ipad`` come first and both contribute,
    then the flat ``CFBundleIconFiles`` array, then the single
    ``CFBundleIconFile``. When nothing is declared, ``AppIcon60x60`` entries are
    created under both modern keys and that name is returned.
    """
    from .metadata import _string_list

    names: list[str] = []
    for key in ICON_KEYS:
        icons = info.get(key)
        if not isinstance(icons, dict):
            continue
        primary = icons.get("CFBundlePrimaryIcon")
        if not isinstance(primary, dict):
            continue
        names.extend(_string_list(primary.get("CFBundleIconFiles")))
        primary.pop("CFBundleIconName", None)

    if not names:
        names.extend(_string_list(info.get("CFBundleIconFiles")))
    if not names:
        single = info.get("CFBundleIconFile")
        if isinstance(single, str) and single:
            names.append(single)

    if not names:
        names.append(DEFAULT_ICON_NAME)
        for key in ICON_KEYS:
            _primary_icon(info, key)["CFBundleIconFiles"] = list(names)

    return names

def _primary_icon(info: dict, key: str) -> dict:
    """The ``CFBundlePrimaryIcon`` dictionary under ``key``, created when absent."""
    icons = info.get(key)
    if not isinstance(icons, dict):
        icons = {}
        info[key] = icons
    primary = icons.get("CFBundlePrimaryIcon")
    if not isinstance(primary, dict):
        primary = {}
        icons["CFBundlePrimaryIcon"] = primary
    return primary

__all__ = ["BundleEdits", "apply_edits"]
