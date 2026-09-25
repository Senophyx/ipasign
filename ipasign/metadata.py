"""Metadata extraction.

Reads what a bundle says about itself: display name, version, bundle
identifier, archive size, primary icon name and a timestamp. Nothing here
signs, and nothing needs a credential.

Reached through :meth:`ipasign.app.App.metadata`, which decides where the
bundle comes from. This module only handles a bundle that is already open, so
it never unpacks anything.

Icons in a shipped bundle are usually "crushed" by ``pngcrush -iphone``: the
file carries a ``CgBI`` chunk, its ``IDAT`` is raw deflate, and the pixels are
BGRA with premultiplied alpha. :func:`_decode_cgbi_png` converts that variant
back to a regular PNG and leaves anything else untouched.
"""

from __future__ import annotations

import hashlib
import json
import struct
import time
import zlib
from dataclasses import dataclass
from pathlib import Path

from .bundle import app_version, display_name
from .signer import write_atomic

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
METADATA_FILE = "metadata.json"
MAX_ICON_PIXELS = 0x4000000

@dataclass(frozen=True, slots=True)
class Metadata:
    """What an app and the archive holding it say about themselves.

    ``size`` and ``file_name`` describe the ``.ipa`` an app came out of, so both
    stay empty for a bundle folder and for a bare Mach-O, which are not archives.
    """

    name: str
    version: str
    bundle_identifier: str
    size: int
    icon_name: str
    file_name: str
    timestamp: int

def from_info(
    info: dict,
    icon_folder: Path | None,
    ipa_file: Path | None,
    output_dir: Path | None,
) -> Metadata:
    """Build metadata from a parsed ``Info.plist``.

    ``icon_folder`` is the bundle root to look for an icon in, or ``None`` for a
    bare Mach-O, which has no bundle root. ``ipa_file`` is the archive the app
    came out of, or ``None`` when there is none. ``output_dir`` additionally
    writes ``metadata.json`` and the icon there.
    """
    icon = _chosen_icon(icon_folder, _icon_names(info)) if icon_folder is not None else None

    metadata = Metadata(
        name=display_name(info),
        version=app_version(info),
        bundle_identifier=str(info.get("CFBundleIdentifier", "")),
        size=_file_size(ipa_file),
        icon_name=_icon_file_name(icon[0]) if icon is not None else "",
        file_name=ipa_file.name if ipa_file is not None else "",
        timestamp=int(time.time()),
    )

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        if icon is not None:
            _write_icon(icon[1], output_dir / metadata.icon_name)
        write_atomic(output_dir / METADATA_FILE, _json_bytes(metadata))
    return metadata

def _file_size(path: Path | None) -> int:
    if path is None:
        return 0
    try:
        return path.stat().st_size
    except OSError:
        return 0

def _icon_names(info: dict) -> list[str]:
    """Declared icon names, in the order the plist lists them.

    ``CFBundleIcons`` is the modern home and wins outright; the flat keys are
    only consulted when it yields nothing.
    """
    names: list[str] = []
    icons = info.get("CFBundleIcons")
    if isinstance(icons, dict):
        primary = icons.get("CFBundlePrimaryIcon")
        if isinstance(primary, dict):
            names.extend(_string_list(primary.get("CFBundleIconFiles")))
    if not names:
        names.extend(_string_list(info.get("CFBundleIconFiles")))
    if not names:
        single = info.get("CFBundleIconFile")
        if isinstance(single, str) and single:
            names.append(single)
    return names

def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]

def _chosen_icon(app_folder: Path, names: list[str]) -> tuple[Path, bytes] | None:
    """The largest declared icon in the bundle root, with its bytes.

    Only the root is searched: the icon iOS shows is never inside a nested
    framework or an asset catalogue.
    """
    best: Path | None = None
    best_size = 0
    for entry in sorted(app_folder.iterdir()):
        if not entry.is_file():
            continue
        if not any(entry.name.startswith(name) for name in names):
            continue
        size = entry.stat().st_size
        if size > best_size:
            best, best_size = entry, size

    if best is None:
        return None
    try:
        return best, best.read_bytes()
    except OSError:
        return None

def _icon_file_name(icon: Path) -> str:
    """The name the icon is written under.

    The reference hashes the icon's absolute path, which points into a
    temporary unpack directory and so changes on every run. Hashing the file
    name instead keeps the sidecar reproducible.
    """
    return hashlib.sha1(icon.name.encode("utf-8")).hexdigest() + ".png"

def _write_icon(data: bytes, target: Path) -> None:
    """Write the icon, decoded when it is the CgBI variant."""
    decoded = _decode_cgbi_png(data)
    write_atomic(target, decoded if decoded is not None else data)

def _json_bytes(metadata: Metadata) -> bytes:
    """The sidecar bytes, tab indented and UTF-8, keys in insertion order."""
    document = {
        "AppName": metadata.name,
        "AppVersion": metadata.version,
        "AppBundleIdentifier": metadata.bundle_identifier,
        "AppSize": metadata.size,
        "IconName": metadata.icon_name,
        "FileName": metadata.file_name,
        "Timestamp": metadata.timestamp,
    }
    return (json.dumps(document, indent="\t", ensure_ascii=False) + "\n").encode("utf-8")

def _decode_cgbi_png(data: bytes) -> bytes | None:
    """Convert Apple's CgBI PNG variant back to a standard PNG.

    Returns ``None`` when the input is not such a PNG, in which case the caller
    should use the original bytes as they are.
    """
    if not data.startswith(PNG_MAGIC):
        return None

    pos = len(PNG_MAGIC)
    cgbi = False
    ihdr: bytes | None = None
    idat = bytearray()
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos : pos + 4], "big")
        kind = data[pos + 4 : pos + 8]
        if length > len(data) - pos - 12:
            return None
        payload = data[pos + 8 : pos + 8 + length]
        if kind == b"CgBI":
            cgbi = True
        elif kind == b"IHDR":
            if length != 13:
                return None
            ihdr = payload
        elif kind == b"IDAT":
            idat += payload
        elif kind == b"IEND":
            break
        pos += 12 + length

    if not cgbi or ihdr is None or not idat:
        return None

    width, height = struct.unpack_from(">II", ihdr)
    # pngcrush -iphone only emits 8-bit RGBA, non-interlaced.
    if ihdr[8] != 8 or ihdr[9] != 6 or ihdr[12] != 0:
        return None
    if not width or not height or width * height > MAX_ICON_PIXELS:
        return None

    stride = width * 4
    raw = _inflate_raw(idat, (stride + 1) * height)
    if raw is None:
        return None
    if not _unfilter(raw, stride, height):
        return None
    _bgra_to_rgba(raw, stride)
    return _build_png(ihdr, raw)

def _inflate_raw(data: bytes, expected: int) -> bytearray | None:
    """Inflate a headerless deflate stream that must expand to ``expected`` bytes.

    The stream has no zlib header, so the window starts at the raw deflate
    boundary (``-MAX_WBITS``). A result of the wrong length means the file is
    not the variant this decoder handles.
    """
    try:
        raw = zlib.decompress(bytes(data), -zlib.MAX_WBITS, expected)
    except zlib.error:
        return None
    if len(raw) != expected:
        return None
    return bytearray(raw)

def _unfilter(raw: bytearray, stride: int, height: int) -> bool:
    """Reverse the per-row filters in place, zeroing every filter byte.

    Filters 2, 3 and 4 reference the previous row, so it must still hold
    reconstructed bytes while the current row is being fixed up.
    """
    row_bytes = stride + 1
    previous = bytearray(stride)
    for row in range(height):
        start = row * row_bytes
        kind = raw[start]
        line = memoryview(raw)[start + 1 : start + row_bytes]
        if kind == 0:
            pass
        elif kind == 1:
            for i in range(4, stride):
                line[i] = (line[i] + line[i - 4]) & 0xFF
        elif kind == 2:
            for i in range(stride):
                line[i] = (line[i] + previous[i]) & 0xFF
        elif kind == 3:
            for i in range(stride):
                left = line[i - 4] if i >= 4 else 0
                line[i] = (line[i] + ((left + previous[i]) >> 1)) & 0xFF
        elif kind == 4:
            for i in range(stride):
                left = line[i - 4] if i >= 4 else 0
                up = previous[i]
                up_left = previous[i - 4] if i >= 4 else 0
                line[i] = (line[i] + _paeth(left, up, up_left)) & 0xFF
        else:
            return False
        raw[start] = 0
        previous[:] = line
    return True

def _paeth(a: int, b: int, c: int) -> int:
    """The PNG Paeth predictor."""
    estimate = a + b - c
    pa = abs(estimate - a)
    pb = abs(estimate - b)
    pc = abs(estimate - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c

def _bgra_to_rgba(raw: bytearray, stride: int) -> None:
    """Swap blue and red, then undo the premultiplied alpha, in place."""
    row_bytes = stride + 1
    for start in range(0, len(raw), row_bytes):
        line = memoryview(raw)[start + 1 : start + row_bytes]
        for i in range(0, stride, 4):
            blue = line[i]
            alpha = line[i + 3]
            line[i] = line[i + 2]
            line[i + 2] = blue
            if 0 < alpha < 255:
                line[i] = min(255, (line[i] * 255 + alpha // 2) // alpha)
                line[i + 1] = min(255, (line[i + 1] * 255 + alpha // 2) // alpha)
                line[i + 2] = min(255, (line[i + 2] * 255 + alpha // 2) // alpha)

def _build_png(ihdr: bytes, raw: bytearray) -> bytes:
    """A standard PNG holding the already unfiltered scanlines."""
    return (
        PNG_MAGIC
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw)))
        + _png_chunk(b"IEND", b"")
    )

def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(kind + payload)
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)

__all__ = ["METADATA_FILE", "Metadata", "from_info"]
