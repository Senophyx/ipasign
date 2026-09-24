"""IPA unpack and repack.

An ``.ipa`` is a zip holding a ``Payload`` folder with the app bundle inside.
Unpacking happens under a scratch directory named ``.ipasign_tmp`` beside the
input, so the work stays on the same filesystem and inside the project.
"""

from __future__ import annotations

import os
import shutil
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .errors import ArchiveError

SCRATCH_DIR = ".ipasign_tmp"


def scratch_root(anchor: Path) -> Path:
    """The scratch directory used for unpacking ``anchor``.

    A file anchor uses its parent, so the work sits next to the input rather
    than in a system temp location.
    """
    base = anchor if anchor.is_dir() else anchor.parent
    return base / SCRATCH_DIR


def _safe_member(name: str) -> bool:
    """Reject absolute paths and parent traversal in an archive member."""
    if not name or name.startswith("/") or name.startswith("\\"):
        return False
    if ":" in name:
        return False
    return ".." not in name.replace("\\", "/").split("/")


@dataclass(slots=True)
class Unpacked:
    """Where an archive was unpacked and what was found inside."""

    root: Path
    payload: Path
    app: Path


def find_app(root: Path) -> Path:
    """The single ``.app`` bundle under ``Payload``."""
    payload = root / "Payload"
    if not payload.is_dir():
        raise ArchiveError(f"archive has no Payload directory: {root}")
    apps = sorted(path for path in payload.iterdir() if path.name.endswith(".app"))
    if not apps:
        raise ArchiveError(f"Payload holds no .app bundle: {payload}")
    if len(apps) > 1:
        raise ArchiveError(f"Payload holds more than one .app bundle: {payload}")
    return apps[0]


def unpack(ipa_path: Path, work_dir: Path | None = None) -> Unpacked:
    """Extract an ``.ipa`` into ``work_dir`` and locate the app bundle."""
    ipa_path = Path(ipa_path)
    if not ipa_path.is_file():
        raise ArchiveError(f"archive not found: {ipa_path}")

    if work_dir is None:
        root = scratch_root(ipa_path) / ipa_path.stem
    else:
        root = Path(work_dir)

    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(ipa_path) as archive:
            for info in archive.infolist():
                if not _safe_member(info.filename):
                    raise ArchiveError(f"archive holds an unsafe path: {info.filename}")
                archive.extract(info, root)
                _restore_mode(root / info.filename, info)
    except zipfile.BadZipFile as exc:
        shutil.rmtree(root, ignore_errors=True)
        raise ArchiveError(f"{ipa_path} is not a zip archive: {exc}") from exc
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise

    return Unpacked(root=root, payload=root / "Payload", app=find_app(root))


def _restore_mode(path: Path, info: zipfile.ZipInfo) -> None:
    """Give extracted files the permissions the archive recorded.

    Mach-O executables must stay executable, and zipfile only applies the mode
    when it is told to.
    """
    if info.is_dir():
        return
    mode = info.external_attr >> 16
    if not mode:
        return
    try:
        path.chmod(stat.S_IMODE(mode))
    except OSError:
        pass


def pack(source: Path, output: Path) -> Path:
    """Zip everything under ``source`` into ``output``.

    Directory entries are written first so an unzip that ignores ordering still
    creates the tree. Files keep their recorded modification time.
    """
    source = Path(source)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    temp = output.with_name(output.name + ".is_tmp")
    try:
        with zipfile.ZipFile(temp, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for dirpath, dirnames, filenames in os.walk(source):
                dirnames.sort()
                filenames.sort()
                for name in dirnames:
                    path = Path(dirpath) / name
                    info = zipfile.ZipInfo(path.relative_to(source).as_posix() + "/")
                    info.external_attr = (stat.S_IFDIR | 0o755) << 16 | 0x10
                    info.date_time = _zip_time(path)
                    archive.writestr(info, b"")
                for name in filenames:
                    path = Path(dirpath) / name
                    info = zipfile.ZipInfo(path.relative_to(source).as_posix())
                    info.external_attr = (stat.S_IFREG | stat.S_IMODE(path.stat().st_mode)) << 16
                    info.date_time = _zip_time(path)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    with open(path, "rb") as handle:
                        archive.writestr(info, handle.read())
        os.replace(temp, output)
    except Exception:
        try:
            temp.unlink()
        except OSError:
            pass
        raise
    return output


def _zip_time(path: Path) -> tuple[int, int, int, int, int, int]:
    """DOS timestamp for a path, clamped to the range the zip format allows."""
    stamp = path.stat().st_mtime
    import time

    local = time.localtime(stamp)
    year = max(1980, min(local.tm_year, 2107))
    return (year, local.tm_mon, local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec)


def cleanup(root: Path) -> None:
    """Remove a scratch directory, pruning the ``.ipasign_tmp`` root when empty."""
    shutil.rmtree(root, ignore_errors=True)
    parent = root.parent
    if parent.name == SCRATCH_DIR and parent.is_dir() and not any(parent.iterdir()):
        try:
            parent.rmdir()
        except OSError:
            pass


__all__ = ["SCRATCH_DIR", "Unpacked", "cleanup", "find_app", "pack", "scratch_root", "unpack"]
