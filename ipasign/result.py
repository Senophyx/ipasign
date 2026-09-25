"""What a signing run produced.

Kept in its own module so :mod:`ipasign.app` and :mod:`ipasign.key` can both
refer to it without importing each other.
"""

from __future__ import annotations

from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class SignResult:
    """What a completed signing run produced.

    ``output_path`` is where the artifact actually landed, ``bundle_id`` the
    identifier sealed into the CodeDirectory, and ``signed_count`` how many
    Mach-O files were signed.

    ``app_name`` and ``app_version`` describe the app itself, read from the
    bundle's ``Info.plist``. ``app_version`` is the release version
    (``CFBundleShortVersionString``), which is what a person recognises, not the
    build number. Both are empty for a bare Mach-O, which has no ``Info.plist``
    to read them from.
    """

    output_path: str
    bundle_id: str
    signed_count: int
    app_name: str = ""
    app_version: str = ""

__all__ = ["SignResult"]
