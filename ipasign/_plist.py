"""Plist serialisation matching what Apple's own tooling emits.

``plistlib`` gets the structure right but writes every ``<real>`` with a decimal
part, so an integral weight comes out as ``1000.0`` where Apple writes ``1000``.
Signing hashes these bytes, so the difference would invalidate a seal. A single
post-processing pass closes the gap.
"""

from __future__ import annotations

import plistlib
import re

_INTEGRAL_REAL = re.compile(rb"<real>(-?\d+)\.0</real>")


def dumps(value: object) -> bytes:
    """Serialise ``value`` as an XML plist with insertion order preserved."""
    raw = plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=False)
    return _INTEGRAL_REAL.sub(rb"<real>\1</real>", raw)


def loads(data: bytes) -> object:
    """Parse an XML or binary plist."""
    return plistlib.loads(data)


__all__ = ["dumps", "loads"]
