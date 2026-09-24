"""Code signature blob construction.

The signature region of a Mach-O is a SuperBlob: a header with a table of
(type, offset) entries followed by the blobs themselves. This module builds each
blob type and assembles them into the SuperBlob a verifier walks.

All multi-byte integers on disk are big-endian, whatever the Mach-O header says.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from .errors import BlobError

CSMAGIC_REQUIREMENT = 0xFADE0C00
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01

CSSLOT_CODEDIRECTORY = 0
CSSLOT_REQUIREMENTS = 2
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
CSSLOT_SIGNATURESLOT = 0x10000

CS_SEC_CODESIGNATURE_ADHOC = 0x2

CS_EXECSEG_MAIN_BINARY = 0x1
CS_EXECSEG_ALLOW_UNSIGNED = 0x10

CD_VERSION = 0x20400
CD_PAGE_SHIFT = 12
CD_PAGE_SIZE = 1 << CD_PAGE_SHIFT
CD_HASH_TYPE_SHA256 = 2
CD_HASH_SIZE_SHA256 = 32
CD_HEADER_SIZE = 88

# Requirement expression opcodes and match operations.
REQ_OP_TRUE = 1
REQ_OP_IDENT = 2
REQ_OP_AND = 6
REQ_OP_CERT_FIELD = 11
REQ_OP_CERT_GENERIC = 14
REQ_OP_APPLE_GENERIC_ANCHOR = 15
REQ_MATCH_EXISTS = 0
REQ_MATCH_EQUAL = 1
REQ_TYPE_DESIGNATED = 3

WWDR_INTERMEDIATE_OID = bytes.fromhex("2a864886f76364060201")


def _be32(value: int) -> bytes:
    return struct.pack(">I", value)


def _be64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _padded_string(text: bytes) -> bytes:
    """Length-prefixed string padded to a 4-byte boundary."""
    pad = (4 - len(text) % 4) % 4
    return _be32(len(text)) + text + b"\0" * pad


def blob(magic: int, body: bytes) -> bytes:
    """Wrap ``body`` in the standard magic plus length header."""
    return _be32(magic) + _be32(len(body) + 8) + body


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_int(value: int) -> bytes:
    """Minimal two's complement INTEGER, sign included."""
    if value == 0:
        raw = b"\0"
    elif value > 0:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\0" + raw
    else:
        size = (value.bit_length() + 8) // 8
        while True:
            try:
                raw = value.to_bytes(size, "big", signed=True)
            except OverflowError:
                size += 1
                continue
            # Strip redundant leading 0xff bytes, but keep the sign bit set.
            while len(raw) > 1 and raw[0] == 0xFF and raw[1] & 0x80:
                raw = raw[1:]
            break
    return b"\x02" + _der_length(len(raw)) + raw


def _der_value(value: object) -> bytes:
    if isinstance(value, bool):
        return b"\x01\x01" + (b"\xff" if value else b"\x00")
    if isinstance(value, int):
        return _der_int(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return b"\x0c" + _der_length(len(raw)) + raw
    if isinstance(value, (list, tuple)):
        body = b"".join(_der_value(item) for item in value)
        return b"\x30" + _der_length(len(body)) + body
    if isinstance(value, dict):
        entries = bytearray()
        for key in sorted(value):
            if not isinstance(key, str):
                raise BlobError(f"entitlement keys must be strings, got {type(key).__name__}")
            entry = _der_value(key) + _der_value(value[key])
            entries += b"\x30" + _der_length(len(entry)) + entry
        return b"\xb0" + _der_length(len(entries)) + bytes(entries)
    raise BlobError(f"entitlements cannot hold a {type(value).__name__}")


def entitlements_der(entitlements: dict) -> bytes:
    """DER form of an entitlements dictionary, wrapped in the version marker."""
    body = b"\x02\x01\x01" + _der_value(entitlements)
    return blob(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, b"\x70" + _der_length(len(body)) + body)


def entitlements_xml(plist_bytes: bytes) -> bytes:
    """XML entitlements blob, the plist bytes carried verbatim."""
    return blob(CSMAGIC_EMBEDDED_ENTITLEMENTS, plist_bytes)


def requirements(bundle_id: str, subject_cn: str) -> bytes:
    """Designated requirement pinning the bundle id, the leaf CN and the WWDR CA.

    With no bundle id or no subject CN there is nothing to pin, so the empty
    requirement set is emitted instead.
    """
    if not bundle_id or not subject_cn:
        return _be32(CSMAGIC_REQUIREMENTS) + _be32(12) + _be32(0)

    expr = bytearray()
    expr += _be32(REQ_OP_TRUE)
    expr += _be32(REQ_OP_AND)
    expr += _be32(REQ_OP_IDENT)
    expr += _padded_string(bundle_id.encode("utf-8"))
    expr += _be32(REQ_OP_AND)
    expr += _be32(REQ_OP_APPLE_GENERIC_ANCHOR)
    expr += _be32(REQ_OP_AND)
    expr += _be32(REQ_OP_CERT_FIELD)
    expr += _be32(0)
    expr += _padded_string(b"subject.CN")
    expr += _be32(REQ_MATCH_EQUAL)
    expr += _padded_string(subject_cn.encode("utf-8"))
    expr += _be32(REQ_OP_CERT_GENERIC)
    expr += _be32(1)
    expr += _padded_string(WWDR_INTERMEDIATE_OID)
    expr += _be32(REQ_MATCH_EXISTS)

    inner = blob(CSMAGIC_REQUIREMENT, bytes(expr))
    outer = bytearray()
    outer += _be32(CSMAGIC_REQUIREMENTS)
    outer += _be32(20 + len(inner))
    outer += _be32(1)
    outer += _be32(REQ_TYPE_DESIGNATED)
    outer += _be32(20)
    outer += inner
    return bytes(outer)


@dataclass(slots=True)
class CodeDirectorySpec:
    """Everything the CodeDirectory builder needs besides the code itself."""

    bundle_id: str
    team_id: str
    code_limit: int
    exec_seg_limit: int
    is_execute: bool
    adhoc: bool = False
    info_plist_hash: bytes = b""
    requirements_hash: bytes = b""
    code_resources_hash: bytes = b""
    entitlements_hash: bytes = b""
    der_entitlements_hash: bytes = b""
    get_task_allow: bool = False
    code_slots: list[bytes] = field(default_factory=list)


def _special_slots(spec: CodeDirectorySpec) -> list[bytes]:
    """Hashes for slots -7 through -1, highest index first.

    Leading empty slots are dropped: a slot index that no blob occupies costs
    nothing, and Apple never writes them. An empty slot between two filled ones
    stays and is serialised as a zero hash.
    """
    empty = b"\0" * CD_HASH_SIZE_SHA256
    slots: list[bytes] = []
    if spec.is_execute:
        slots.append(spec.der_entitlements_hash or empty)
        slots.append(empty)
    slots.append(spec.entitlements_hash or empty)
    slots.append(empty)
    slots.append(spec.code_resources_hash or empty)
    slots.append(spec.requirements_hash or empty)
    slots.append(spec.info_plist_hash or empty)

    first_used = 0
    for index, value in enumerate(slots):
        if value != empty:
            first_used = index
            break
    else:
        return []
    return slots[first_used:]


def exec_seg_flags(spec: CodeDirectorySpec) -> int:
    """Bitfield for the executable segment.

    ``MAIN_BINARY`` marks the process entry point and is required on any
    ``MH_EXECUTE``. ``ALLOW_UNSIGNED`` is development only and is set solely
    when ``get-task-allow`` is true, not merely present.
    """
    flags = 0
    if spec.is_execute:
        flags |= CS_EXECSEG_MAIN_BINARY
        if spec.get_task_allow:
            flags |= CS_EXECSEG_ALLOW_UNSIGNED
    return flags


def code_directory(spec: CodeDirectorySpec) -> bytes:
    """Build the SHA-256 CodeDirectory for one slice."""
    if not spec.bundle_id:
        raise BlobError("a CodeDirectory needs a bundle identifier")
    if spec.code_limit <= 0:
        raise BlobError("a CodeDirectory needs a positive code limit")

    ident = spec.bundle_id.encode("utf-8") + b"\0"
    team = spec.team_id.encode("utf-8") + b"\0" if spec.team_id else b""
    slots = _special_slots(spec)

    n_code = spec.code_limit // CD_PAGE_SIZE
    if spec.code_limit % CD_PAGE_SIZE:
        n_code += 1
    if len(spec.code_slots) != n_code:
        raise BlobError(f"expected {n_code} code slots, got {len(spec.code_slots)}")

    ident_offset = CD_HEADER_SIZE
    team_offset = ident_offset + len(ident) if team else 0
    hash_offset = ident_offset + len(ident) + len(team) + len(slots) * CD_HASH_SIZE_SHA256

    out = bytearray()
    out += _be32(CSMAGIC_CODEDIRECTORY)
    out += _be32(0)  # length, patched below
    out += _be32(CD_VERSION)
    out += _be32(CS_SEC_CODESIGNATURE_ADHOC if spec.adhoc else 0)
    out += _be32(hash_offset)
    out += _be32(ident_offset)
    out += _be32(len(slots))
    out += _be32(n_code)
    out += _be32(spec.code_limit)
    out += bytes([CD_HASH_SIZE_SHA256, CD_HASH_TYPE_SHA256, 0, CD_PAGE_SHIFT])
    out += _be32(0)  # spare2
    out += _be32(0)  # scatterOffset
    out += _be32(team_offset)
    out += _be32(0)  # spare3
    out += _be64(0)  # codeLimit64
    out += _be64(0)  # execSegBase
    out += _be64(spec.exec_seg_limit)
    out += _be64(exec_seg_flags(spec))
    assert len(out) == CD_HEADER_SIZE, "CodeDirectory header size drifted"

    out += ident
    out += team
    for value in slots:
        if len(value) != CD_HASH_SIZE_SHA256:
            raise BlobError("special slot hash has the wrong size")
        out += value
    for value in spec.code_slots:
        if len(value) != CD_HASH_SIZE_SHA256:
            raise BlobError("code slot hash has the wrong size")
        out += value

    struct.pack_into(">I", out, 4, len(out))
    return bytes(out)


def hash_pages(data: memoryview, limit: int, page_size: int = CD_PAGE_SIZE) -> list[bytes]:
    """SHA-256 each page of ``data`` up to ``limit`` bytes.

    The last page may be short and is hashed as-is, never zero padded.
    """
    if limit < 0 or limit > len(data):
        raise BlobError(f"code limit {limit} is outside the slice (size {len(data)})")
    slots: list[bytes] = []
    offset = 0
    while offset < limit:
        end = min(offset + page_size, limit)
        slots.append(hashlib.sha256(data[offset:end]).digest())
        offset = end
    return slots


def superblob(entries: list[tuple[int, bytes]]) -> bytes:
    """Assemble blobs into a SuperBlob, in the order given.

    Empty blobs are skipped and the count and offsets reflect only what is
    present.
    """
    present = [(kind, body) for kind, body in entries if body]
    header_size = 12 + 8 * len(present)
    out = bytearray()
    out += _be32(CSMAGIC_EMBEDDED_SIGNATURE)
    out += _be32(0)  # length, patched below
    out += _be32(len(present))

    offset = header_size
    bodies = bytearray()
    for kind, body in present:
        out += _be32(kind)
        out += _be32(offset)
        bodies += body
        offset += len(body)
    out += bodies

    struct.pack_into(">I", out, 4, len(out))
    return bytes(out)


def blob_wrapper(payload: bytes) -> bytes:
    """Wrap a CMS signature in the blob type the signature slot expects."""
    return blob(CSMAGIC_BLOBWRAPPER, payload)


__all__ = [
    "CodeDirectorySpec",
    "code_directory",
    "entitlements_der",
    "entitlements_xml",
    "exec_seg_flags",
    "hash_pages",
    "requirements",
    "superblob",
    "blob",
    "blob_wrapper",
    "CSSLOT_CODEDIRECTORY",
    "CSSLOT_REQUIREMENTS",
    "CSSLOT_ENTITLEMENTS",
    "CSSLOT_DER_ENTITLEMENTS",
    "CSSLOT_ALTERNATE_CODEDIRECTORIES",
    "CSSLOT_SIGNATURESLOT",
]
