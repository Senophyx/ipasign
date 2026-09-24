"""Self-checks for the pure logic in ipasign.

Run with ``python -m ipasign._selftest``. These cover the parts that are easy to
get silently wrong and that need no sample IPA or certificate: DER integers,
requirement encoding, special slot trimming, signature region sizing and the
plist real formatting.
"""

from __future__ import annotations

import plistlib

from . import _plist, blobs, macho


def test_der_integers() -> None:
    assert blobs._der_int(0) == bytes.fromhex("020100")
    assert blobs._der_int(127) == bytes.fromhex("02017f")
    assert blobs._der_int(128) == bytes.fromhex("02020080")
    assert blobs._der_int(255) == bytes.fromhex("020200ff")
    assert blobs._der_int(256) == bytes.fromhex("02020100")
    assert blobs._der_int(-128) == bytes.fromhex("020180")
    assert blobs._der_int(-129) == bytes.fromhex("0202ff7f")
    assert blobs._der_int(-1) == bytes.fromhex("0201ff")


def test_der_booleans_and_strings() -> None:
    assert blobs._der_value(True) == bytes.fromhex("0101ff")
    assert blobs._der_value(False) == bytes.fromhex("010100")
    assert blobs._der_value("ab") == bytes.fromhex("0c026162")


def test_requirements_layout() -> None:
    blob = blobs.requirements("com.example.app", "CN Name")
    assert blob[:4] == bytes.fromhex("fade0c01")
    total = int.from_bytes(blob[4:8], "big")
    assert total == len(blob), "length field must match the built length"
    assert int.from_bytes(blob[8:12], "big") == 1
    assert int.from_bytes(blob[12:16], "big") == blobs.REQ_TYPE_DESIGNATED
    assert int.from_bytes(blob[16:20], "big") == 20
    assert blob[20:24] == bytes.fromhex("fade0c00")
    inner_len = int.from_bytes(blob[24:28], "big")
    assert inner_len == len(blob) - 20

    empty = blobs.requirements("", "CN")
    assert empty == bytes.fromhex("fade0c010000000c00000000")
    assert blobs.requirements("com.example.app", "") == empty


def test_special_slot_trimming() -> None:
    empty = b"\0" * 32
    base = dict(bundle_id="a", team_id="t", code_limit=1, exec_seg_limit=0, is_execute=True)

    # Nothing but the mandatory zero slot -4: every leading slot drops.
    spec = blobs.CodeDirectorySpec(**base)
    assert blobs._special_slots(spec) == []

    # Info.plist fills -1, so -1 survives and nothing above it does.
    spec = blobs.CodeDirectorySpec(**base, info_plist_hash=b"\x01" * 32)
    assert blobs._special_slots(spec) == [b"\x01" * 32]

    # DER entitlements fill -7 while -6 and -4 stay zero: those survive.
    spec = blobs.CodeDirectorySpec(**base, der_entitlements_hash=b"\x02" * 32)
    slots = blobs._special_slots(spec)
    assert len(slots) == 7
    assert slots[0] == b"\x02" * 32
    assert slots[5] == empty and slots[3] == empty

    # A non-executable omits -6 and -7 entirely. Entitlements at -5 with the
    # zero slot -4 below it means five slots survive.
    spec = blobs.CodeDirectorySpec(
        **{**base, "is_execute": False}, entitlements_hash=b"\x07" * 32
    )
    slots = blobs._special_slots(spec)
    assert len(slots) == 5
    assert slots[0] == b"\x07" * 32 and slots[1] == empty

    # Only Info.plist filled on a non-executable: the four leading slots drop.
    spec = blobs.CodeDirectorySpec(
        **{**base, "is_execute": False}, info_plist_hash=b"\x01" * 32
    )
    assert blobs._special_slots(spec) == [b"\x01" * 32]


def test_exec_seg_flags() -> None:
    base = dict(bundle_id="a", team_id="t", code_limit=1, exec_seg_limit=0, is_execute=True)
    assert blobs.exec_seg_flags(blobs.CodeDirectorySpec(**base)) == 0x1
    assert blobs.exec_seg_flags(blobs.CodeDirectorySpec(**base, get_task_allow=True)) == 0x11
    assert (
        blobs.exec_seg_flags(blobs.CodeDirectorySpec(**{**base, "is_execute": False}))
        == 0
    )


def test_code_directory_self_consistency() -> None:
    spec = blobs.CodeDirectorySpec(
        bundle_id="com.example.app",
        team_id="TEAM123456",
        code_limit=5000,
        exec_seg_limit=4096,
        is_execute=True,
        info_plist_hash=b"\x03" * 32,
        code_slots=[b"\x04" * 32, b"\x05" * 32],
    )
    cd = blobs.code_directory(spec)
    assert len(cd) == int.from_bytes(cd[4:8], "big"), "length field must match the blob"

    (_, _, version, flags, hash_offset, ident_offset, n_special, n_code, code_limit) = (
        int.from_bytes(cd[i : i + 4], "big") for i in range(0, 36, 4)
    )
    assert version == blobs.CD_VERSION
    assert flags == 0
    assert ident_offset == blobs.CD_HEADER_SIZE
    assert n_special == 1
    assert n_code == 2, "5000 bytes is two pages"
    assert code_limit == 5000
    assert hash_offset == blobs.CD_HEADER_SIZE + len("com.example.app") + 1 + 32 + len("TEAM123456") + 1
    assert hash_offset + n_code * 32 == len(cd)

    # Ad-hoc sets the flag and tolerates a missing team id.
    adhoc = blobs.code_directory(
        blobs.CodeDirectorySpec(
            bundle_id="a", team_id="", code_limit=1, exec_seg_limit=0, is_execute=False,
            adhoc=True, code_slots=[b"\x06" * 32],
        )
    )
    assert int.from_bytes(adhoc[12:16], "big") == blobs.CS_SEC_CODESIGNATURE_ADHOC
    assert int.from_bytes(adhoc[48:52], "big") == 0, "teamOffset is zero with no team id"


def test_signature_region_size() -> None:
    size = macho.signature_region_size(0)
    assert size % 4096 == 0
    assert size >= 32768
    assert macho.signature_region_size(319488) > size, "one page past the 4096 rounding"
    assert macho.signature_region_size(4095) == size, "no page crossed yet"


def test_align_helpers() -> None:
    assert macho.align_up(4096, 4096) == 8192, "align_up is never a no-op"
    assert macho.round_up(4096, 4096) == 4096
    assert macho.align_up(4097, 4096) == 8192
    assert macho.round_up(4097, 4096) == 8192


def test_plist_real_formatting() -> None:
    raw = _plist.dumps({"weight": 1000.0, "ratio": 0.5, "n": 7})
    assert b"<real>1000</real>" in raw
    assert b"<real>1000.0</real>" not in raw
    assert b"<real>0.5</real>" in raw
    assert plistlib.loads(raw) == {"weight": 1000.0, "ratio": 0.5, "n": 7}


def test_plist_key_order() -> None:
    raw = _plist.dumps({"z": 1, "a": 2, "m": 3})
    assert raw.index(b"<key>z</key>") < raw.index(b"<key>a</key>") < raw.index(b"<key>m</key>")


def test_superblob_offsets() -> None:
    a = b"AAAA"
    b = b"BB"
    blob = blobs.superblob([(0, a), (2, b), (5, b"")])
    assert int.from_bytes(blob[4:8], "big") == len(blob)
    assert int.from_bytes(blob[8:12], "big") == 2, "the empty blob is skipped"
    assert int.from_bytes(blob[12:16], "big") == 0
    assert int.from_bytes(blob[16:20], "big") == 12 + 16
    assert int.from_bytes(blob[20:24], "big") == 2
    assert int.from_bytes(blob[24:28], "big") == 12 + 16 + len(a)
    assert blob.endswith(a + b)


def test_hash_pages_short_final_page() -> None:
    data = memoryview(b"\x01" * 5000)
    slots = blobs.hash_pages(data, 5000)
    assert len(slots) == 2
    assert slots[1] == __import__("hashlib").sha256(b"\x01" * 904).digest()


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {test.__name__}: {exc}")
        else:
            print(f"ok   {test.__name__}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
