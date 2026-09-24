"""Tests for the code signature blob builders."""

from __future__ import annotations

import hashlib
import unittest

from ipasign import blobs
from ipasign.errors import BlobError


class DerLengthTests(unittest.TestCase):
    def test_short_form(self) -> None:
        self.assertEqual(blobs._der_length(0), b"\x00")
        self.assertEqual(blobs._der_length(127), b"\x7f")

    def test_long_form(self) -> None:
        self.assertEqual(blobs._der_length(128), b"\x81\x80")
        self.assertEqual(blobs._der_length(255), b"\x81\xff")
        self.assertEqual(blobs._der_length(256), b"\x82\x01\x00")


class DerIntegerTests(unittest.TestCase):
    """Boundary cases matter: a naive sizing over-allocates negatives."""

    def test_positive(self) -> None:
        self.assertEqual(blobs._der_int(0), bytes.fromhex("020100"))
        self.assertEqual(blobs._der_int(127), bytes.fromhex("02017f"))
        self.assertEqual(blobs._der_int(128), bytes.fromhex("02020080"))
        self.assertEqual(blobs._der_int(255), bytes.fromhex("020200ff"))
        self.assertEqual(blobs._der_int(256), bytes.fromhex("02020100"))

    def test_negative(self) -> None:
        self.assertEqual(blobs._der_int(-1), bytes.fromhex("0201ff"))
        self.assertEqual(blobs._der_int(-128), bytes.fromhex("020180"))
        self.assertEqual(blobs._der_int(-129), bytes.fromhex("0202ff7f"))
        # -256 needs two's complement and no redundant leading bytes.
        self.assertEqual(blobs._der_int(-256), bytes.fromhex("0202ff00"))

    def test_round_trip_through_int(self) -> None:
        for value in (-65536, -32768, -129, -128, -1, 0, 1, 127, 128, 255, 256, 65535):
            encoded = blobs._der_int(value)
            body = encoded[2:]
            self.assertEqual(int.from_bytes(body, "big", signed=True), value, value)


class DerValueTests(unittest.TestCase):
    def test_booleans(self) -> None:
        self.assertEqual(blobs._der_value(True), bytes.fromhex("0101ff"))
        self.assertEqual(blobs._der_value(False), bytes.fromhex("010100"))

    def test_bool_is_not_int(self) -> None:
        # bool is a subclass of int, so the check order matters.
        self.assertEqual(blobs._der_value(True), bytes.fromhex("0101ff"))
        self.assertNotEqual(blobs._der_value(True), blobs._der_int(1))

    def test_string(self) -> None:
        self.assertEqual(blobs._der_value("ab"), bytes.fromhex("0c026162"))
        self.assertEqual(blobs._der_value(""), bytes.fromhex("0c00"))

    def test_array(self) -> None:
        self.assertEqual(blobs._der_value([True, True]), bytes.fromhex("30060101ff0101ff"))

    def test_dictionary_is_sorted_and_wrapped(self) -> None:
        blob = blobs._der_value({"b": 1, "a": 2})
        self.assertEqual(blob[0], 0xB0, "the dict uses context-specific tag 16")
        key_a = bytes.fromhex("0c0161")  # OID-free UTF8String, length 1, "a"
        key_b = bytes.fromhex("0c0162")
        self.assertLess(blob.index(key_a), blob.index(key_b), "keys are sorted")
        # Each pair is wrapped in its own SEQUENCE.
        self.assertEqual(blob.count(b"\x30\x06"), 2)

    def test_unsupported_type_raises(self) -> None:
        for value in (object(), 1.5, None):
            with self.assertRaises(BlobError):
                blobs._der_value(value)


class EntitlementsTests(unittest.TestCase):
    def test_der_wrapper(self) -> None:
        blob = blobs.entitlements_der({"get-task-allow": False})
        self.assertEqual(blob[:4], bytes.fromhex("fade7172"))
        self.assertEqual(int.from_bytes(blob[4:8], "big"), len(blob))
        # 0x70, then the version INTEGER 1.
        self.assertEqual(blob[8], 0x70)
        self.assertEqual(blob[10:13], bytes.fromhex("020101"))

    def test_xml_wrapper_carries_plist_verbatim(self) -> None:
        plist = b'<?xml version="1.0"?><plist/>'
        blob = blobs.entitlements_xml(plist)
        self.assertEqual(blob[:4], bytes.fromhex("fade7171"))
        self.assertEqual(int.from_bytes(blob[4:8], "big"), len(blob))
        self.assertEqual(blob[8:], plist)


class RequirementsTests(unittest.TestCase):
    def test_layout(self) -> None:
        blob = blobs.requirements("com.example.app", "CN Name")
        self.assertEqual(blob[:4], bytes.fromhex("fade0c01"))
        self.assertEqual(int.from_bytes(blob[4:8], "big"), len(blob))
        self.assertEqual(int.from_bytes(blob[8:12], "big"), 1, "one designated requirement")
        self.assertEqual(int.from_bytes(blob[12:16], "big"), blobs.REQ_TYPE_DESIGNATED)
        self.assertEqual(int.from_bytes(blob[16:20], "big"), 20, "inner blob starts at 20")

        self.assertEqual(blob[20:24], bytes.fromhex("fade0c00"))
        inner_len = int.from_bytes(blob[24:28], "big")
        self.assertEqual(inner_len, len(blob) - 20)

    def test_strings_are_nul_padded_to_four(self) -> None:
        # "subject.CN" is 10 bytes, so two padding bytes follow.
        blob = blobs.requirements("a", "b")
        self.assertIn(b"subject.CN\x00\x00", blob)

    def test_empty_set_when_input_incomplete(self) -> None:
        empty = bytes.fromhex("fade0c010000000c00000000")
        self.assertEqual(blobs.requirements("", "CN"), empty)
        self.assertEqual(blobs.requirements("com.example.app", ""), empty)
        self.assertEqual(blobs.requirements("", ""), empty)

    def test_bundle_id_is_embedded(self) -> None:
        blob = blobs.requirements("com.example.mine", "CN")
        self.assertIn(b"com.example.mine", blob)


class SpecialSlotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.empty = b"\0" * 32
        self.base = dict(
            bundle_id="a", team_id="t", code_limit=1, exec_seg_limit=0, is_execute=True
        )

    def test_all_empty_drops_everything(self) -> None:
        self.assertEqual(blobs._special_slots(blobs.CodeDirectorySpec(**self.base)), [])

    def test_trailing_slots_are_erased(self) -> None:
        spec = blobs.CodeDirectorySpec(**self.base, info_plist_hash=b"\x01" * 32)
        self.assertEqual(blobs._special_slots(spec), [b"\x01" * 32])

    def test_interior_empty_slot_survives(self) -> None:
        # -7 filled, -6 and -4 empty: those zeros must stay.
        spec = blobs.CodeDirectorySpec(**self.base, der_entitlements_hash=b"\x02" * 32)
        slots = blobs._special_slots(spec)
        self.assertEqual(len(slots), 7)
        self.assertEqual(slots[0], b"\x02" * 32)
        self.assertEqual(slots[1], self.empty)
        self.assertEqual(slots[3], self.empty)

    def test_non_executable_omits_der_and_unused(self) -> None:
        spec = blobs.CodeDirectorySpec(
            **{**self.base, "is_execute": False}, entitlements_hash=b"\x07" * 32
        )
        slots = blobs._special_slots(spec)
        self.assertEqual(len(slots), 5)
        self.assertEqual(slots[0], b"\x07" * 32)
        self.assertEqual(slots[1], self.empty)


class ExecSegFlagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = dict(
            bundle_id="a", team_id="t", code_limit=1, exec_seg_limit=0, is_execute=True
        )

    def test_main_binary_for_execute(self) -> None:
        self.assertEqual(blobs.exec_seg_flags(blobs.CodeDirectorySpec(**self.base)), 0x1)

    def test_allow_unsigned_only_with_get_task_allow(self) -> None:
        self.assertEqual(
            blobs.exec_seg_flags(blobs.CodeDirectorySpec(**self.base, get_task_allow=True)),
            0x11,
        )

    def test_non_execute_has_no_flags(self) -> None:
        spec = blobs.CodeDirectorySpec(**{**self.base, "is_execute": False})
        self.assertEqual(blobs.exec_seg_flags(spec), 0)


class CodeDirectoryTests(unittest.TestCase):
    def test_header_and_offsets(self) -> None:
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
        self.assertEqual(len(cd), int.from_bytes(cd[4:8], "big"), "length must match")

        fields = [int.from_bytes(cd[i : i + 4], "big") for i in range(0, 36, 4)]
        _, _, version, flags, hash_offset, ident_offset, n_special, n_code, code_limit = fields
        self.assertEqual(version, blobs.CD_VERSION)
        self.assertEqual(flags, 0)
        self.assertEqual(ident_offset, blobs.CD_HEADER_SIZE)
        self.assertEqual(n_special, 1)
        self.assertEqual(n_code, 2, "5000 bytes is two pages")
        self.assertEqual(code_limit, 5000)
        expected_hash_offset = blobs.CD_HEADER_SIZE + len("com.example.app") + 1 + 32 + len("TEAM123456") + 1
        self.assertEqual(hash_offset, expected_hash_offset)
        self.assertEqual(hash_offset + n_code * 32, len(cd))

        hash_size, hash_type, spare1, page_size = cd[36:40]
        self.assertEqual((hash_size, hash_type, page_size), (32, 2, 12))

    def test_adhoc_flag_and_no_team_offset(self) -> None:
        cd = blobs.code_directory(
            blobs.CodeDirectorySpec(
                bundle_id="a", team_id="", code_limit=1, exec_seg_limit=0,
                is_execute=False, adhoc=True, code_slots=[b"\x06" * 32],
            )
        )
        self.assertEqual(int.from_bytes(cd[12:16], "big"), blobs.CS_SEC_CODESIGNATURE_ADHOC)
        self.assertEqual(int.from_bytes(cd[48:52], "big"), 0, "teamOffset zero without team id")

    def test_missing_bundle_id_raises(self) -> None:
        with self.assertRaises(BlobError):
            blobs.code_directory(
                blobs.CodeDirectorySpec(
                    bundle_id="", team_id="t", code_limit=1, exec_seg_limit=0,
                    is_execute=False, code_slots=[b"\x01" * 32],
                )
            )

    def test_slot_count_mismatch_raises(self) -> None:
        with self.assertRaises(BlobError):
            blobs.code_directory(
                blobs.CodeDirectorySpec(
                    bundle_id="a", team_id="t", code_limit=1, exec_seg_limit=0,
                    is_execute=False, code_slots=[],
                )
            )


class HashPagesTests(unittest.TestCase):
    def test_full_pages(self) -> None:
        data = memoryview(b"\x01" * 8192)
        slots = blobs.hash_pages(data, 8192)
        self.assertEqual(len(slots), 2)
        self.assertEqual(slots[0], hashlib.sha256(b"\x01" * 4096).digest())

    def test_short_final_page_is_hashed_as_is(self) -> None:
        data = memoryview(b"\x01" * 5000)
        slots = blobs.hash_pages(data, 5000)
        self.assertEqual(len(slots), 2)
        self.assertEqual(slots[1], hashlib.sha256(b"\x01" * 904).digest())

    def test_zero_limit_gives_no_slots(self) -> None:
        self.assertEqual(blobs.hash_pages(memoryview(b"abc"), 0), [])

    def test_limit_past_end_raises(self) -> None:
        with self.assertRaises(BlobError):
            blobs.hash_pages(memoryview(b"abc"), 4)


class SuperBlobTests(unittest.TestCase):
    def test_offsets_and_length(self) -> None:
        a, b = b"AAAA", b"BB"
        blob = blobs.superblob([(0, a), (2, b)])
        self.assertEqual(blob[:4], bytes.fromhex("fade0cc0"))
        self.assertEqual(int.from_bytes(blob[4:8], "big"), len(blob))
        self.assertEqual(int.from_bytes(blob[8:12], "big"), 2)
        self.assertEqual(int.from_bytes(blob[12:16], "big"), 0)
        self.assertEqual(int.from_bytes(blob[16:20], "big"), 12 + 16)
        self.assertEqual(int.from_bytes(blob[20:24], "big"), 2)
        self.assertEqual(int.from_bytes(blob[24:28], "big"), 12 + 16 + len(a))
        self.assertTrue(blob.endswith(a + b))

    def test_empty_blobs_are_skipped(self) -> None:
        blob = blobs.superblob([(0, b"AAAA"), (2, b""), (5, b"BB")])
        self.assertEqual(int.from_bytes(blob[8:12], "big"), 2, "count excludes empties")

    def test_all_empty_is_an_empty_container(self) -> None:
        blob = blobs.superblob([(0, b""), (2, b"")])
        self.assertEqual(blob, bytes.fromhex("fade0cc00000000c00000000"))


if __name__ == "__main__":
    unittest.main()
