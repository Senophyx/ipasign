"""Tests for per-file signing and the public Key API."""

from __future__ import annotations

import hashlib
import shutil
import struct
import unittest

from ipasign import blobs, macho
from ipasign.errors import BundleError, InvalidInputError, MachOError
from ipasign.key import Key
from ipasign.signer import (
    FileContext,
    Signer,
    bundle_id_fallback,
    embedded_info_plist_hash,
    sign_file_data,
    write_atomic,
)

from . import fixtures


def superblob_of(data: bytes, slice_index: int = 0) -> bytes:
    """Pull the SuperBlob out of a signed Mach-O."""
    parsed = macho.MachOFile.parse(data)
    slc = parsed.slices[slice_index]
    if slc.code_signature is None:
        raise AssertionError("slice carries no signature")
    start = slc.base + slc.code_signature.data[0]
    return data[start : start + slc.code_signature.data[1]]


def entries_of(superblob: bytes) -> dict[int, bytes]:
    """Map slot type to blob bytes."""
    count = struct.unpack_from(">I", superblob, 8)[0]
    out = {}
    for i in range(count):
        kind, offset = struct.unpack_from(">II", superblob, 12 + i * 8)
        length = struct.unpack_from(">I", superblob, offset + 4)[0]
        out[kind] = superblob[offset : offset + length]
    return out


class AtomicWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("signer_atomic")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_writes_and_leaves_no_temp_file(self) -> None:
        target = self.root / "Runner"
        write_atomic(target, b"payload")
        self.assertEqual(target.read_bytes(), b"payload")
        self.assertFalse((self.root / "Runner.is_tmp").exists())

    def test_overwrites_existing_file(self) -> None:
        target = self.root / "Runner"
        target.write_bytes(b"old")
        write_atomic(target, b"new")
        self.assertEqual(target.read_bytes(), b"new")

    def test_temp_name_keeps_the_basename(self) -> None:
        """Two binaries in one directory must not collide on the temp name."""
        from ipasign.signer import _temp_path

        first = _temp_path(self.root / "Runner")
        second = _temp_path(self.root / "Flutter")
        self.assertNotEqual(first, second)
        self.assertTrue(first.name.startswith("Runner"))
        self.assertTrue(first.name.endswith(".is_tmp"))


class BundleIdFallbackTests(unittest.TestCase):
    def test_uses_file_name_with_extension(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        self.assertEqual(bundle_id_fallback(slc, fixtures.SCRATCH / "libX.dylib"), "libX.dylib")

    def test_embedded_info_plist_wins(self) -> None:
        # The synthetic slice has no __info_plist, so build one with a plist.
        data = fixtures.macho_with_info_plist({"CFBundleIdentifier": "com.example.embedded"})
        slc = macho.MachOFile.parse(data).slices[0]
        self.assertTrue(slc.info_plist, "fixture must carry an embedded plist")
        self.assertEqual(bundle_id_fallback(slc, fixtures.SCRATCH / "Runner"), "com.example.embedded")

    def test_embedded_info_plist_hash(self) -> None:
        data = fixtures.macho_with_info_plist({"CFBundleIdentifier": "com.example.embedded"})
        slc = macho.MachOFile.parse(data).slices[0]
        self.assertEqual(embedded_info_plist_hash(slc), hashlib.sha256(slc.info_plist).digest())

    def test_missing_info_plist_hashes_to_zeros(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        self.assertEqual(embedded_info_plist_hash(slc), b"\0" * 32)


class AdhocSignTests(unittest.TestCase):
    """Ad-hoc needs no credentials, so it can be tested end to end."""

    def sign(self, data: bytes | None = None, **spec) -> tuple[bytes, dict[int, bytes]]:
        source = data if data is not None else fixtures.minimal_macho()
        ctx = FileContext(bundle_id=spec.pop("bundle_id", "com.example.test"))
        signed, _ = sign_file_data(Signer(adhoc=True), source, ctx)
        return signed, entries_of(superblob_of(signed))

    def test_slice_grows_and_gets_a_signature_command(self) -> None:
        signed, _ = self.sign()
        parsed = macho.MachOFile.parse(signed)
        self.assertIsNotNone(parsed.slices[0].code_signature)
        self.assertGreater(len(signed), len(fixtures.minimal_macho()))

    def test_superblob_has_no_cms_in_adhoc_mode(self) -> None:
        _, entries = self.sign()
        self.assertNotIn(blobs.CSSLOT_SIGNATURESLOT, entries, "ad-hoc omits the CMS slot")
        self.assertIn(blobs.CSSLOT_CODEDIRECTORY, entries)

    def test_code_directory_flags(self) -> None:
        _, entries = self.sign()
        cd = entries[blobs.CSSLOT_CODEDIRECTORY]
        flags = int.from_bytes(cd[12:16], "big")
        self.assertEqual(flags, blobs.CS_SEC_CODESIGNATURE_ADHOC)

    def test_code_directory_length_field_matches(self) -> None:
        _, entries = self.sign()
        cd = entries[blobs.CSSLOT_CODEDIRECTORY]
        self.assertEqual(len(cd), int.from_bytes(cd[4:8], "big"))

    def test_exec_seg_flags_set_main_binary(self) -> None:
        _, entries = self.sign()
        cd = entries[blobs.CSSLOT_CODEDIRECTORY]
        exec_seg_flags = int.from_bytes(cd[80:88], "big")
        self.assertEqual(exec_seg_flags, blobs.CS_EXECSEG_MAIN_BINARY)

    def test_code_limit_is_the_signature_offset(self) -> None:
        signed, entries = self.sign()
        slc = macho.MachOFile.parse(signed).slices[0]
        cd = entries[blobs.CSSLOT_CODEDIRECTORY]
        code_limit = int.from_bytes(cd[32:36], "big")
        self.assertEqual(code_limit, slc.code_signature.data[0])

    def test_code_slots_hash_the_pages(self) -> None:
        source = fixtures.minimal_macho()
        signed, entries = self.sign(source)
        cd = entries[blobs.CSSLOT_CODEDIRECTORY]
        hash_offset = int.from_bytes(cd[16:20], "big")
        n_code = int.from_bytes(cd[28:32], "big")
        code_limit = int.from_bytes(cd[32:36], "big")

        # The pages come from the slice the blob was built against, which is the
        # grown one; only the region before code_limit is hashed.
        expected = blobs.hash_pages(memoryview(signed), code_limit)
        self.assertEqual(n_code, len(expected))
        self.assertEqual(cd[hash_offset : hash_offset + n_code * 32], b"".join(expected))

    def test_code_slots_cover_the_grown_slice(self) -> None:
        """Page 0 holds the load commands, which growing rewrites.

        The blob is therefore built against the grown slice, not the original
        file, or the very first page hash would be stale.
        """
        signed, entries = self.sign()
        cd = entries[blobs.CSSLOT_CODEDIRECTORY]
        hash_offset = int.from_bytes(cd[16:20], "big")
        n_code = int.from_bytes(cd[28:32], "big")
        code_limit = int.from_bytes(cd[32:36], "big")

        expected = b"".join(blobs.hash_pages(memoryview(signed), code_limit))
        self.assertEqual(cd[hash_offset : hash_offset + n_code * 32], expected)

    def test_growing_changes_the_first_page_hash(self) -> None:
        """A sanity check that the previous test is not vacuous."""
        source = fixtures.minimal_macho()
        signed, entries = self.sign(source)
        cd = entries[blobs.CSSLOT_CODEDIRECTORY]
        hash_offset = int.from_bytes(cd[16:20], "big")
        code_limit = int.from_bytes(cd[32:36], "big")

        original_first = blobs.hash_pages(memoryview(source), code_limit)[0]
        self.assertNotEqual(cd[hash_offset : hash_offset + 32], original_first)

    def test_special_slots_are_sealed(self) -> None:
        """Slot -2 holds Requirements; -1 (Info.plist) stays zero here."""
        _, entries = self.sign()
        cd = entries[blobs.CSSLOT_CODEDIRECTORY]
        hash_offset = int.from_bytes(cd[16:20], "big")
        n_special = int.from_bytes(cd[24:28], "big")
        self.assertGreaterEqual(n_special, 2)

        def slot(index: int) -> bytes:
            return cd[hash_offset - 32 * (index + 1) : hash_offset - 32 * index]

        self.assertEqual(slot(0), b"\0" * 32, "slot -1 is Info.plist, absent here")
        self.assertEqual(
            slot(1), hashlib.sha256(entries[blobs.CSSLOT_REQUIREMENTS]).digest()
        )

    def test_signing_twice_is_stable(self) -> None:
        first, _ = self.sign()
        second, _ = self.sign(first)
        self.assertEqual(len(first), len(second))

    def test_fat_file_signs_every_slice(self) -> None:
        source = fixtures.minimal_fat(fixtures.minimal_macho(), fixtures.minimal_macho())
        signed, count = sign_file_data(
            Signer(adhoc=True), source, FileContext(bundle_id="com.example.fat")
        )
        self.assertEqual(count, 2)
        parsed = macho.MachOFile.parse(signed)
        self.assertEqual(len(parsed.slices), 2)
        for slc in parsed.slices:
            self.assertIsNotNone(slc.code_signature, "every slice gets a signature")

    def test_entitlements_appear_for_an_executable(self) -> None:
        signer = Signer(adhoc=True, entitlements={"get-task-allow": True},
                        entitlements_plist=fixtures.info_plist())
        signed, _ = sign_file_data(signer, fixtures.minimal_macho(), FileContext(bundle_id="a"))
        entries = entries_of(superblob_of(signed))
        self.assertIn(blobs.CSSLOT_ENTITLEMENTS, entries)
        self.assertIn(blobs.CSSLOT_DER_ENTITLEMENTS, entries)

    def test_dylib_gets_no_der_entitlements(self) -> None:
        signer = Signer(adhoc=True, entitlements={"get-task-allow": True},
                        entitlements_plist=fixtures.info_plist())
        source = fixtures.minimal_macho(file_type=0x6)  # MH_DYLIB
        signed, _ = sign_file_data(signer, source, FileContext(bundle_id="a"))
        entries = entries_of(superblob_of(signed))
        self.assertNotIn(blobs.CSSLOT_DER_ENTITLEMENTS, entries)

    def test_get_task_allow_sets_allow_unsigned(self) -> None:
        signer = Signer(adhoc=True, entitlements={"get-task-allow": True},
                        entitlements_plist=fixtures.info_plist())
        signed, _ = sign_file_data(signer, fixtures.minimal_macho(), FileContext(bundle_id="a"))
        cd = entries_of(superblob_of(signed))[blobs.CSSLOT_CODEDIRECTORY]
        flags = int.from_bytes(cd[80:88], "big")
        self.assertEqual(flags, blobs.CS_EXECSEG_MAIN_BINARY | blobs.CS_EXECSEG_ALLOW_UNSIGNED)

    def test_get_task_allow_false_does_not_set_allow_unsigned(self) -> None:
        """A distribution profile has the key but sets it false."""
        signer = Signer(adhoc=True, entitlements={"get-task-allow": False},
                        entitlements_plist=fixtures.info_plist())
        signed, _ = sign_file_data(signer, fixtures.minimal_macho(), FileContext(bundle_id="a"))
        cd = entries_of(superblob_of(signed))[blobs.CSSLOT_CODEDIRECTORY]
        flags = int.from_bytes(cd[80:88], "big")
        self.assertEqual(flags, blobs.CS_EXECSEG_MAIN_BINARY)


class SignerValidationTests(unittest.TestCase):
    def test_non_adhoc_without_identity_raises(self) -> None:
        with self.assertRaises(BundleError):
            sign_file_data(
                Signer(adhoc=False), fixtures.minimal_macho(), FileContext(bundle_id="a")
            )

    def test_bad_macho_raises(self) -> None:
        with self.assertRaises(MachOError):
            sign_file_data(Signer(adhoc=True), b"not a macho", FileContext(bundle_id="a"))


class KeyValidationTests(unittest.TestCase):
    def test_adhoc_rejects_credentials(self) -> None:
        with self.assertRaises(InvalidInputError):
            Key("x.p12", adhoc=True)

    def test_non_adhoc_needs_p12(self) -> None:
        with self.assertRaises(InvalidInputError):
            Key(None)

    def test_non_adhoc_needs_profile(self) -> None:
        with self.assertRaises(InvalidInputError):
            Key("x.p12")



if __name__ == "__main__":
    unittest.main()
