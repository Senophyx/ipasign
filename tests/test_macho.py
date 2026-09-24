"""Tests for Mach-O parsing and rewriting."""

from __future__ import annotations

import unittest

from ipasign import macho
from ipasign.errors import MachOError

from . import fixtures


class AlignHelperTests(unittest.TestCase):
    def test_align_up_is_never_a_noop(self) -> None:
        self.assertEqual(macho.align_up(4096, 4096), 8192)
        self.assertEqual(macho.align_up(4097, 4096), 8192)
        self.assertEqual(macho.align_up(1, 4096), 4096)

    def test_round_up_is_a_noop_when_aligned(self) -> None:
        self.assertEqual(macho.round_up(4096, 4096), 4096)
        self.assertEqual(macho.round_up(4097, 4096), 8192)
        self.assertEqual(macho.round_up(1, 4096), 4096)


class SignatureRegionTests(unittest.TestCase):
    def test_page_aligned_and_has_headroom(self) -> None:
        size = macho.signature_region_size(0)
        self.assertEqual(size % 4096, 0)
        self.assertGreaterEqual(size, 32768)

    def test_grows_when_a_page_is_crossed(self) -> None:
        base = macho.signature_region_size(0)
        self.assertEqual(macho.signature_region_size(4095), base, "no page crossed yet")
        self.assertGreater(macho.signature_region_size(319488), base)


class ParseThinTests(unittest.TestCase):
    def test_fields(self) -> None:
        parsed = macho.MachOFile.parse(fixtures.minimal_macho())
        self.assertFalse(parsed.is_fat)
        self.assertEqual(len(parsed.slices), 1)
        slc = parsed.slices[0]
        self.assertTrue(slc.is_64)
        self.assertFalse(slc.big_endian)
        self.assertTrue(slc.is_execute)
        self.assertEqual(slc.ncmds, 2)
        self.assertEqual(len(slc.segments), 2)

    def test_segments_and_section(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        text = slc.text_segment
        self.assertIsNotNone(text)
        self.assertEqual(text.name, "__TEXT")
        self.assertEqual(text.vmsize, fixtures.TEXT_END)
        self.assertEqual(slc.exec_seg_limit, fixtures.TEXT_END)

        linkedit = slc.linkedit_segment
        self.assertIsNotNone(linkedit)
        self.assertEqual(linkedit.fileoff, fixtures.LINKEDIT_OFFSET)

        section = text.section("__text")
        self.assertIsNotNone(section)
        self.assertEqual(section.offset, fixtures.TEXT_OFFSET)

    def test_free_space_after_load_commands(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        expected = fixtures.TEXT_OFFSET - (fixtures.HEADER_SIZE + fixtures.SIZEOFCMDS)
        self.assertEqual(slc.load_commands_free_space, expected)

    def test_unsigned_slice_has_no_signature(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        self.assertIsNone(slc.code_signature)
        # With no LC_CODE_SIGNATURE, the region starts at the file end rounded
        # up to 16, which for this fixture is already aligned.
        self.assertEqual(slc.code_length, fixtures.FILE_SIZE)

    def test_round_trip_view_is_lossless(self) -> None:
        data = fixtures.minimal_macho()
        parsed = macho.MachOFile.parse(data)
        self.assertEqual(bytes(parsed.slices[0].view), data)


class ParseErrorTests(unittest.TestCase):
    """`struct.error` and friends must not escape as raw exceptions."""

    def test_too_short(self) -> None:
        with self.assertRaises(MachOError):
            macho.MachOFile.parse(b"\xcf\xfa\xed\xfe")

    def test_bad_magic(self) -> None:
        with self.assertRaises(MachOError):
            macho.MachOFile.parse(b"not a macho at all")

    def test_truncated_header_becomes_macho_error(self) -> None:
        with self.assertRaises(MachOError):
            macho.MachOFile.parse(b"\xcf\xfa\xed\xfe" + b"\x00" * 4)

    def test_fat_claiming_too_many_archs(self) -> None:
        with self.assertRaises(MachOError):
            macho.MachOFile.parse(b"\xca\xfe\xba\xbe" + b"\xff" * 4)

    def test_fat_arch_past_end_of_file(self) -> None:
        header = b"\xca\xfe\xba\xbe" + (1).to_bytes(4, "big")
        entry = (0x0100000C).to_bytes(4, "big") + b"\0" * 4
        entry += (999999).to_bytes(4, "big") + (4096).to_bytes(4, "big") + (14).to_bytes(4, "big")
        with self.assertRaises(MachOError):
            macho.MachOFile.parse(header + entry)


class ParseFatTests(unittest.TestCase):
    def test_two_slices(self) -> None:
        parsed = macho.MachOFile.parse(fixtures.minimal_fat(fixtures.minimal_macho(), fixtures.minimal_macho()))
        self.assertTrue(parsed.is_fat)
        self.assertTrue(parsed.fat_big_endian)
        self.assertEqual(len(parsed.slices), 2)
        self.assertEqual(len(parsed.archs), 2)
        self.assertEqual(parsed.archs[0].align, 14)

    def test_slices_are_laid_at_alignment(self) -> None:
        parsed = macho.MachOFile.parse(fixtures.minimal_fat(fixtures.minimal_macho(), fixtures.minimal_macho()))
        for arch in parsed.archs:
            self.assertEqual(arch.offset % 16384, 0)

    def test_little_endian_fat_header(self) -> None:
        parsed = macho.MachOFile.parse(
            fixtures.minimal_fat(fixtures.minimal_macho(), big_endian=False)
        )
        self.assertTrue(parsed.is_fat)
        self.assertFalse(parsed.fat_big_endian)
        self.assertEqual(parsed.archs[0].cpu_type, 0x0100000C)


class GrowSliceTests(unittest.TestCase):
    def test_adds_code_signature_command(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        code_length = slc.code_length
        new_length = code_length + macho.signature_region_size(code_length)

        grown = macho.grow_slice(slc, new_length)
        self.assertEqual(len(grown), new_length)

        reparsed = macho.MachOFile.parse(grown).slices[0]
        self.assertIsNotNone(reparsed.code_signature, "LC_CODE_SIGNATURE must be appended")
        self.assertEqual(reparsed.ncmds, slc.ncmds + 1)
        self.assertEqual(reparsed.sizeofcmds, slc.sizeofcmds + 16)
        self.assertEqual(reparsed.code_signature.data[0], code_length)
        self.assertEqual(reparsed.code_signature.data[1], new_length - code_length)

    def test_linkedit_is_extended(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        old_linkedit = slc.linkedit_segment
        code_length = slc.code_length
        new_length = code_length + macho.signature_region_size(code_length)

        reparsed = macho.MachOFile.parse(macho.grow_slice(slc, new_length)).slices[0]
        new_linkedit = reparsed.linkedit_segment
        self.assertEqual(new_linkedit.filesize, new_length - old_linkedit.fileoff)
        self.assertGreater(new_linkedit.vmsize, old_linkedit.vmsize)
        self.assertEqual(new_linkedit.vmsize % 4096, 0)

    def test_shrinking_is_refused(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        with self.assertRaises(MachOError):
            macho.grow_slice(slc, slc.size - 1)

    def test_original_buffer_is_untouched(self) -> None:
        data = fixtures.minimal_macho()
        before = bytes(data)
        slc = macho.MachOFile.parse(data).slices[0]
        macho.grow_slice(slc, slc.size + 4096)
        self.assertEqual(bytes(data), before, "grow_slice must not mutate its input")


class PlaceSignatureTests(unittest.TestCase):
    def test_writes_at_the_region_start(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        code_length = slc.code_length
        new_length = code_length + macho.signature_region_size(code_length)
        grown = macho.grow_slice(slc, new_length)
        grown_slice = macho.MachOFile.parse(grown).slices[0]

        signature = b"\xde\xad\xbe\xef" * 4
        placed = macho.place_signature(grown_slice, grown, code_length, signature)
        self.assertEqual(len(placed), new_length)
        self.assertEqual(placed[code_length : code_length + len(signature)], signature)

    def test_too_large_signature_raises(self) -> None:
        slc = macho.MachOFile.parse(fixtures.minimal_macho()).slices[0]
        code_length = slc.code_length
        data = macho.grow_slice(slc, code_length + 64)
        grown_slice = macho.MachOFile.parse(data).slices[0]
        with self.assertRaises(MachOError):
            macho.place_signature(grown_slice, data, code_length, b"\0" * 4096)


class BuildFatTests(unittest.TestCase):
    def test_layout_and_arch_rewrite(self) -> None:
        slice_a = fixtures.minimal_macho()
        slice_b = fixtures.minimal_macho() + b"\0" * 32
        source = macho.MachOFile.parse(fixtures.minimal_fat(slice_a, slice_b))

        rebuilt = macho.build_fat([slice_a, slice_b], source.archs, True)
        reparsed = macho.MachOFile.parse(rebuilt)
        self.assertEqual(len(reparsed.slices), 2)
        for arch in reparsed.archs:
            self.assertEqual(arch.offset % 16384, 0)
            self.assertEqual(arch.align, 14)
        self.assertEqual(bytes(reparsed.slices[0].view), slice_a)
        self.assertEqual(bytes(reparsed.slices[1].view), slice_b)

    def test_count_mismatch_raises(self) -> None:
        source = macho.MachOFile.parse(fixtures.minimal_fat(fixtures.minimal_macho()))
        with self.assertRaises(MachOError):
            macho.build_fat([fixtures.minimal_macho(), fixtures.minimal_macho()], source.archs, True)


if __name__ == "__main__":
    unittest.main()
