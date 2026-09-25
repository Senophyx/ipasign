"""Tests for metadata extraction."""

from __future__ import annotations

import hashlib
import json
import plistlib
import shutil
import unittest
import zipfile
import zlib
from pathlib import Path

from ipasign import metadata
from ipasign.app import App
from ipasign.metadata import Metadata

from . import fixtures

def _png_parts(data: bytes) -> tuple[bytes, bytes]:
    """(IHDR bytes, concatenated IDAT payload) for a PNG."""
    ihdr = b""
    idat = b""
    pos = len(metadata.PNG_MAGIC)
    while pos + 12 <= len(data):
        length = int.from_bytes(data[pos : pos + 4], "big")
        kind = data[pos + 4 : pos + 8]
        payload = data[pos + 8 : pos + 8 + length]
        if kind == b"IHDR":
            ihdr = payload
        elif kind == b"IDAT":
            idat += payload
        elif kind == b"IEND":
            break
        pos += 12 + length
    return ihdr, idat

def _rows(data: bytes) -> list[bytes]:
    """The scanlines of an RGBA PNG whose filter bytes are already cleared."""
    ihdr, idat = _png_parts(data)
    width, height = int.from_bytes(ihdr[:4], "big"), int.from_bytes(ihdr[4:8], "big")
    stride = width * 4
    raw = zlib.decompress(idat)
    return [raw[row * (stride + 1) + 1 : (row + 1) * (stride + 1)] for row in range(height)]

def _info(**overrides) -> dict:
    """A parsed ``Info.plist``, the shape ``from_info`` takes."""
    return plistlib.loads(fixtures.info_plist(**overrides))

def _pack(app: Path, ipa: Path) -> Path:
    """Zip a bundle directory into a real ``.ipa``, the way an archive holds it."""
    with zipfile.ZipFile(ipa, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(app.rglob("*")):
            if path.is_file():
                name = f"Payload/{app.name}/{path.relative_to(app).as_posix()}"
                archive.writestr(name, path.read_bytes())
    return ipa

class IconNameTests(unittest.TestCase):
    def test_prefers_cfbundleicons(self) -> None:
        info = {
            "CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}},
            "CFBundleIconFiles": ["Other"],
        }
        self.assertEqual(metadata._icon_names(info), ["AppIcon60x60"])

    def test_falls_back_to_the_flat_array_then_the_single_key(self) -> None:
        self.assertEqual(metadata._icon_names({"CFBundleIconFiles": ["Flat"]}), ["Flat"])
        self.assertEqual(metadata._icon_names({"CFBundleIconFile": "Solo"}), ["Solo"])

    def test_empty_and_malformed_shapes_are_ignored(self) -> None:
        no_files = {"CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": []}}}
        self.assertEqual(metadata._icon_names({}), [])
        self.assertEqual(metadata._icon_names({"CFBundleIcons": "nope"}), [])
        self.assertEqual(metadata._icon_names(no_files), [])
        self.assertEqual(metadata._icon_names({"CFBundleIconFiles": ["", 7, "Ok"]}), ["Ok"])

class FromInfoTests(unittest.TestCase):
    """The plain builder, with no archive or app involved."""

    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("metadata_from_info")
        self.bundle = fixtures.fake_bundle(
            self.root / "TestApp.app",
            CFBundleDisplayName="TestApp",
            CFBundleShortVersionString="2.3.4",
            CFBundleIcons={"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}},
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_reads_the_declared_fields(self) -> None:
        info = _info(CFBundleDisplayName="TestApp", CFBundleShortVersionString="2.3.4")
        found = metadata.from_info(info, None, None, None)
        self.assertEqual(found.name, "TestApp")
        self.assertEqual(found.version, "2.3.4")
        self.assertEqual(found.bundle_identifier, "com.example.test")
        self.assertIsInstance(found.timestamp, int)

    def test_an_absent_archive_leaves_size_and_file_name_empty(self) -> None:
        found = metadata.from_info(_info(), None, None, None)
        self.assertEqual(found.size, 0)
        self.assertEqual(found.file_name, "")

    def test_an_absent_bundle_root_leaves_the_icon_empty(self) -> None:
        info = _info(CFBundleIcons={"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}})
        self.assertEqual(metadata.from_info(info, None, None, None).icon_name, "")

    def test_nothing_is_written_without_an_output_directory(self) -> None:
        out = self.root / "meta"
        metadata.from_info(_info(), self.bundle, None, None)
        self.assertFalse(out.exists())

    def test_the_sidecar_mirrors_the_returned_object(self) -> None:
        out = self.root / "meta"
        found = metadata.from_info(
            _info(CFBundleDisplayName="TestApp"), self.bundle, None, out
        )
        written = json.loads((out / metadata.METADATA_FILE).read_text())
        self.assertEqual(
            written,
            {
                "AppName": found.name,
                "AppVersion": found.version,
                "AppBundleIdentifier": found.bundle_identifier,
                "AppSize": found.size,
                "IconName": found.icon_name,
                "FileName": found.file_name,
                "Timestamp": found.timestamp,
            },
        )

class AppMetadataTests(unittest.TestCase):
    """``App.metadata()`` across the three kinds of input."""

    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("metadata_app")
        self.icon = fixtures.standard_png([b"\x0a\x0b\x0c\xff"])
        self.app = fixtures.fake_bundle(
            self.root / "TestApp.app",
            CFBundleDisplayName="TestApp",
            CFBundleShortVersionString="2.3.4",
            CFBundleIcons={"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}},
        )
        (self.app / "AppIcon60x60@2x.png").write_bytes(self.icon)
        self.ipa = _pack(self.app, self.root / "TestApp.ipa")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_reads_an_archive(self) -> None:
        found = App(self.ipa).metadata()
        self.assertIsInstance(found, Metadata)
        self.assertEqual(found.name, "TestApp")
        self.assertEqual(found.version, "2.3.4")
        self.assertEqual(found.bundle_identifier, "com.example.test")
        self.assertEqual(found.size, self.ipa.stat().st_size)
        self.assertEqual(found.file_name, "TestApp.ipa")

    def test_reads_a_bundle_folder(self) -> None:
        found = App(self.app).metadata()
        self.assertEqual(found.name, "TestApp")
        self.assertEqual(found.version, "2.3.4")
        self.assertEqual(found.bundle_identifier, "com.example.test")
        self.assertEqual(found.size, 0, "a folder has no archive size")
        self.assertEqual(found.file_name, "", "a folder has no archive name")

    def test_a_bare_macho_without_a_plist_reports_nothing(self) -> None:
        runner = self.root / "Runner"
        runner.write_bytes(fixtures.minimal_macho())
        found = App(runner).metadata()
        self.assertEqual(found.name, "")
        self.assertEqual(found.bundle_identifier, "")
        self.assertEqual(found.size, 0)

    def test_a_bare_macho_reads_its_embedded_plist(self) -> None:
        embedded = self.root / "Embedded"
        embedded.write_bytes(
            fixtures.macho_with_info_plist(
                {
                    "CFBundleIdentifier": "com.example.embedded",
                    "CFBundleDisplayName": "TestApp",
                    "CFBundleShortVersionString": "2.3.4",
                }
            )
        )
        found = App(embedded).metadata()
        self.assertEqual(found.name, "TestApp")
        self.assertEqual(found.version, "2.3.4")
        self.assertEqual(found.bundle_identifier, "com.example.embedded")

    def test_reading_an_archive_leaves_it_untouched(self) -> None:
        before = self.ipa.read_bytes()
        App(self.ipa).metadata()
        self.assertEqual(self.ipa.read_bytes(), before)

    def test_reading_an_archive_cleans_up_its_scratch(self) -> None:
        App(self.ipa).metadata()
        self.assertFalse((self.root / ".ipasign_tmp").exists())

    def test_save_to_writes_the_sidecar_and_the_icon(self) -> None:
        out = self.root / "meta"
        found = App(self.ipa).metadata(save_to=out)
        written = json.loads((out / metadata.METADATA_FILE).read_text())
        self.assertEqual(written["AppName"], "TestApp")
        self.assertEqual(written["AppSize"], found.size)
        self.assertEqual((out / found.icon_name).read_bytes(), self.icon)

    def test_save_to_creates_the_output_directory(self) -> None:
        out = self.root / "deeper" / "still"
        App(self.ipa).metadata(save_to=out)
        self.assertTrue((out / metadata.METADATA_FILE).is_file())

    def test_reading_a_signed_output_describes_that_archive(self) -> None:
        """The name and size follow the archive actually read."""
        target = self.root / "signed.ipa"
        App(self.ipa).sign(fixtures.adhoc_key(), output=target)
        found = App(target).metadata()
        self.assertEqual(found.file_name, "signed.ipa")
        self.assertEqual(found.size, target.stat().st_size)

class IconSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("metadata_icon")
        self.app = fixtures.fake_bundle(
            self.root / "TestApp.app",
            CFBundleIcons={"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}},
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_picks_the_largest_matching_icon(self) -> None:
        small = fixtures.standard_png([b"\x01\x02\x03\xff"])
        large = fixtures.standard_png([b"\x04\x05\x06\xff" * 2, b"\x07\x08\x09\xff" * 2])
        (self.app / "AppIcon60x60@2x.png").write_bytes(small)
        (self.app / "AppIcon60x60@3x.png").write_bytes(large)
        (self.app / "Unrelated.png").write_bytes(fixtures.standard_png([b"\x00" * 64]))

        out = self.root / "meta"
        found = App(_pack(self.app, self.root / "TestApp.ipa")).metadata(save_to=out)
        expected = hashlib.sha1(b"AppIcon60x60@3x.png").hexdigest() + ".png"
        self.assertEqual(found.icon_name, expected)
        self.assertEqual((out / expected).read_bytes(), large)

    def test_only_the_bundle_root_is_searched(self) -> None:
        nested = self.app / "Frameworks" / "Inner.framework"
        nested.mkdir(parents=True)
        (nested / "AppIcon60x60@2x.png").write_bytes(fixtures.standard_png([b"\x00" * 16]))
        found = App(_pack(self.app, self.root / "TestApp.ipa")).metadata()
        self.assertEqual(found.icon_name, "")

    def test_the_icon_name_does_not_depend_on_where_the_archive_is(self) -> None:
        (self.app / "AppIcon60x60@2x.png").write_bytes(fixtures.standard_png([b"\x11\x22\x33\xff"]))
        ipa = _pack(self.app, self.root / "TestApp.ipa")
        first = App(ipa).metadata()
        second = App(ipa).metadata(save_to=self.root / "meta2")
        self.assertEqual(first.icon_name, second.icon_name)

class CgbiDecodeTests(unittest.TestCase):
    """The icon variant Xcode ships is not a valid PNG until it is decoded."""

    def setUp(self) -> None:
        # Every channel is at most its alpha, so the crush and the decode are
        # exact and the comparison can be byte for byte.
        self.rows = [
            bytes((255, 0, 0, 255)) + bytes((0, 255, 0, 128)) + bytes((0, 0, 255, 0)),
            bytes((16, 32, 48, 64)) * 3,
        ]

    def test_decodes_a_crushed_png(self) -> None:
        decoded = metadata._decode_cgbi_png(fixtures.cgbi_png(self.rows))
        self.assertIsNotNone(decoded)
        self.assertEqual(_rows(decoded), self.rows)

    def test_decoded_output_is_a_standard_png(self) -> None:
        decoded = metadata._decode_cgbi_png(fixtures.cgbi_png(self.rows))
        self.assertNotIn(b"CgBI", decoded)
        self.assertTrue(decoded.startswith(metadata.PNG_MAGIC))
        ihdr, idat = _png_parts(decoded)
        self.assertEqual((ihdr[8], ihdr[9], ihdr[12]), (8, 6, 0))
        self.assertEqual(zlib.decompress(idat)[0], 0, "filter bytes are cleared")

    def test_swaps_bgra_back_to_rgba(self) -> None:
        """A red pixel must not come back blue, and a blue one must not come back red."""
        red, green, blue = (255, 0, 0, 255), (0, 255, 0, 255), (0, 0, 255, 255)
        rows = [bytes(red) + bytes(green) + bytes(blue)]
        decoded = metadata._decode_cgbi_png(fixtures.cgbi_png(rows))
        self.assertEqual(_rows(decoded), rows)

    def test_undoes_premultiplied_alpha(self) -> None:
        # Both rows premultiply and un-premultiply exactly, which is what lets
        # the comparison be byte for byte rather than approximate.
        rows = [bytes((210, 105, 55, 200)), bytes((0, 1, 3, 200)), bytes((0, 8, 16, 32))]
        decoded = metadata._decode_cgbi_png(fixtures.cgbi_png(rows))
        self.assertEqual(_rows(decoded), rows)

    def test_fully_transparent_pixels_are_kept_untouched(self) -> None:
        """Alpha 0 has no scale factor, so the channels survive as they are."""
        rows = [bytes((9, 8, 7, 0)) * 2]
        decoded = metadata._decode_cgbi_png(fixtures.cgbi_png(rows))
        self.assertEqual(_rows(decoded), rows)

    def test_reverses_every_row_filter(self) -> None:
        """Filters 1 to 4 reference earlier bytes, so a naive unfilter breaks them."""
        # Every channel is exact under premultiplication, and no two adjacent
        # bytes are equal, so a wrong Sub or Paeth cannot pass by accident.
        rows = [
            bytes((0, 37, 91, 255)) + bytes((11, 53, 67, 255)),
            bytes((118, 155, 209, 128)) + bytes((129, 171, 185, 128)),
            bytes((0, 37, 91, 0)) + bytes((11, 53, 67, 0)),
        ]
        for kind in (0, 1, 2, 3, 4):
            with self.subTest(filter=kind):
                decoded = metadata._decode_cgbi_png(fixtures.cgbi_png(rows, filter_kind=kind))
                self.assertIsNotNone(decoded)
                self.assertEqual(_rows(decoded), rows)

    def test_plain_png_is_left_alone(self) -> None:
        self.assertIsNone(metadata._decode_cgbi_png(fixtures.standard_png(self.rows)))

    def test_non_png_is_left_alone(self) -> None:
        self.assertIsNone(metadata._decode_cgbi_png(b"not a png at all"))

    def test_non_rgba_cgbi_is_left_alone(self) -> None:
        data = bytearray(fixtures.cgbi_png(self.rows))
        index = data.find(b"IHDR") + 8
        data[index + 1] = 2  # colour type RGB, which pngcrush never emits
        self.assertIsNone(metadata._decode_cgbi_png(bytes(data)))

    def test_truncated_cgbi_is_left_alone(self) -> None:
        data = fixtures.cgbi_png(self.rows)
        self.assertIsNone(metadata._decode_cgbi_png(data[: len(data) // 2]))

    def test_save_to_writes_the_decoded_icon(self) -> None:
        root = fixtures.scratch_dir("metadata_cgbi")
        try:
            app = fixtures.fake_bundle(
                root / "TestApp.app",
                CFBundleIcons={"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}},
            )
            (app / "AppIcon60x60@2x.png").write_bytes(fixtures.cgbi_png(self.rows))
            ipa = _pack(app, root / "TestApp.ipa")

            found = App(ipa).metadata(save_to=root / "meta")
            icon = (root / "meta" / found.icon_name).read_bytes()
            self.assertEqual(_rows(icon), self.rows)
        finally:
            shutil.rmtree(root, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
