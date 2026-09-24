"""Tests for bundle traversal, sealing and metadata helpers."""

from __future__ import annotations

import plistlib
import shutil
import unittest

from ipasign import bundle
from ipasign.errors import BundleError

from . import fixtures


class DisplayNameTests(unittest.TestCase):
    def test_prefers_display_name(self) -> None:
        self.assertEqual(bundle.display_name({"CFBundleDisplayName": "Nexa"}), "Nexa")

    def test_falls_back_to_name_then_executable(self) -> None:
        self.assertEqual(bundle.display_name({"CFBundleName": "Nexa"}), "Nexa")
        self.assertEqual(bundle.display_name({"CFBundleExecutable": "Runner"}), "Runner")

    def test_display_name_wins_when_several_present(self) -> None:
        info = {"CFBundleDisplayName": "Nexa", "CFBundleName": "Other", "CFBundleExecutable": "Runner"}
        self.assertEqual(bundle.display_name(info), "Nexa")

    def test_empty_value_does_not_stop_the_search(self) -> None:
        self.assertEqual(bundle.display_name({"CFBundleDisplayName": "", "CFBundleName": "Nexa"}), "Nexa")

    def test_missing_everything(self) -> None:
        self.assertEqual(bundle.display_name({}), "")


class AppVersionTests(unittest.TestCase):
    def test_release_version_wins_over_build_number(self) -> None:
        info = {"CFBundleShortVersionString": "1.0.2", "CFBundleVersion": "2"}
        self.assertEqual(bundle.app_version(info), "1.0.2")

    def test_falls_back_to_build_number(self) -> None:
        self.assertEqual(bundle.app_version({"CFBundleVersion": "2"}), "2")

    def test_missing(self) -> None:
        self.assertEqual(bundle.app_version({}), "")

    def test_non_string_value_is_converted(self) -> None:
        self.assertEqual(bundle.app_version({"CFBundleVersion": 42}), "42")


class ParseInfoPlistTests(unittest.TestCase):
    def test_parses(self) -> None:
        self.assertEqual(bundle.parse_info_plist(fixtures.info_plist())["CFBundleName"], "Test")

    def test_not_a_plist_raises(self) -> None:
        with self.assertRaises(BundleError):
            bundle.parse_info_plist(b"not a plist")

    def test_not_a_dictionary_raises(self) -> None:
        with self.assertRaises(BundleError):
            bundle.parse_info_plist(plistlib.dumps([1, 2, 3], fmt=plistlib.FMT_XML))


class IsMachoFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("bundle_macho")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_detects_thin_and_fat(self) -> None:
        (self.root / "thin").write_bytes(fixtures.minimal_macho())
        (self.root / "fat").write_bytes(fixtures.minimal_fat(fixtures.minimal_macho()))
        self.assertTrue(bundle.is_macho_file(self.root / "thin"))
        self.assertTrue(bundle.is_macho_file(self.root / "fat"))

    def test_rejects_other_files(self) -> None:
        (self.root / "text").write_text("hello")
        self.assertFalse(bundle.is_macho_file(self.root / "text"))

    def test_missing_file_is_not_an_error(self) -> None:
        self.assertFalse(bundle.is_macho_file(self.root / "nope"))


class BundleDetailsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.fake_bundle(fixtures.scratch_dir("bundle_details") / "Test.app")

    def tearDown(self) -> None:
        shutil.rmtree(fixtures.SCRATCH / "bundle_details", ignore_errors=True)

    def test_reads_id_executable_and_plist_bytes(self) -> None:
        bundle_id, executable, info = bundle.bundle_details(self.root)
        self.assertEqual(bundle_id, "com.example.test")
        self.assertEqual(executable, "Test")
        self.assertEqual(bundle.parse_info_plist(info)["CFBundleName"], "Test")

    def test_missing_info_plist_raises(self) -> None:
        (self.root / "Info.plist").unlink()
        with self.assertRaises(BundleError):
            bundle.bundle_details(self.root)

    def test_missing_keys_raise(self) -> None:
        (self.root / "Info.plist").write_bytes(fixtures.info_plist(CFBundleIdentifier=""))
        with self.assertRaises(BundleError):
            bundle.bundle_details(self.root)


class CodeResourcesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.fake_bundle(fixtures.scratch_dir("code_resources") / "Test.app")

    def tearDown(self) -> None:
        shutil.rmtree(fixtures.SCRATCH / "code_resources", ignore_errors=True)

    def test_shape(self) -> None:
        raw = bundle.generate_code_resources(self.root, "Test")
        parsed = plistlib.loads(raw)
        self.assertEqual(set(parsed), {"files", "files2", "rules", "rules2"})

    def test_executable_and_signature_are_excluded(self) -> None:
        raw = bundle.generate_code_resources(self.root, "Test")
        parsed = plistlib.loads(raw)
        self.assertNotIn("Test", parsed["files"])
        self.assertNotIn(bundle.CODE_RESOURCES, parsed["files"])

    def test_resource_is_sealed_with_both_hashes(self) -> None:
        raw = bundle.generate_code_resources(self.root, "Test")
        parsed = plistlib.loads(raw)
        self.assertIn("Resource.txt", parsed["files"])
        self.assertIsInstance(parsed["files"]["Resource.txt"], bytes, "files holds raw data")
        self.assertIn("hash", parsed["files2"]["Resource.txt"])
        self.assertIn("hash2", parsed["files2"]["Resource.txt"])

    def test_info_plist_and_pkginfo_are_omitted_from_files2(self) -> None:
        (self.root / "PkgInfo").write_bytes(b"APPL????")
        parsed = plistlib.loads(bundle.generate_code_resources(self.root, "Test"))
        self.assertIn("Info.plist", parsed["files"], "still present in files")
        self.assertNotIn("Info.plist", parsed["files2"], "omitted from files2")
        self.assertNotIn("PkgInfo", parsed["files2"])

    def test_lproj_entries_are_marked_optional(self) -> None:
        lproj = self.root / "Base.lproj"
        lproj.mkdir()
        (lproj / "Main.strings").write_text("x")
        parsed = plistlib.loads(bundle.generate_code_resources(self.root, "Test"))
        entry = parsed["files"]["Base.lproj/Main.strings"]
        self.assertIsInstance(entry, dict)
        self.assertTrue(entry["optional"])
        self.assertTrue(parsed["files2"]["Base.lproj/Main.strings"]["optional"])

    def test_locversion_is_omitted_from_files(self) -> None:
        lproj = self.root / "Base.lproj"
        lproj.mkdir()
        (lproj / "locversion.plist").write_text("x")
        parsed = plistlib.loads(bundle.generate_code_resources(self.root, "Test"))
        self.assertNotIn("Base.lproj/locversion.plist", parsed["files"])
        self.assertNotIn("Base.lproj/locversion.plist", parsed["files2"])

    def test_rules_are_present(self) -> None:
        parsed = plistlib.loads(bundle.generate_code_resources(self.root, "Test"))
        self.assertIs(parsed["rules"]["^.*"], True)
        self.assertTrue(parsed["rules2"]["^Info\\.plist$"]["omit"])

    def test_integral_weights_have_no_decimal_part(self) -> None:
        raw = bundle.generate_code_resources(self.root, "Test")
        self.assertIn(b"<real>1000</real>", raw)
        self.assertNotIn(b"<real>1000.0</real>", raw)


class CollectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("collect")
        self.app = fixtures.fake_bundle(self.root / "Test.app")
        nested = fixtures.fake_bundle(self.root / "Test.app" / "Frameworks" / "Inner.framework")
        (nested / "Test").write_bytes(fixtures.minimal_macho())

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_collect_macho_files_finds_nested(self) -> None:
        found = bundle.collect_macho_files(self.app)
        names = {p.name for p in found}
        self.assertIn("Test", names)
        self.assertEqual(len(found), 2, "the nested framework executable too")

    def test_collect_macho_skips_dsym(self) -> None:
        dsym = self.app / "Test.app.dSYM"
        dsym.mkdir()
        (dsym / "Test").write_bytes(fixtures.minimal_macho())
        found = bundle.collect_macho_files(self.app)
        self.assertFalse(any("dSYM" in str(p) for p in found))

    def test_nested_bundles_are_deepest_first(self) -> None:
        found = bundle.collect_nested_bundles(self.app)
        self.assertEqual(found[0].name, "Inner.framework")
        self.assertNotIn(self.app.resolve(), [p.resolve() for p in found])


if __name__ == "__main__":
    unittest.main()
