"""Tests for the App facade."""

from __future__ import annotations

import shutil
import unittest

from ipasign import archive, macho
from ipasign.app import App
from ipasign.errors import ArchiveError, InvalidInputError
from ipasign.key import Key
from ipasign.result import SignResult

from . import fixtures

class AppValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("app_validation")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_missing_input_raises(self) -> None:
        with self.assertRaises(InvalidInputError):
            App(self.root / "nope.ipa")

    def test_a_file_it_cannot_sign_is_refused(self) -> None:
        path = self.root / "notes.txt"
        path.write_text("hello")
        with self.assertRaises(InvalidInputError):
            App(path)

    def test_a_bundle_folder_is_accepted(self) -> None:
        app = fixtures.fake_bundle(self.root / "Test.app")
        self.assertEqual(App(app).path, app)

    def test_a_bare_macho_is_accepted(self) -> None:
        path = self.root / "Runner"
        path.write_bytes(fixtures.minimal_macho())
        self.assertEqual(App(path).path, path)

    def test_the_input_is_not_touched_on_construction(self) -> None:
        """Building an App must not unpack anything."""
        ipa = fixtures.fake_ipa(self.root / "Test.ipa")
        before = ipa.read_bytes()
        App(ipa)
        self.assertEqual(ipa.read_bytes(), before)
        self.assertFalse((self.root / ".ipasign_tmp").exists())

    def test_only_an_archive_is_flagged_as_one(self) -> None:
        ipa = fixtures.fake_ipa(self.root / "Test.ipa")
        app = fixtures.fake_bundle(self.root / "Test.app")
        macho_path = self.root / "Runner"
        macho_path.write_bytes(fixtures.minimal_macho())

        self.assertTrue(App(ipa).is_archive)
        self.assertFalse(App(app).is_archive)
        self.assertFalse(App(macho_path).is_archive)

class DefaultOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("app_default_output")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _default(self, name: str) -> str:
        path = self.root / name
        path.write_bytes(b"x")
        return App(path).default_output.name

    def test_appends_signed_before_the_extension(self) -> None:
        self.assertEqual(self._default("test.ipa"), "test-signed.ipa")

    def test_output_sits_beside_the_input(self) -> None:
        path = self.root / "test.ipa"
        path.write_bytes(b"x")
        self.assertEqual(App(path).default_output.parent, self.root)

    def test_an_already_signed_name_gains_another_suffix(self) -> None:
        """No guessing: a confusing name simply gets longer."""
        self.assertEqual(self._default("test-signed.ipa"), "test-signed-signed.ipa")

    def test_extension_case_is_preserved(self) -> None:
        self.assertEqual(self._default("Test.IPA"), "Test-signed.IPA")

class AppSignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("app_sign")
        self.ipa = fixtures.fake_ipa(self.root / "test.ipa")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_signs_to_the_default_output(self) -> None:
        result = App(self.ipa).sign(Key(adhoc=True))
        self.assertIsInstance(result, SignResult)
        self.assertEqual(result.output_path, str(self.root / "test-signed.ipa"))
        self.assertTrue((self.root / "test-signed.ipa").is_file())

    def test_signs_to_an_explicit_output(self) -> None:
        target = self.root / "build" / "out.ipa"
        result = App(self.ipa).sign(Key(adhoc=True), output=target)
        self.assertEqual(result.output_path, str(target))
        self.assertTrue(target.is_file())
        self.assertFalse((self.root / "test-signed.ipa").exists())

    def test_result_describes_the_bundle(self) -> None:
        result = App(self.ipa).sign(Key(adhoc=True))
        self.assertEqual(result.bundle_id, "com.example.test")
        self.assertGreaterEqual(result.signed_count, 1)
        self.assertEqual(result.app_name, "Test")
        self.assertEqual(result.app_version, "1.0")

    def test_the_signed_output_really_carries_a_signature(self) -> None:
        result = App(self.ipa).sign(Key(adhoc=True))
        unpacked = archive.unpack(result.output_path, self.root / "work")
        signed = (unpacked.app / "Test").read_bytes()
        self.assertIsNotNone(macho.MachOFile.parse(signed).slices[0].code_signature)

    def test_the_input_is_left_untouched(self) -> None:
        before = self.ipa.read_bytes()
        App(self.ipa).sign(Key(adhoc=True))
        self.assertEqual(self.ipa.read_bytes(), before)

    def test_scratch_is_removed_after_signing(self) -> None:
        App(self.ipa).sign(Key(adhoc=True))
        self.assertFalse((self.root / ".ipasign_tmp").exists())

    def test_an_existing_output_is_overwritten(self) -> None:
        target = self.root / "test-signed.ipa"
        target.write_bytes(b"stale")
        App(self.ipa).sign(Key(adhoc=True))
        self.assertNotEqual(target.read_bytes(), b"stale")

    def test_output_may_be_the_input_itself(self) -> None:
        """The archive is fully unpacked before anything is written back."""
        result = App(self.ipa).sign(Key(adhoc=True), output=self.ipa)
        self.assertEqual(result.output_path, str(self.ipa))
        unpacked = archive.unpack(self.ipa, self.root / "work")
        signed = (unpacked.app / "Test").read_bytes()
        self.assertIsNotNone(macho.MachOFile.parse(signed).slices[0].code_signature)

    def test_signing_the_output_again_keeps_a_valid_archive(self) -> None:
        first = App(self.ipa).sign(Key(adhoc=True))
        second = App(first.output_path).sign(Key(adhoc=True))
        self.assertEqual(second.output_path, str(self.root / "test-signed-signed.ipa"))
        self.assertTrue((self.root / "test-signed-signed.ipa").is_file())

    def test_signing_twice_from_one_app_reuses_the_input(self) -> None:
        app = App(self.ipa)
        first = app.sign(Key(adhoc=True), output=self.root / "one.ipa")
        second = app.sign(Key(adhoc=True), output=self.root / "two.ipa")
        self.assertEqual(first.bundle_id, second.bundle_id)
        self.assertTrue((self.root / "one.ipa").is_file())
        self.assertTrue((self.root / "two.ipa").is_file())

    def test_a_missing_input_is_caught_by_construction(self) -> None:
        """Validation happens up front, so sign() never sees a bad path."""
        app = App(self.ipa)
        self.ipa.unlink()
        with self.assertRaises(ArchiveError):
            app.sign(Key(adhoc=True))

class AppFolderTests(unittest.TestCase):
    """A bundle folder is signed where it is."""

    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("app_folder")
        self.bundle = fixtures.fake_bundle(self.root / "Test.app")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_signs_in_place_and_reports_the_folder(self) -> None:
        result = App(self.bundle).sign(Key(adhoc=True))
        self.assertIsInstance(result, SignResult)
        self.assertEqual(result.output_path, str(self.bundle))
        self.assertEqual(result.bundle_id, "com.example.test")
        self.assertGreaterEqual(result.signed_count, 1)

    def test_the_executable_really_carries_a_signature(self) -> None:
        App(self.bundle).sign(Key(adhoc=True))
        signed = (self.bundle / "Test").read_bytes()
        self.assertIsNotNone(macho.MachOFile.parse(signed).slices[0].code_signature)

    def test_code_resources_are_written(self) -> None:
        App(self.bundle).sign(Key(adhoc=True))
        self.assertTrue((self.bundle / "_CodeSignature" / "CodeResources").is_file())

    def test_an_output_path_is_refused(self) -> None:
        """In-place is the only sensible target, so fail loudly."""
        with self.assertRaises(InvalidInputError):
            App(self.bundle).sign(Key(adhoc=True), output=self.root / "out.app")

    def test_the_default_output_still_names_the_folder(self) -> None:
        """Only an archive gets a derived name; the property stays harmless."""
        self.assertEqual(App(self.bundle).default_output.name, "Test-signed.app")

    def test_reports_the_display_name_and_version(self) -> None:
        app = fixtures.fake_bundle(
            self.root / "Named.app",
            CFBundleDisplayName="TestApp",
            CFBundleShortVersionString="2.3.4",
        )
        result = App(app).sign(Key(adhoc=True))
        self.assertEqual(result.app_name, "TestApp")
        self.assertEqual(result.app_version, "2.3.4")

class AppMachoTests(unittest.TestCase):
    """A bare Mach-O is signed where it is."""

    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("app_macho")
        self.runner = self.root / "Runner"
        self.runner.write_bytes(fixtures.minimal_macho())

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_signs_in_place(self) -> None:
        result = App(self.runner).sign(Key(adhoc=True))
        self.assertIsInstance(result, SignResult)
        self.assertEqual(result.output_path, str(self.runner))
        self.assertEqual(result.signed_count, 1)
        signed = macho.MachOFile.parse(self.runner.read_bytes())
        self.assertIsNotNone(signed.slices[0].code_signature)

    def test_bundle_id_falls_back_to_the_file_name(self) -> None:
        result = App(self.runner).sign(Key(adhoc=True))
        self.assertEqual(result.bundle_id, "Runner")

    def test_bundle_id_can_be_named(self) -> None:
        result = App(self.runner).sign(Key(adhoc=True), bundle_id="com.example.custom")
        self.assertEqual(result.bundle_id, "com.example.custom")

    def test_an_output_path_is_refused(self) -> None:
        with self.assertRaises(InvalidInputError):
            App(self.runner).sign(Key(adhoc=True), output=self.root / "out.bin")

    def test_a_dylib_gets_no_der_entitlements(self) -> None:
        """A non-executable file must not be sealed as an app executable."""
        dylib = self.root / "libX.dylib"
        dylib.write_bytes(fixtures.minimal_macho(file_type=0x6))  # MH_DYLIB
        result = App(dylib).sign(Key(adhoc=True))
        self.assertEqual(result.bundle_id, "libX.dylib")
        self.assertEqual(result.signed_count, 1)

    def test_name_and_version_come_from_the_embedded_plist(self) -> None:
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
        result = App(embedded).sign(Key(adhoc=True))
        self.assertEqual(result.bundle_id, "com.example.embedded")
        self.assertEqual(result.app_name, "TestApp")
        self.assertEqual(result.app_version, "2.3.4")

class AppCheckTests(unittest.TestCase):
    """App.check reads the certificate without signing."""

    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("app_check")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_unsigned_macho_reports_not_signed(self) -> None:
        runner = self.root / "Runner"
        runner.write_bytes(fixtures.minimal_macho())
        result = App(runner).check(ocsp=False)
        self.assertFalse(result.signed)
        self.assertEqual(result.code, -2)

    def test_unsigned_ipa_reports_not_signed(self) -> None:
        ipa = fixtures.fake_ipa(self.root / "Test.ipa")
        result = App(ipa).check(ocsp=False)
        self.assertEqual(result.type, "IPA")
        self.assertFalse(result.signed)

    def test_bundle_folder_resolves_to_its_executable(self) -> None:
        app = fixtures.fake_bundle(self.root / "Test.app")
        result = App(app).check(ocsp=False)
        self.assertEqual(result.path, str(app / "Test"))
        self.assertEqual(result.type, "Mach-O")
        self.assertFalse(result.signed)

    def test_bundle_without_an_executable_raises(self) -> None:
        app = self.root / "Empty.app"
        app.mkdir()
        (app / "Info.plist").write_bytes(fixtures.info_plist())
        with self.assertRaises(InvalidInputError):
            App(app).check(ocsp=False)

if __name__ == "__main__":
    unittest.main()
