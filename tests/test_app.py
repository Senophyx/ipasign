"""Tests for the App facade."""

from __future__ import annotations

import shutil
import unittest

from ipasign import archive, macho
from ipasign.app import App
from ipasign.errors import InvalidInputError
from ipasign.key import Key, SignResult

from . import fixtures

class AppValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("app_validation")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_missing_input_raises(self) -> None:
        with self.assertRaises(InvalidInputError):
            App(self.root / "nope.ipa")

    def test_a_directory_is_refused(self) -> None:
        app = fixtures.fake_bundle(self.root / "Test.app")
        with self.assertRaises(InvalidInputError):
            App(app)

    def test_a_non_ipa_file_is_refused(self) -> None:
        path = self.root / "notes.txt"
        path.write_text("hello")
        with self.assertRaises(InvalidInputError):
            App(path)

    def test_the_input_is_not_touched_on_construction(self) -> None:
        """Building an App must not unpack anything."""
        ipa = fixtures.fake_ipa(self.root / "Test.ipa")
        before = ipa.read_bytes()
        App(ipa)
        self.assertEqual(ipa.read_bytes(), before)
        self.assertFalse((self.root / ".ipasign_tmp").exists())

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

    def test_a_missing_input_is_refused_at_sign_time_too(self) -> None:
        app = App(self.ipa)
        self.ipa.unlink()
        with self.assertRaises(InvalidInputError):
            app.sign(Key(adhoc=True))

if __name__ == "__main__":
    unittest.main()
