"""Tests for IPA unpack and repack."""

from __future__ import annotations

import shutil
import sys
import unittest
import zipfile

from ipasign import archive
from ipasign.errors import ArchiveError

from . import fixtures


class SafeMemberTests(unittest.TestCase):
    """Archive members are attacker controlled, so traversal must be refused."""

    def test_accepts_normal_paths(self) -> None:
        for name in ("Payload/App.app/Info.plist", "a/b/c", "file.txt"):
            self.assertTrue(archive._safe_member(name), name)

    def test_rejects_absolute(self) -> None:
        for name in ("/etc/passwd", "\\windows\\system32"):
            self.assertFalse(archive._safe_member(name), name)

    def test_rejects_parent_traversal(self) -> None:
        for name in ("../evil", "a/../../evil", "..", "a/.."):
            self.assertFalse(archive._safe_member(name), name)

    def test_rejects_windows_drive(self) -> None:
        self.assertFalse(archive._safe_member("C:/evil"))

    def test_rejects_empty(self) -> None:
        self.assertFalse(archive._safe_member(""))


class ScratchRootTests(unittest.TestCase):
    def test_file_anchor_uses_parent(self) -> None:
        root = archive.scratch_root(fixtures.SCRATCH / "x" / "app.ipa")
        self.assertEqual(root.name, archive.SCRATCH_DIR)
        self.assertEqual(root.parent, fixtures.SCRATCH / "x")

    def test_directory_anchor_uses_itself(self) -> None:
        root = archive.scratch_root(fixtures.SCRATCH)
        self.assertEqual(root, fixtures.SCRATCH / archive.SCRATCH_DIR)


class UnpackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("archive_unpack")
        self.ipa = fixtures.fake_ipa(self.root / "in.ipa")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_unpacks_and_finds_app(self) -> None:
        unpacked = archive.unpack(self.ipa, self.root / "work")
        self.assertTrue((unpacked.app / "Info.plist").is_file())
        self.assertTrue((unpacked.app / "Test").is_file())
        self.assertEqual(unpacked.app.name, "Test.app")

    @unittest.skipIf(sys.platform == "win32", "Windows chmod ignores permission bits")
    def test_extracted_executable_stays_executable(self) -> None:
        """The execute bit must survive the round trip on POSIX filesystems.

        Windows has no such bit: ``os.chmod`` there only toggles the read-only
        flag, so the assertion would be meaningless rather than wrong.
        """
        unpacked = archive.unpack(self.ipa, self.root / "work")
        mode = (unpacked.app / "Test").stat().st_mode
        self.assertTrue(mode & 0o111, "the executable bit must survive the round trip")

    def test_reuses_clean_directory(self) -> None:
        target = self.root / "work"
        target.mkdir()
        (target / "stale.txt").write_text("left over")
        archive.unpack(self.ipa, target)
        self.assertFalse((target / "stale.txt").exists(), "the directory is wiped first")

    def test_missing_archive_raises(self) -> None:
        with self.assertRaises(ArchiveError):
            archive.unpack(self.root / "nope.ipa", self.root / "work")

    def test_not_a_zip_raises(self) -> None:
        bad = self.root / "bad.ipa"
        bad.write_text("not a zip")
        with self.assertRaises(ArchiveError):
            archive.unpack(bad, self.root / "work")

    def test_no_payload_raises(self) -> None:
        bad = self.root / "empty.ipa"
        with zipfile.ZipFile(bad, "w") as zf:
            zf.writestr("Readme.txt", "hello")
        with self.assertRaises(ArchiveError):
            archive.unpack(bad, self.root / "work")

    def test_traversal_member_is_refused(self) -> None:
        evil = self.root / "evil.ipa"
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", fixtures.info_plist())
            zf.writestr("../../escaped.txt", "boom")
        with self.assertRaises(ArchiveError):
            archive.unpack(evil, self.root / "work")
        self.assertFalse((self.root / "escaped.txt").exists())


class FindAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("archive_findapp")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_finds_single_app(self) -> None:
        app = self.root / "Payload" / "Mine.app"
        app.mkdir(parents=True)
        self.assertEqual(archive.find_app(self.root), app)

    def test_no_payload_raises(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self.assertRaises(ArchiveError):
            archive.find_app(self.root)

    def test_empty_payload_raises(self) -> None:
        (self.root / "Payload").mkdir(parents=True)
        with self.assertRaises(ArchiveError):
            archive.find_app(self.root)

    def test_two_apps_raise(self) -> None:
        payload = self.root / "Payload"
        (payload / "One.app").mkdir(parents=True)
        (payload / "Two.app").mkdir()
        with self.assertRaises(ArchiveError):
            archive.find_app(self.root)


class PackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("archive_pack")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_round_trip_preserves_tree_and_bytes(self) -> None:
        source = self.root / "src" / "Payload"
        fixtures.fake_bundle(source / "Test.app")
        fixture_files = sorted(
            p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()
        )

        output = self.root / "out.ipa"
        archive.pack(source, output)

        with zipfile.ZipFile(output) as zf:
            names = sorted(n for n in zf.namelist() if not n.endswith("/"))
            self.assertEqual(names, fixture_files)
            for name in fixture_files:
                self.assertEqual(zf.read(name), (source / name).read_bytes())

    def test_pack_leaves_no_temp_file_behind(self) -> None:
        source = self.root / "src" / "Payload"
        fixtures.fake_bundle(source / "Test.app")
        output = self.root / "out.ipa"
        archive.pack(source, output)
        self.assertTrue(output.is_file())
        self.assertFalse(output.with_name(output.name + ".is_tmp").exists())

    def test_repack_of_unpacked_archive_keeps_a_valid_zip(self) -> None:
        ipa = fixtures.fake_ipa(self.root / "in.ipa")
        unpacked = archive.unpack(ipa, self.root / "work")
        output = self.root / "out.ipa"
        archive.pack(unpacked.root, output)

        again = archive.unpack(output, self.root / "work2")
        self.assertTrue((again.app / "Info.plist").is_file())

    def test_cleanup_removes_scratch_and_prunes_empty_parent(self) -> None:
        ipa = self.root / "in.ipa"
        ipa.write_bytes(b"x")
        root = archive.scratch_root(ipa) / "stem"
        root.mkdir(parents=True)
        self.assertTrue(root.exists())
        archive.cleanup(root)
        self.assertFalse(root.exists())
        self.assertFalse(archive.scratch_root(ipa).exists(), "the empty .ipasign_tmp is pruned")


class CleanupTests(unittest.TestCase):
    def test_cleanup_is_silent_on_missing_directory(self) -> None:
        archive.cleanup(fixtures.SCRATCH / "does-not-exist")


if __name__ == "__main__":
    unittest.main()
