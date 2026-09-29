"""Tests for the bundle modification pass."""

from __future__ import annotations

import plistlib
import shutil
import unittest
from pathlib import Path

from ipasign import edit
from ipasign.bundle import generate_code_resources, read_info_plist
from ipasign.edit import BundleEdits, apply_edits
from ipasign.errors import BundleError

from . import fixtures

def _info(app: Path) -> dict:
    return read_info_plist(app)

class BundleEditsTests(unittest.TestCase):
    def test_a_fresh_queue_is_empty(self) -> None:
        self.assertTrue(BundleEdits().empty)

    def test_any_recorded_edit_makes_it_non_empty(self) -> None:
        self.assertFalse(BundleEdits(bundle_id="com.example.prod").empty)
        self.assertFalse(BundleEdits(documents=True).empty)
        self.assertFalse(BundleEdits(icon=Path("icon.png")).empty)

    def test_an_empty_queue_writes_nothing(self) -> None:
        root = fixtures.scratch_dir("edit_empty")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        app = fixtures.fake_bundle(root / "Test.app")
        before = (app / "Info.plist").read_bytes()
        apply_edits(app, BundleEdits())
        self.assertEqual((app / "Info.plist").read_bytes(), before)

class IdentityEditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("edit_identity")
        self.app = fixtures.fake_bundle(self.root / "Test.app")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_bundle_id_is_written_to_the_root_plist(self) -> None:
        apply_edits(self.app, BundleEdits(bundle_id="com.example.prod"))
        self.assertEqual(_info(self.app)["CFBundleIdentifier"], "com.example.prod")

    def test_name_sets_both_keys(self) -> None:
        apply_edits(self.app, BundleEdits(name="ProdApp"))
        info = _info(self.app)
        self.assertEqual(info["CFBundleName"], "ProdApp")
        self.assertEqual(info["CFBundleDisplayName"], "ProdApp")

    def test_version_sets_both_keys(self) -> None:
        apply_edits(self.app, BundleEdits(version="2.3.4"))
        info = _info(self.app)
        self.assertEqual(info["CFBundleVersion"], "2.3.4")
        self.assertEqual(info["CFBundleShortVersionString"], "2.3.4")

    def test_existing_key_order_survives(self) -> None:
        before = list(_info(self.app))
        apply_edits(self.app, BundleEdits(version="2.3.4"))
        self.assertEqual(list(_info(self.app))[: len(before)], before)

    def test_a_no_op_edit_leaves_the_plist_bytes_alone(self) -> None:
        """Nothing changes, so the file, and any seal over it, stays valid."""
        before = (self.app / "Info.plist").read_bytes()
        apply_edits(self.app, BundleEdits(name=""))
        self.assertEqual((self.app / "Info.plist").read_bytes(), before)

    def test_repeating_an_edit_changes_nothing_the_second_time(self) -> None:
        """A settled plist is byte-identical, so a seal over it stays valid."""
        apply_edits(self.app, BundleEdits(bundle_id="com.example.prod", name="ProdApp"))
        settled = (self.app / "Info.plist").read_bytes()
        apply_edits(self.app, BundleEdits(bundle_id="com.example.prod", name="ProdApp"))
        self.assertEqual((self.app / "Info.plist").read_bytes(), settled)

    def test_a_version_edit_sets_both_keys(self) -> None:
        """Even when only one of the two already matches."""
        apply_edits(self.app, BundleEdits(version="1.0"))
        info = _info(self.app)
        self.assertEqual(info["CFBundleVersion"], "1.0")
        self.assertEqual(info["CFBundleShortVersionString"], "1.0")

    def test_localised_strings_are_rewritten(self) -> None:
        strings = self.app / "zh_CN.lproj"
        strings.mkdir()
        (strings / "InfoPlist.strings").write_bytes(
            plistlib.dumps({"CFBundleName": "Old", "CFBundleDisplayName": "Old"})
        )
        apply_edits(self.app, BundleEdits(name="ProdApp"))
        written = plistlib.loads((strings / "InfoPlist.strings").read_bytes())
        self.assertEqual(written["CFBundleName"], "ProdApp")
        self.assertEqual(written["CFBundleDisplayName"], "ProdApp")

    def test_an_unreadable_strings_file_is_skipped(self) -> None:
        strings = self.app / "zh-Hans.lproj"
        strings.mkdir()
        (strings / "InfoPlist.strings").write_bytes(b"not a plist")
        apply_edits(self.app, BundleEdits(name="ProdApp"))
        self.assertEqual((strings / "InfoPlist.strings").read_bytes(), b"not a plist")

    def test_a_plugin_gets_the_identifier_replaced(self) -> None:
        plugin = fixtures.fake_bundle(
            self.app / "PlugIns" / "Widget.appex",
            CFBundleIdentifier="com.example.test.widget",
            WKCompanionAppBundleIdentifier="com.example.test",
            NSExtension={"NSExtensionAttributes": {"WKAppBundleIdentifier": "com.example.test"}},
        )
        apply_edits(self.app, BundleEdits(bundle_id="com.example.prod"))

        info = _info(plugin)
        self.assertEqual(info["CFBundleIdentifier"], "com.example.prod.widget")
        self.assertEqual(info["WKCompanionAppBundleIdentifier"], "com.example.prod")
        self.assertEqual(
            info["NSExtension"]["NSExtensionAttributes"]["WKAppBundleIdentifier"],
            "com.example.prod",
        )

    def test_a_framework_is_not_rewritten(self) -> None:
        """Only .app and .appex carry an identifier of their own."""
        framework = fixtures.fake_bundle(
            self.app / "Frameworks" / "Inner.framework",
            CFBundleIdentifier="com.example.test.inner",
        )
        apply_edits(self.app, BundleEdits(bundle_id="com.example.prod"))
        self.assertEqual(_info(framework)["CFBundleIdentifier"], "com.example.test.inner")

    def test_a_plugin_without_a_plist_is_left_alone(self) -> None:
        broken = self.app / "PlugIns" / "Broken.appex"
        broken.mkdir(parents=True)
        apply_edits(self.app, BundleEdits(bundle_id="com.example.prod"))
        self.assertFalse((broken / "Info.plist").exists())

    def test_a_plugin_with_no_identifier_keeps_its_bytes(self) -> None:
        plugin = self.app / "PlugIns" / "Bare.appex"
        plugin.mkdir(parents=True)
        (plugin / "Info.plist").write_bytes(
            plistlib.dumps({"CFBundleExecutable": "Bare"}, sort_keys=False)
        )
        before = (plugin / "Info.plist").read_bytes()
        apply_edits(self.app, BundleEdits(bundle_id="com.example.prod"))
        self.assertEqual((plugin / "Info.plist").read_bytes(), before)

class ToggleEditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("edit_toggles")
        self.app = fixtures.fake_bundle(self.root / "Test.app")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_documents_enables_both_keys(self) -> None:
        apply_edits(self.app, BundleEdits(documents=True))
        info = _info(self.app)
        self.assertIs(info["UISupportsDocumentBrowser"], True)
        self.assertIs(info["UIFileSharingEnabled"], True)

    def test_minimum_os_is_written(self) -> None:
        apply_edits(self.app, BundleEdits(minimum_os="15.0"))
        self.assertEqual(_info(self.app)["MinimumOSVersion"], "15.0")

    def test_supported_devices_are_dropped(self) -> None:
        fixtures.fake_bundle(self.app, UISupportedDevices=["iPhone1,1"])
        apply_edits(self.app, BundleEdits(drop_supported_devices=True))
        self.assertNotIn("UISupportedDevices", _info(self.app))

    def test_dropping_an_absent_array_writes_nothing(self) -> None:
        before = (self.app / "Info.plist").read_bytes()
        apply_edits(self.app, BundleEdits(drop_supported_devices=True))
        self.assertEqual((self.app / "Info.plist").read_bytes(), before)

    def test_extensions_folder_is_deleted(self) -> None:
        (self.app / "Extensions").mkdir()
        (self.app / "Extensions" / "Widget.appex").mkdir()
        apply_edits(self.app, BundleEdits(drop_extensions=True))
        self.assertFalse((self.app / "PlugIns").exists())
        self.assertFalse((self.app / "Extensions").exists())

    def test_watch_folders_are_deleted(self) -> None:
        for name in ("Watch", "WatchKit", "com.apple.WatchPlaceholder"):
            (self.app / name).mkdir()
        apply_edits(self.app, BundleEdits(drop_watch=True))
        for name in ("Watch", "WatchKit", "com.apple.WatchPlaceholder"):
            self.assertFalse((self.app / name).exists())

    def test_missing_folders_are_not_an_error(self) -> None:
        apply_edits(self.app, BundleEdits(drop_extensions=True, drop_watch=True))

    def test_provision_is_deleted_at_the_root_and_in_nested_bundles(self) -> None:
        plugin = fixtures.fake_bundle(self.app / "PlugIns" / "Widget.appex")
        (self.app / "embedded.mobileprovision").write_bytes(b"profile")
        (plugin / "embedded.mobileprovision").write_bytes(b"profile")
        apply_edits(self.app, BundleEdits(drop_provision=True))
        self.assertFalse((self.app / "embedded.mobileprovision").exists())
        self.assertFalse((plugin / "embedded.mobileprovision").exists())

    def test_provision_removal_never_raises_when_absent(self) -> None:
        apply_edits(self.app, BundleEdits(drop_provision=True))

class IconEditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("edit_icon")
        self.icon = self.root / "icon.png"
        self.icon.write_bytes(fixtures.standard_png([b"\x11\x22\x33\xff" * 2] * 2))

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _bundle(self, **overrides) -> Path:
        return fixtures.fake_bundle(self.root / "Test.app", **overrides)

    def test_declared_root_pngs_are_overwritten(self) -> None:
        app = self._bundle(
            CFBundleIcons={"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}}
        )
        (app / "AppIcon60x60@2x.png").write_bytes(b"old")
        (app / "Other.png").write_bytes(b"old")

        apply_edits(app, BundleEdits(icon=self.icon))
        self.assertEqual((app / "AppIcon60x60@2x.png").read_bytes(), self.icon.read_bytes())
        self.assertEqual((app / "Other.png").read_bytes(), b"old")

    def test_nested_pngs_are_left_alone(self) -> None:
        app = self._bundle(
            CFBundleIcons={"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}}
        )
        nested = app / "Frameworks" / "Inner.framework"
        nested.mkdir(parents=True)
        (nested / "AppIcon60x60.png").write_bytes(b"old")

        apply_edits(app, BundleEdits(icon=self.icon))
        self.assertEqual((nested / "AppIcon60x60.png").read_bytes(), b"old")

    def test_ipad_icons_are_covered_too(self) -> None:
        app = self._bundle(
            **{
                "CFBundleIcons~ipad": {
                    "CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon76x76"]}
                }
            }
        )
        (app / "AppIcon76x76@2x~ipad.png").write_bytes(b"old")
        apply_edits(app, BundleEdits(icon=self.icon))
        self.assertEqual((app / "AppIcon76x76@2x~ipad.png").read_bytes(), self.icon.read_bytes())

    def test_cfbundleiconname_is_erased(self) -> None:
        """Otherwise the Assets.car icon wins on iOS 11+."""
        app = self._bundle(
            CFBundleIcons={
                "CFBundlePrimaryIcon": {
                    "CFBundleIconFiles": ["AppIcon60x60"],
                    "CFBundleIconName": "AppIcon",
                }
            }
        )
        apply_edits(app, BundleEdits(icon=self.icon))
        primary = _info(app)["CFBundleIcons"]["CFBundlePrimaryIcon"]
        self.assertNotIn("CFBundleIconName", primary)
        self.assertEqual(primary["CFBundleIconFiles"], ["AppIcon60x60"])

    def test_a_declared_name_missing_on_disk_is_created(self) -> None:
        app = self._bundle(
            CFBundleIcons={"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}}
        )
        apply_edits(app, BundleEdits(icon=self.icon))
        self.assertEqual((app / "AppIcon60x60@2x.png").read_bytes(), self.icon.read_bytes())

    def test_no_declared_icon_creates_the_default_entries(self) -> None:
        app = self._bundle()
        apply_edits(app, BundleEdits(icon=self.icon))

        info = _info(app)
        for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
            self.assertEqual(
                info[key]["CFBundlePrimaryIcon"]["CFBundleIconFiles"], ["AppIcon60x60"]
            )
        self.assertEqual((app / "AppIcon60x60@2x.png").read_bytes(), self.icon.read_bytes())

    def test_the_flat_keys_are_the_fallback(self) -> None:
        app = self._bundle(CFBundleIconFile="Solo")
        apply_edits(app, BundleEdits(icon=self.icon))
        self.assertEqual((app / "Solo@2x.png").read_bytes(), self.icon.read_bytes())

    def test_a_non_png_is_refused(self) -> None:
        app = self._bundle()
        bad = self.root / "bad.png"
        bad.write_bytes(b"not a png at all, really not")
        with self.assertRaises(BundleError):
            apply_edits(app, BundleEdits(icon=bad))

    def test_a_missing_icon_file_is_refused(self) -> None:
        app = self._bundle()
        with self.assertRaises(BundleError):
            apply_edits(app, BundleEdits(icon=self.root / "nope.png"))

    def test_the_png_is_not_decoded_just_copied(self) -> None:
        """A CgBI icon is written as it is; the caller owns the bytes."""
        app = self._bundle(
            CFBundleIcons={"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}}
        )
        crushed = fixtures.cgbi_png([b"\x11\x22\x33\xff" * 2] * 2)
        self.icon.write_bytes(crushed)
        (app / "AppIcon60x60.png").write_bytes(b"old")
        apply_edits(app, BundleEdits(icon=self.icon))
        self.assertEqual((app / "AppIcon60x60.png").read_bytes(), crushed)

class SealOrderTests(unittest.TestCase):
    """An edited file must be inside the seal, never added after it."""

    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("edit_seal")
        self.app = fixtures.fake_bundle(self.root / "Test.app")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_a_replaced_icon_is_sealed_with_its_new_hash(self) -> None:
        icon = self.root / "icon.png"
        icon.write_bytes(fixtures.standard_png([b"\x44\x55\x66\xff" * 2] * 2))
        (self.app / "AppIcon60x60.png").write_bytes(b"old")

        apply_edits(self.app, BundleEdits(icon=icon))
        sealed = plistlib.loads(generate_code_resources(self.app, "Test"))

        expected = __import__("hashlib").sha1(icon.read_bytes()).digest()
        self.assertEqual(sealed["files"]["AppIcon60x60.png"], expected)

    def test_a_removed_folder_is_not_sealed(self) -> None:
        plugins = self.app / "PlugIns"
        plugins.mkdir()
        (plugins / "Widget.appex").mkdir()
        (plugins / "Widget.appex" / "Info.plist").write_bytes(fixtures.info_plist())

        apply_edits(self.app, BundleEdits(drop_extensions=True))
        sealed = plistlib.loads(generate_code_resources(self.app, "Test"))
        self.assertFalse(any(key.startswith("PlugIns/") for key in sealed["files"]))

class EditModuleSurfaceTests(unittest.TestCase):
    def test_the_public_surface_is_small(self) -> None:
        self.assertEqual(set(edit.__all__), {"BundleEdits", "apply_edits"})

if __name__ == "__main__":
    unittest.main()
