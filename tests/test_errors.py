"""Tests for the exception hierarchy."""

from __future__ import annotations

import unittest

from ipasign import errors


class HierarchyTests(unittest.TestCase):
    def test_every_error_derives_from_the_base(self) -> None:
        for name in errors.__all__:
            if name == "IpasignError":
                continue
            self.assertTrue(
                issubclass(getattr(errors, name), errors.IpasignError),
                f"{name} must derive from IpasignError",
            )

    def test_profile_error_is_a_credential_error(self) -> None:
        self.assertTrue(issubclass(errors.ProfileError, errors.CredentialError))


class NoRawLeakTests(unittest.TestCase):
    """The public API must not surface struct.error, KeyError or bare ValueError."""

    def test_macho_parse_wraps_struct_errors(self) -> None:
        from ipasign.macho import MachOFile

        for payload in (b"\xcf\xfa\xed\xfe", b"\xcf\xfa\xed\xfe" + b"\x00" * 4, b"\xca\xfe\xba\xbe" + b"\xff" * 4):
            try:
                MachOFile.parse(payload)
            except errors.IpasignError:
                pass
            except Exception as exc:  # noqa: BLE001 - the point of the test
                self.fail(f"leaked {type(exc).__name__} for {payload!r}")

    def test_bad_entitlements_wrap_into_blob_error(self) -> None:
        from ipasign import blobs

        with self.assertRaises(errors.BlobError):
            blobs._der_value(object())


if __name__ == "__main__":
    unittest.main()
