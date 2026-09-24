"""Tests for credential and provisioning profile loading."""

from __future__ import annotations

import datetime
import shutil
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from ipasign import credentials
from ipasign.credentials import load_entitlements, load_identity, load_profile
from ipasign.errors import CredentialError, ProfileError

from . import fixtures


def make_p12(path: Path, password: bytes | None, *, include_key: bool = True, include_cert: bool = True) -> Path:
    """Write a throwaway p12 holding a self-signed leaf."""
    identity = fixtures.test_identity()
    key = identity.private_key if include_key else None
    cert = identity.certificate if include_cert else None
    path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"test",
            key,
            cert,
            None,
            serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption(),
        )
    )
    return path


def _profile_with(*certs) -> object:
    """A stand-in profile whose developer certificates seed the chain."""
    from cryptography.hazmat.primitives.serialization import Encoding

    from ipasign.credentials import ProvisioningProfile

    der = [cert.public_bytes(Encoding.DER) for cert in certs]
    return ProvisioningProfile(
        data=b"",
        entitlements={"application-identifier": "TEAM123456.com.example.test"},
        entitlements_plist=b"<plist/>",
        team_id="TEAM123456",
        application_id="TEAM123456.com.example.test",
        developer_certificates=der,
    )


class ProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("credentials_profile")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, data: bytes, name: str = "profile.mobileprovision") -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_reads_team_entitlements_and_application_id(self) -> None:
        profile = load_profile(self.write(fixtures.mobileprovision()))
        self.assertEqual(profile.team_id, "TEAM123456")
        self.assertEqual(profile.application_id, "TEAM123456.com.example.test")
        self.assertEqual(profile.entitlements["application-identifier"], "TEAM123456.com.example.test")

    def test_entitlements_plist_is_preserved_in_order(self) -> None:
        profile = load_profile(self.write(fixtures.mobileprovision()))
        self.assertLess(
            profile.entitlements_plist.index(b"application-identifier"),
            profile.entitlements_plist.index(b"get-task-allow"),
            "insertion order must survive",
        )

    def test_get_task_allow_reads_the_boolean(self) -> None:
        false_profile = load_profile(self.write(fixtures.mobileprovision()))
        self.assertFalse(false_profile.get_task_allow)

        true_profile = load_profile(
            self.write(
                fixtures.mobileprovision(
                    entitlements={"application-identifier": "app", "get-task-allow": True}
                ),
                "true.mobileprovision",
            )
        )
        self.assertTrue(true_profile.get_task_allow)

    def test_get_task_allow_absent_is_false(self) -> None:
        profile = load_profile(
            self.write(
                fixtures.mobileprovision(entitlements={"application-identifier": "app"}),
                "absent.mobileprovision",
            )
        )
        self.assertFalse(profile.get_task_allow)

    def test_matches_bundle_id(self) -> None:
        profile = load_profile(self.write(fixtures.mobileprovision()))
        self.assertTrue(profile.matches("com.example.test"))
        self.assertFalse(profile.matches("com.other.app"))

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(ProfileError):
            load_profile(self.root / "nope.mobileprovision")

    def test_empty_file_raises(self) -> None:
        with self.assertRaises(ProfileError):
            load_profile(self.write(b"", "empty.mobileprovision"))

    def test_garbage_raises(self) -> None:
        with self.assertRaises(ProfileError):
            load_profile(self.write(b"not a cms structure", "garbage.mobileprovision"))

    def test_missing_team_identifier_raises(self) -> None:
        with self.assertRaises(ProfileError):
            load_profile(self.write(fixtures.mobileprovision(include_team=False), "noteam.mobileprovision"))

    def test_missing_entitlements_raises(self) -> None:
        with self.assertRaises(ProfileError):
            load_profile(
                self.write(fixtures.mobileprovision(include_entitlements=False), "noent.mobileprovision")
            )


class IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("credentials_identity")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_loads_key_and_leaf_when_a_chain_is_given(self) -> None:
        path = make_p12(self.root / "id.p12", b"secret")
        identity = fixtures.test_identity("Test Signer")
        # The p12 carries no CA chain, so pass the issuer explicitly the way a
        # profile would supply it.
        loaded = load_identity(path, "secret", _profile_with(identity.certificate))
        self.assertEqual(loaded.subject_cn, "Test Signer")
        self.assertIn(loaded.certificate, loaded.chain)

    def test_self_signed_leaf_without_chain_raises(self) -> None:
        path = make_p12(self.root / "id.p12", b"secret")
        with self.assertRaises(CredentialError):
            load_identity(path, "secret")

    def test_chain_has_leaf_last(self) -> None:
        identity = fixtures.test_identity("Test Signer")
        path = make_p12(self.root / "id.p12", b"secret")
        loaded = load_identity(path, "secret", _profile_with(identity.certificate))
        self.assertEqual(loaded.chain[-1], loaded.certificate)

    def test_wrong_password_raises(self) -> None:
        path = make_p12(self.root / "id.p12", b"secret")
        with self.assertRaises(CredentialError):
            load_identity(path, "wrong")

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(CredentialError):
            load_identity(self.root / "nope.p12", "x")

    def test_p12_without_key_raises(self) -> None:
        path = make_p12(self.root / "nokey.p12", None, include_key=False)
        with self.assertRaises(CredentialError):
            load_identity(path, None)

    def test_p12_without_certificate_raises(self) -> None:
        path = make_p12(self.root / "nocert.p12", None, include_cert=False)
        with self.assertRaises(CredentialError):
            load_identity(path, None)


class EntitlementsFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fixtures.scratch_dir("credentials_entitlements")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_reads_and_preserves_order(self) -> None:
        path = self.root / "ent.plist"
        path.write_bytes(fixtures.info_plist(z=1))
        parsed, raw = load_entitlements(path)
        self.assertIsInstance(parsed, dict)
        self.assertEqual(raw, fixtures.info_plist(z=1))

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(CredentialError):
            load_entitlements(self.root / "nope.plist")

    def test_not_a_plist_raises(self) -> None:
        path = self.root / "bad.plist"
        path.write_text("nope")
        with self.assertRaises(CredentialError):
            load_entitlements(path)

    def test_not_a_dictionary_raises(self) -> None:
        import plistlib

        path = self.root / "list.plist"
        path.write_bytes(plistlib.dumps([1, 2, 3], fmt=plistlib.FMT_XML))
        with self.assertRaises(CredentialError):
            load_entitlements(path)


class ChainSelectionTests(unittest.TestCase):
    """A p12 or profile chain must not shadow the right intermediate."""

    def test_unrelated_chain_is_discarded(self) -> None:
        leaf = fixtures.test_identity("Leaf")
        stranger = fixtures.test_identity("Stranger")
        # The stranger does not issue the leaf, so it is dropped and the search
        # falls through to the embedded Apple intermediates, which have no match.
        with self.assertRaises(CredentialError):
            credentials._select_chain(leaf.certificate, [stranger.certificate], [])

    def test_matching_chain_is_kept_with_leaf_last(self) -> None:
        """An intermediate that issues the leaf is kept, and the leaf is last."""
        issuer = fixtures.test_identity("Intermediate")
        leaf = fixtures.issued_by(issuer.certificate, "Leaf")
        chain = credentials._select_chain(leaf.certificate, [issuer.certificate], [])
        self.assertEqual(chain[-1], leaf.certificate)
        self.assertIn(issuer.certificate, chain)
        self.assertEqual(chain.count(leaf.certificate), 1, "the leaf is not duplicated")

    def test_self_signed_leaf_without_chain_raises(self) -> None:
        identity = fixtures.test_identity("Orphan")
        with self.assertRaises(CredentialError):
            credentials._select_chain(identity.certificate, [], [])

    def test_embedded_intermediate_is_found_for_a_real_issuer(self) -> None:
        """A leaf issued by an embedded Apple intermediate resolves by subject."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes as x509_hashes
        from cryptography.hazmat.primitives.asymmetric import rsa as x509_rsa
        from cryptography.x509.oid import NameOID

        from ipasign import _apple_ca

        intermediate = x509.load_pem_x509_certificate(_apple_ca.WWDR_G3.encode())
        key = x509_rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issued")]))
            .issuer_name(intermediate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, x509_hashes.SHA256())
        )
        chain = credentials._select_chain(leaf, [], [])
        self.assertIn(intermediate, chain)
        self.assertEqual(chain[-1], leaf)


if __name__ == "__main__":
    unittest.main()
