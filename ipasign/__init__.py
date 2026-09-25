"""ipasign: pure-Python iOS code signing.

Re-sign iOS ``.ipa`` archives, ``.app`` bundles, frameworks, dylibs and bare
Mach-O executables with a ``.p12`` identity and a ``.mobileprovision`` profile.

    import ipasign

    key = ipasign.Key(pkey, prov, password)

    app = ipasign.App("input.ipa")
    signed = app.sign(key)
    print(f"Successfully signed: {signed.output_path}")

:class:`App` accepts anything signable: an ``.ipa`` archive, an ``.app`` bundle
folder, a framework, a dylib, or a bare Mach-O executable. An archive gets a
default output named after the input; everything else is signed in place.
"""

from .app import App
from .errors import (
    ArchiveError,
    BlobError,
    BundleError,
    CredentialError,
    InvalidInputError,
    IpasignError,
    MachOError,
    NotEnoughSpaceError,
    ProfileError,
)
from .key import Key
from .result import SignResult

__version__ = "1.0"

__all__ = [
    "App",
    "Key",
    "SignResult",
    "IpasignError",
    "InvalidInputError",
    "MachOError",
    "BlobError",
    "CredentialError",
    "ProfileError",
    "BundleError",
    "ArchiveError",
    "NotEnoughSpaceError",
]
