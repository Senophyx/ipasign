"""ipasign: pure-Python iOS code signing.

Re-sign iOS ``.ipa`` archives, ``.app`` bundles, frameworks, dylibs and bare
Mach-O executables with a ``.p12`` identity and a ``.mobileprovision`` profile.

    import ipasign

    key = ipasign.Key(pkey, prov, password)

    app = ipasign.App("input.ipa")
    signed = app.sign(key)
    print(f"Successfully signed: {signed.output_path}")

The same run through :meth:`Key.sign`, naming the output explicitly::

    out = key.sign("input.ipa", "output.ipa")
    print(f"Successfully signed: {out.output_path}")
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
from .key import Key, SignResult

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
