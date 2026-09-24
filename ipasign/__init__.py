"""ipasign: pure-Python iOS code signing.

Re-sign iOS ``.ipa`` archives, ``.app`` bundles, frameworks, dylibs and bare
Mach-O executables with a ``.p12`` identity and a ``.mobileprovision`` profile.

    import ipasign

    key = ipasign.Key(pkey, prov, password)
    out = key.sign(input_file, output_file)
    print(f"Successfully signed: {out.output_path}")
"""

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
