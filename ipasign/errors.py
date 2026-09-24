"""Exception types raised by the public API.

Everything the library raises derives from :class:`IpasignError`, so callers
can catch one base class and still tell the failure modes apart.
"""

from __future__ import annotations


class IpasignError(Exception):
    """Base class for every error ipasign raises."""


class InvalidInputError(IpasignError):
    """The input is not something this library knows how to sign."""


class MachOError(IpasignError):
    """A Mach-O file is malformed or cannot be rewritten."""


class BlobError(IpasignError):
    """A code signature blob could not be built or parsed."""


class CredentialError(IpasignError):
    """A signing identity, password or provisioning profile is unusable."""


class ProfileError(CredentialError):
    """A provisioning profile could not be read or is missing required data."""


class BundleError(IpasignError):
    """A bundle is missing the structure signing requires."""


class ArchiveError(IpasignError):
    """An archive could not be unpacked or repacked."""


class NotEnoughSpaceError(MachOError):
    """The load commands have no room for a new LC_CODE_SIGNATURE."""


__all__ = [
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
