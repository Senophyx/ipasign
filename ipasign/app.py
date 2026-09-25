"""The :class:`App` facade: name an ``.ipa``, then sign it.

``App`` is the shorter path to what :meth:`Key.sign` already does. The only
thing it adds is a default output path, derived from the input, so the common
case does not have to name one:

    app = ipasign.App("test.ipa")
    signed = app.sign(key)                    # -> test-signed.ipa
    signed = app.sign(key, output="out.ipa")  # -> out.ipa

It holds no signing state of its own: the key carries the identity and the
entitlements, and every call goes through :meth:`Key.sign`.
"""

from __future__ import annotations

import os
from pathlib import Path

from .errors import InvalidInputError
from .key import Key, SignResult

class App:
    """One ``.ipa`` archive, ready to be signed.

    The path is validated here and unpacked later, when :meth:`sign` runs.
    """

    def __init__(self, ipa: str | os.PathLike) -> None:
        path = Path(ipa)
        if not path.exists():
            raise InvalidInputError(f"input does not exist: {path}")
        if not path.is_file() or path.suffix.lower() != ".ipa":
            raise InvalidInputError(f"not an .ipa file: {path}")
        self.path = path

    @property
    def default_output(self) -> Path:
        """Where :meth:`sign` writes when the caller names no output.

        ``test.ipa`` becomes ``test-signed.ipa`` beside it. An input that
        already ends in ``-signed`` simply gains another suffix.
        """
        return self.path.with_name(f"{self.path.stem}-signed{self.path.suffix}")

    def sign(
        self,
        key: Key,
        output: str | os.PathLike | None = None,
    ) -> SignResult:
        """Sign the archive and report where the result landed.

        ``output`` defaults to :attr:`default_output`. An existing file at the
        target is overwritten, which is safe even when it is the input itself:
        the archive is fully unpacked before anything is written back.
        """
        target = Path(output) if output is not None else self.default_output
        return key.sign(self.path, target)

__all__ = ["App"]
