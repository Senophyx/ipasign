"""Test suite for ipasign.

Run everything with::

    python -m unittest discover -s tests -t .

Or a single module::

    python -m unittest tests.test_blobs

The tests build their own inputs from ``tests/fixtures.py``, so they need
neither the sample IPA nor the signing certificate under ``__test/``. Scratch
files live in ``tests/.scratch`` and are removed as the tests finish.
"""

from __future__ import annotations
