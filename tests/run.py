"""Run the whole test suite and clean up after it.

    python tests/run.py

``python -m unittest discover`` works too; this wrapper just removes the shared
scratch directory once every test has finished, including after a failure.
"""

from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests import fixtures  # noqa: E402 - path must be set up first


def main() -> int:
    try:
        suite = unittest.defaultTestLoader.discover(str(TESTS_DIR), top_level_dir=str(PROJECT_ROOT))
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        shutil.rmtree(fixtures.SCRATCH, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
