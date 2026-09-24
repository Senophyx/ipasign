"""Tests for the plist serialisation helper."""

from __future__ import annotations

import plistlib
import unittest

from ipasign import _plist


class RealFormattingTests(unittest.TestCase):
    """plistlib writes 1000.0; Apple writes 1000. The seal hashes these bytes."""

    def test_integral_real_has_no_decimal_part(self) -> None:
        raw = _plist.dumps({"weight": 1000.0})
        self.assertIn(b"<real>1000</real>", raw)
        self.assertNotIn(b"<real>1000.0</real>", raw)

    def test_fractional_real_is_left_alone(self) -> None:
        self.assertIn(b"<real>0.5</real>", _plist.dumps({"ratio": 0.5}))

    def test_negative_integral_real(self) -> None:
        self.assertIn(b"<real>-20</real>", _plist.dumps({"n": -20.0}))

    def test_integers_are_not_touched(self) -> None:
        self.assertIn(b"<integer>1000</integer>", _plist.dumps({"n": 1000}))

    def test_value_survives_the_round_trip(self) -> None:
        source = {"weight": 1000.0, "ratio": 0.5, "n": 7, "name": "x"}
        self.assertEqual(plistlib.loads(_plist.dumps(source)), source)


class KeyOrderTests(unittest.TestCase):
    def test_insertion_order_is_preserved(self) -> None:
        raw = _plist.dumps({"z": 1, "a": 2, "m": 3})
        self.assertLess(raw.index(b"<key>z</key>"), raw.index(b"<key>a</key>"))
        self.assertLess(raw.index(b"<key>a</key>"), raw.index(b"<key>m</key>"))

    def test_order_is_not_sorted(self) -> None:
        # Search for the wrapped key, not the bare word: "apple" also appears in
        # the DOCTYPE URL (www.apple.com).
        raw = _plist.dumps({"zebra": 1, "apple": 2})
        self.assertLess(raw.index(b"<key>zebra</key>"), raw.index(b"<key>apple</key>"))


class LoadTests(unittest.TestCase):
    def test_loads_xml(self) -> None:
        self.assertEqual(_plist.loads(_plist.dumps({"a": 1})), {"a": 1})

    def test_loads_binary(self) -> None:
        raw = plistlib.dumps({"a": 1}, fmt=plistlib.FMT_BINARY)
        self.assertEqual(_plist.loads(raw), {"a": 1})


if __name__ == "__main__":
    unittest.main()
