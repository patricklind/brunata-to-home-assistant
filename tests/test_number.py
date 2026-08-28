"""Tests for shared Brunata numeric normalization."""

from __future__ import annotations

import unittest

from custom_components.brunata_online.number import parse_finite_number


class NumberNormalizationTests(unittest.TestCase):
    def test_parses_supported_localized_values(self) -> None:
        self.assertEqual(parse_finite_number("1.234,56"), 1234.56)
        self.assertEqual(parse_finite_number("1,234.56"), 1234.56)
        self.assertEqual(parse_finite_number("12,5"), 12.5)
        self.assertEqual(parse_finite_number(12), 12.0)
        self.assertEqual(parse_finite_number(12, preserve_integer=True), 12)

    def test_rejects_unsafe_or_missing_values(self) -> None:
        for value in (None, True, False, "", "NaN", "Infinity", float("inf")):
            with self.subTest(value=value):
                self.assertIsNone(parse_finite_number(value))


if __name__ == "__main__":
    unittest.main()
