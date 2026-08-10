"""Tests for pure meter normalization and aggregation helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

path = (
    Path(__file__).parents[1] / "custom_components" / "brunata_online" / "meter_data.py"
)
spec = importlib.util.spec_from_file_location("meter_data", path)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Cannot load {path}")
meter_data = importlib.util.module_from_spec(spec)
spec.loader.exec_module(meter_data)


class MeterDataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_row = {
            "meter": {
                "meterId": "old",
                "meterSequenceNo": "1",
                "meterNo": "hot-water",
                "allocationUnit": "W",
            },
            "reading": {"value": None},
        }
        self.new_row = {
            "meter": {
                "meterId": "new",
                "meterSequenceNo": "2",
                "meterNo": "hot-water",
                "allocationUnit": "W",
            },
            "reading": {"value": "1,25"},
        }

    def test_transmitter_replacement_uses_historical_baseline(self) -> None:
        old_key = meter_data.history_key(meter_data.row_key(self.old_row))
        coordinator_data = {
            "meter_history_30d": {
                old_key: [
                    {"value": "not-a-number"},
                    {"value": "12,5"},
                    {"value": None},
                ]
            }
        }

        self.assertEqual(
            meter_data.current_or_history_value(coordinator_data, self.old_row),
            12.5,
        )
        self.assertEqual(
            meter_data.sum_current_values(
                coordinator_data, [self.old_row, self.new_row]
            ),
            13.75,
        )

    def test_current_zero_is_not_replaced_by_history(self) -> None:
        self.old_row["reading"]["value"] = 0
        old_key = meter_data.history_key(meter_data.row_key(self.old_row))
        data = {"meter_history_30d": {old_key: [{"value": 99}]}}
        self.assertEqual(meter_data.current_or_history_value(data, self.old_row), 0)

    def test_boolean_is_not_a_numeric_meter_value(self) -> None:
        self.assertIsNone(meter_data.normalize_reading_value(True))


if __name__ == "__main__":
    unittest.main()
