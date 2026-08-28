"""Tests for consumption reports and budget progress."""

from __future__ import annotations

from datetime import date
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "brunata_analytics",
    ROOT / "custom_components" / "brunata_online" / "analytics.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load analytics module")
analytics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analytics)


class ConsumptionReportTests(unittest.TestCase):
    def test_compares_current_and_previous_calendar_windows(self) -> None:
        points = [
            {"date": "2026-07-31", "value": 100},
            {"date": "2026-08-07", "value": 112},
            {"date": "2026-08-14", "value": 130},
        ]

        report = analytics.consumption_report(
            points, period="week", today=date(2026, 8, 14)
        )

        self.assertEqual(report["current"], 18.0)
        self.assertEqual(report["previous"], 12.0)
        self.assertEqual(report["change_percent"], 50.0)
        self.assertEqual(report["status"], "complete")

    def test_reports_unavailable_when_history_is_insufficient(self) -> None:
        report = analytics.consumption_report(
            [{"date": "2026-08-14", "value": 130}],
            period="month",
            today=date(2026, 8, 14),
        )

        self.assertEqual(report["status"], "insufficient_history")
        self.assertIsNone(report["change_percent"])

    def test_rejects_meter_resets(self) -> None:
        report = analytics.consumption_report(
            [
                {"date": "2026-08-01", "value": 100},
                {"date": "2026-08-07", "value": 10},
                {"date": "2026-08-14", "value": 20},
            ],
            period="week",
            today=date(2026, 8, 14),
        )

        self.assertEqual(report["status"], "insufficient_history")

    def test_calculates_budget_progress_without_dividing_by_zero(self) -> None:
        self.assertEqual(
            analytics.budget_progress(25, 100),
            {"budget": 100.0, "consumed": 25.0, "remaining": 75.0, "percent": 25.0},
        )
        self.assertIsNone(analytics.budget_progress(25, 0))


if __name__ == "__main__":
    unittest.main()
