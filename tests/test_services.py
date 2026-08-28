"""Tests for report and CSV action response builders."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).parents[1]

vol = sys.modules.get("voluptuous", types.ModuleType("voluptuous"))
vol.Optional = getattr(vol, "Optional", lambda value, **kwargs: value)
vol.Required = getattr(vol, "Required", lambda value, **kwargs: value)
vol.In = getattr(vol, "In", lambda value: value)
sys.modules["voluptuous"] = vol

core = sys.modules.get("homeassistant.core", types.ModuleType("homeassistant.core"))
core.HomeAssistant = object
core.ServiceCall = object
core.SupportsResponse = types.SimpleNamespace(ONLY="only")
sys.modules["homeassistant.core"] = core
exceptions = types.ModuleType("homeassistant.exceptions")
exceptions.Unauthorized = RuntimeError
sys.modules["homeassistant.exceptions"] = exceptions

package = sys.modules.get("custom_components", types.ModuleType("custom_components"))
package.__path__ = [str(ROOT / "custom_components")]
integration = sys.modules.get(
    "custom_components.brunata_online", types.ModuleType("custom_components.brunata_online")
)
integration.__path__ = [str(ROOT / "custom_components" / "brunata_online")]
sys.modules["custom_components"] = package
sys.modules["custom_components.brunata_online"] = integration

from custom_components.brunata_online import services  # noqa: E402


class ServiceResponseTests(unittest.TestCase):
    def setUp(self) -> None:
        today = date.today()
        dates = [today - timedelta(days=14), today - timedelta(days=7), today]
        row = {
            "meter": {
                "meterId": "one",
                "meterSequenceNo": "1",
                "meterNo": "42",
                "allocationUnit": "K",
                "placement": "=private",
            }
        }
        self.coordinator = types.SimpleNamespace(
            config_entry=types.SimpleNamespace(entry_id="entry", title="Home"),
            data={
                "fetched_at": today.isoformat(),
                "meters": [row],
                "meter_history_30d": {
                    "one|1|42|K": [
                        {"date": dates[0].isoformat(), "value": 10},
                        {"date": dates[1].isoformat(), "value": 15},
                        {"date": dates[2].isoformat(), "value": 25},
                    ]
                },
            },
        )

    def test_builds_report_response(self) -> None:
        response = services.build_report_response([self.coordinator], "week")
        report = response["accounts"][0]["meters"][0]
        self.assertEqual(report["current"], 10.0)
        self.assertEqual(report["previous"], 5.0)
        self.assertEqual(report["change_percent"], 100.0)

    def test_csv_neutralizes_spreadsheet_formulas(self) -> None:
        response = services.build_csv_response([self.coordinator])
        self.assertEqual(response["filename"], "brunata-report.csv")
        self.assertIn("'=private", response["content"])
        self.assertNotIn("\nHome,=private", response["content"])


if __name__ == "__main__":
    unittest.main()
