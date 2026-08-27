"""Tests for the sidebar panel's stable WebSocket payload."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).parents[1]

voluptuous = types.ModuleType("voluptuous")
voluptuous.Required = lambda value: value
sys.modules.setdefault("voluptuous", voluptuous)

websocket_api = types.ModuleType("homeassistant.components.websocket_api")
websocket_api.ActiveConnection = object
websocket_api.websocket_command = lambda schema: lambda func: func
websocket_api.async_response = lambda func: func
websocket_api.async_register_command = lambda hass, command: None
sys.modules["homeassistant.components.websocket_api"] = websocket_api

core = sys.modules.get("homeassistant.core", types.ModuleType("homeassistant.core"))
core.HomeAssistant = object
core.callback = lambda func: func
sys.modules["homeassistant.core"] = core

package = sys.modules.get("custom_components", types.ModuleType("custom_components"))
package.__path__ = [str(ROOT / "custom_components")]
integration = sys.modules.get(
    "custom_components.brunata_online",
    types.ModuleType("custom_components.brunata_online"),
)
integration.__path__ = [str(ROOT / "custom_components" / "brunata_online")]
sys.modules["custom_components"] = package
sys.modules["custom_components.brunata_online"] = integration

from custom_components.brunata_online import panel  # noqa: E402


class PanelPayloadTests(unittest.TestCase):
    """Ensure raw coordinator data becomes chart-friendly panel data."""

    def test_builds_meter_and_history_payload(self) -> None:
        meter = {
            "meterId": "meter-1",
            "meterNo": "123",
            "meterSequenceNo": "1",
            "allocationUnit": "K",
            "placement": "Køkken",
            "unit": "8",
        }
        coordinator = types.SimpleNamespace(
            data={
                "meters": [
                    {
                        "meter": meter,
                        "reading": {
                            "value": "123,45",
                            "readingDate": "2026-08-27",
                        },
                    }
                ],
                "meter_history_30d": {
                    "meter-1|1|123|K": [
                        {"date": "2026-08-01", "value": "120,0"},
                        {"date": "2026-08-27", "value": "123,45"},
                    ]
                },
            },
            config_entry=types.SimpleNamespace(title="Hjem"),
            last_update_success=True,
            last_update_success_time=datetime(2026, 8, 27, tzinfo=timezone.utc),
        )
        hass = types.SimpleNamespace(
            data={"brunata_online": {"entry-id": coordinator}}
        )

        result = panel.build_panel_payload(hass)
        account = result["accounts"][0]
        reading = account["meters"][0]

        self.assertEqual(account["title"], "Hjem")
        self.assertEqual(reading["medium"], "cold_water")
        self.assertEqual(reading["unit"], "m³")
        self.assertEqual(reading["value"], 123.45)
        self.assertEqual(
            [point["value"] for point in reading["history"]], [120.0, 123.45]
        )


if __name__ == "__main__":
    unittest.main()
