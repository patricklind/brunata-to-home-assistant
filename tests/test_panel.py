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
voluptuous.Optional = lambda value, **kwargs: value
voluptuous.All = lambda *values: values[0]
voluptuous.Coerce = lambda value: value
voluptuous.In = lambda value: value
voluptuous.Match = lambda value: value
voluptuous.Range = lambda **kwargs: kwargs
sys.modules.setdefault("voluptuous", voluptuous)

websocket_api = types.ModuleType("homeassistant.components.websocket_api")
websocket_api.ActiveConnection = object
websocket_api.websocket_command = lambda schema: lambda func: func
websocket_api.async_response = lambda func: func


def _require_admin(func):
    func.requires_admin = True
    return func


websocket_api.require_admin = _require_admin
websocket_api.async_register_command = lambda hass, command: None
sys.modules["homeassistant.components.websocket_api"] = websocket_api

core = sys.modules.get("homeassistant.core", types.ModuleType("homeassistant.core"))
core.HomeAssistant = object
core.callback = lambda func: func
sys.modules["homeassistant.core"] = core

storage = types.ModuleType("homeassistant.helpers.storage")
storage.Store = object
sys.modules["homeassistant.helpers.storage"] = storage

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
        hass = types.SimpleNamespace(data={"brunata_online": {"entry-id": coordinator}})

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

    def test_websocket_payload_requires_admin(self) -> None:
        self.assertIs(panel.websocket_panel_data.requires_admin, True)

    def test_panel_payload_contains_server_settings(self) -> None:
        hass = types.SimpleNamespace(
            data={
                "brunata_online": {},
                panel.PANEL_SETTINGS_DATA: {
                    "period": 7,
                    "precision": 1,
                    "currency": "DKK",
                    "waterPrice": 12.5,
                    "heatingPrice": 0.8,
                },
            }
        )
        self.assertEqual(
            build := panel.build_panel_payload(hass),
            {
                "accounts": [],
                "settings": hass.data[panel.PANEL_SETTINGS_DATA],
            },
        )
        self.assertEqual(build["settings"]["currency"], "DKK")

    def test_normalizes_untrusted_persisted_settings(self) -> None:
        self.assertEqual(
            panel.normalize_panel_settings(
                {
                    "period": 9,
                    "precision": 99,
                    "currency": "dkk",
                    "waterPrice": "12,50",
                    "heatingPrice": -4,
                }
            ),
            {
                "period": 30,
                "precision": 3,
                "currency": "DKK",
                "waterPrice": 12.5,
                "heatingPrice": 0.0,
            },
        )
        self.assertEqual(
            panel.normalize_panel_settings(
                {
                    "period": True,
                    "precision": float("inf"),
                    "waterPrice": "NaN",
                    "heatingPrice": "Infinity",
                }
            ),
            panel.DEFAULT_PANEL_SETTINGS,
        )

    def test_settings_update_websocket_requires_admin(self) -> None:
        self.assertIs(panel.websocket_update_panel_settings.requires_admin, True)


class PanelSettingsUpdateTests(unittest.IsolatedAsyncioTestCase):
    async def test_settings_update_is_normalized_persisted_and_returned(self) -> None:
        class FakeStore:
            saved = None

            async def async_save(self, value):
                self.saved = value

        class FakeConnection:
            result = None

            def send_result(self, message_id, value):
                self.result = (message_id, value)

        store = FakeStore()
        connection = FakeConnection()
        hass = types.SimpleNamespace(data={panel.PANEL_SETTINGS_STORE: store})

        await panel.websocket_update_panel_settings(
            hass,
            connection,
            {
                "id": 7,
                "settings": {
                    "period": "7",
                    "precision": "1",
                    "currency": "dkk",
                    "waterPrice": "10,25",
                    "heatingPrice": "-1",
                },
            },
        )

        expected = {
            "period": 7,
            "precision": 1,
            "currency": "DKK",
            "waterPrice": 10.25,
            "heatingPrice": 0.0,
        }
        self.assertEqual(store.saved, expected)
        self.assertEqual(hass.data[panel.PANEL_SETTINGS_DATA], expected)
        self.assertEqual(connection.result, (7, {"settings": expected}))


if __name__ == "__main__":
    unittest.main()
