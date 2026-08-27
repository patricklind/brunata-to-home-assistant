"""Tests for privacy-preserving Home Assistant diagnostics."""

from __future__ import annotations

import asyncio
from enum import Enum
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).parents[1]

homeassistant = types.ModuleType("homeassistant")
components = types.ModuleType("homeassistant.components")
diagnostics_stub = types.ModuleType("homeassistant.components.diagnostics")
config_entries = types.ModuleType("homeassistant.config_entries")
core = types.ModuleType("homeassistant.core")
const = types.ModuleType("homeassistant.const")


class Platform(Enum):
    """Minimal Home Assistant platform stub."""

    SENSOR = "sensor"


def async_redact_data(data, keys):
    return {
        key: "**REDACTED**" if key in keys else value for key, value in data.items()
    }


diagnostics_stub.async_redact_data = async_redact_data
config_entries.ConfigEntry = object
core.HomeAssistant = object
const.Platform = Platform
sys.modules.update(
    {
        "homeassistant": homeassistant,
        "homeassistant.components": components,
        "homeassistant.components.diagnostics": diagnostics_stub,
        "homeassistant.config_entries": config_entries,
        "homeassistant.core": core,
        "homeassistant.const": const,
    }
)

package = types.ModuleType("custom_components")
package.__path__ = [str(ROOT / "custom_components")]
integration = types.ModuleType("custom_components.brunata_online")
integration.__path__ = [str(ROOT / "custom_components" / "brunata_online")]
sys.modules["custom_components"] = package
sys.modules["custom_components.brunata_online"] = integration

from custom_components.brunata_online import diagnostics  # noqa: E402


class DiagnosticsTests(unittest.TestCase):
    """Ensure useful data is exported without account or meter identity."""

    def test_redacts_credentials_and_raw_meter_identifiers(self) -> None:
        row = {
            "meter": {
                "meterId": "secret-meter-id",
                "meterSequenceNo": "3",
                "meterNo": "private-serial",
                "allocationUnit": "K",
                "placement": "Private bathroom",
            },
            "reading": {"value": 123.4, "readingDate": "2026-08-01"},
        }
        raw_key = "secret-meter-id|3|private-serial|K"
        coordinator = types.SimpleNamespace(
            data={
                "fetched_at": "2026-08-27T12:00:00+00:00",
                "best_startdate": "2026-08-01",
                "non_null_readings": 1,
                "attempts": [{"startdate": "2026-08-01", "status": "ok"}],
                "meters": [row],
                "meter_history_30d": {
                    raw_key: [
                        {
                            "date": "2026-08-01",
                            "reading_date": "2026-08-01",
                            "value": 123.4,
                            "private": "drop-me",
                        }
                    ]
                },
                "meter_history_meta": {"successful_days": 1},
                "consumer": {"email": "must-not-appear@example.com"},
            }
        )
        hass = types.SimpleNamespace(data={"brunata_online": {"entry": coordinator}})
        entry = types.SimpleNamespace(
            entry_id="entry",
            data={"username": "person@example.com", "password": "secret"},
        )

        result = asyncio.run(
            diagnostics.async_get_config_entry_diagnostics(hass, entry)
        )
        serialized = repr(result)

        self.assertEqual(result["config_entry"]["username"], "**REDACTED**")
        self.assertEqual(result["config_entry"]["password"], "**REDACTED**")
        self.assertEqual(result["coordinator"]["meters"][0]["reading"]["value"], 123.4)
        self.assertEqual(len(result["coordinator"]["meters"][0]["meter_ref"]), 12)
        for secret in (
            "person@example.com",
            "secret-meter-id",
            "private-serial",
            "Private bathroom",
            "must-not-appear@example.com",
            "drop-me",
        ):
            self.assertNotIn(secret, serialized)

    def test_handles_missing_coordinator(self) -> None:
        hass = types.SimpleNamespace(data={})
        entry = types.SimpleNamespace(entry_id="missing", data={})

        result = asyncio.run(
            diagnostics.async_get_config_entry_diagnostics(hass, entry)
        )

        self.assertEqual(result["coordinator"], {"available": False})


if __name__ == "__main__":
    unittest.main()
