"""WebSocket data source for the Brunata Online panel."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN

PANEL_WS_REGISTERED = "brunata_online_panel_ws_registered"


def _number(value: Any) -> float | None:
    """Convert Brunata's localized numeric values for the frontend."""
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    text = value.strip().replace(" ", "")
    if not text:
        return None
    if "," in text and "." in text:
        text = (
            text.replace(".", "").replace(",", ".")
            if text.rfind(",") > text.rfind(".")
            else text.replace(",", "")
        )
    elif "," in text:
        text = text.replace(",", ".")
    try:
        return float(text)
    except ValueError:
        return None


def _medium(meter: dict[str, Any]) -> str:
    allocation = str(meter.get("allocationUnit") or "").lower()
    meter_type = str(meter.get("meterType") or "").lower()
    if allocation == "k" or "cold" in meter_type or "koldt" in meter_type:
        return "cold_water"
    if allocation == "w" or "hot" in meter_type or "varmt" in meter_type:
        return "hot_water"
    if allocation == "o" or "heat" in meter_type or "opvarm" in meter_type:
        return "heating"
    return "other"


def _unit(meter: dict[str, Any]) -> str:
    return {"8": "m³", "4": "kWh", "9": "kWh"}.get(
        str(meter.get("unit") or ""), "units"
    )


def build_panel_payload(hass: HomeAssistant) -> dict[str, Any]:
    """Build a compact, stable view of all configured Brunata accounts."""
    accounts: list[dict[str, Any]] = []
    for entry_id, coordinator in hass.data.get(DOMAIN, {}).items():
        data = coordinator.data or {}
        meters: list[dict[str, Any]] = []
        for row in data.get("meters") or []:
            if not isinstance(row, dict):
                continue
            meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
            reading = row.get("reading") if isinstance(row.get("reading"), dict) else {}
            key = "|".join(
                str(meter.get(name) or "")
                for name in ("meterId", "meterSequenceNo", "meterNo", "allocationUnit")
            )
            history = (data.get("meter_history_30d") or {}).get(key) or []
            meters.append(
                {
                    "id": str(meter.get("meterId") or meter.get("meterNo") or key),
                    "name": str(
                        meter.get("placement") or meter.get("meterNo") or "Måler"
                    ),
                    "number": str(meter.get("meterNo") or ""),
                    "medium": _medium(meter),
                    "unit": _unit(meter),
                    "value": _number(reading.get("value")),
                    "reading_date": reading.get("readingDate"),
                    "history": [
                        {
                            "date": point.get("date") or point.get("reading_date"),
                            "value": _number(point.get("value")),
                        }
                        for point in history
                        if isinstance(point, dict)
                        and _number(point.get("value")) is not None
                    ],
                }
            )
        accounts.append(
            {
                "entry_id": entry_id,
                "title": getattr(
                    getattr(coordinator, "config_entry", None),
                    "title",
                    "Brunata Online",
                ),
                "available": coordinator.last_update_success,
                "last_update": (
                    coordinator.last_update_success_time.isoformat()
                    if getattr(coordinator, "last_update_success_time", None)
                    else None
                ),
                "meters": meters,
            }
        )
    return {"accounts": accounts}


@websocket_api.websocket_command({vol.Required("type"): "brunata_online/panel_data"})
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_panel_data(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Return the latest coordinator data to a Home Assistant administrator."""
    connection.send_result(msg["id"], build_panel_payload(hass))


@callback
def async_register_websocket(hass: HomeAssistant) -> None:
    """Register panel commands once per Home Assistant process."""
    if hass.data.get(PANEL_WS_REGISTERED):
        return
    websocket_api.async_register_command(hass, websocket_panel_data)
    hass.data[PANEL_WS_REGISTERED] = True
