"""WebSocket data source for the Brunata Online panel."""

from __future__ import annotations

import math
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import DOMAIN

PANEL_WS_REGISTERED = "brunata_online_panel_ws_registered"
PANEL_SETTINGS_DATA = "brunata_online_panel_settings"
PANEL_SETTINGS_STORE = "brunata_online_panel_settings_store"
PANEL_SETTINGS_STORAGE_KEY = "brunata_online.panel_settings"
DEFAULT_PANEL_SETTINGS: dict[str, Any] = {
    "period": 30,
    "precision": 2,
    "currency": "EUR",
    "waterPrice": 0.0,
    "heatingPrice": 0.0,
}


def _number(value: Any) -> float | None:
    """Convert Brunata's localized numeric values for the frontend."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
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
        number = float(text)
        return number if math.isfinite(number) else None
    except ValueError:
        return None


def normalize_panel_settings(value: Any) -> dict[str, Any]:
    """Validate persisted or WebSocket-provided display settings."""
    source = value if isinstance(value, dict) else {}
    period = 7 if _number(source.get("period")) == 7 else 30
    precision_value = _number(source.get("precision"))
    precision = round(precision_value) if precision_value is not None else 2
    precision = min(3, max(0, precision))
    currency = str(source.get("currency") or "").upper()
    if not currency.isascii() or not currency.isalpha() or len(currency) != 3:
        currency = "EUR"

    def price(name: str) -> float:
        parsed = _number(source.get(name))
        return max(0.0, parsed) if parsed is not None else 0.0

    return {
        "period": period,
        "precision": precision,
        "currency": currency,
        "waterPrice": price("waterPrice"),
        "heatingPrice": price("heatingPrice"),
    }


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
    return {
        "accounts": accounts,
        "settings": dict(hass.data.get(PANEL_SETTINGS_DATA, DEFAULT_PANEL_SETTINGS)),
    }


@websocket_api.websocket_command({vol.Required("type"): "brunata_online/panel_data"})
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_panel_data(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Return the latest coordinator data to a Home Assistant administrator."""
    connection.send_result(msg["id"], build_panel_payload(hass))


@websocket_api.websocket_command(
    {
        vol.Required("type"): "brunata_online/panel_settings/update",
        vol.Required("settings"): dict,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_update_panel_settings(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Validate and persist shared panel settings."""
    settings = normalize_panel_settings(msg["settings"])
    store: Store = hass.data[PANEL_SETTINGS_STORE]
    await store.async_save(settings)
    hass.data[PANEL_SETTINGS_DATA] = settings
    connection.send_result(msg["id"], {"settings": settings})


async def async_register_websocket(hass: HomeAssistant) -> None:
    """Register panel commands once per Home Assistant process."""
    if hass.data.get(PANEL_WS_REGISTERED):
        return
    store = Store(hass, 1, PANEL_SETTINGS_STORAGE_KEY)
    hass.data[PANEL_SETTINGS_STORE] = store
    hass.data[PANEL_SETTINGS_DATA] = normalize_panel_settings(await store.async_load())
    websocket_api.async_register_command(hass, websocket_panel_data)
    websocket_api.async_register_command(hass, websocket_update_panel_settings)
    hass.data[PANEL_WS_REGISTERED] = True
