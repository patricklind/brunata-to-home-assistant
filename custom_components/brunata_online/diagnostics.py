"""Diagnostics support for Brunata Online."""

from __future__ import annotations

import hashlib
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_PASSWORD, CONF_USERNAME, DOMAIN

TO_REDACT = {CONF_PASSWORD, CONF_USERNAME}


def _anonymous_meter_reference(value: object) -> str:
    """Return a stable, non-reversible reference for diagnostics."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _meter_key(row: dict[str, Any]) -> str:
    """Build the same stable meter identity shape used by the API client."""
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    parts = (
        meter.get("meterId"),
        meter.get("meterSequenceNo"),
        meter.get("meterNo"),
        meter.get("allocationUnit"),
    )
    return "|".join(str(part or "") for part in parts)


def _diagnostic_meter(row: object) -> dict[str, Any] | None:
    """Keep fields needed to diagnose stale values, without meter identity."""
    if not isinstance(row, dict):
        return None
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    reading = row.get("reading") if isinstance(row.get("reading"), dict) else {}
    return {
        "meter_ref": _anonymous_meter_reference(_meter_key(row)),
        "allocation_unit": meter.get("allocationUnit"),
        "meter_type": meter.get("meterType"),
        "unit": meter.get("unit"),
        "mounted_date": meter.get("mountedDate"),
        "dismounted_date": meter.get("dismountedDate"),
        "reading": {
            "value": reading.get("value"),
            "date": reading.get("readingDate"),
            "historical_fallback": bool(reading.get("historicalFallback")),
        },
    }


def _diagnostic_history(history: object) -> list[dict[str, Any]]:
    """Remove raw meter keys while retaining the readings needed for #42."""
    if not isinstance(history, dict):
        return []
    result: list[dict[str, Any]] = []
    for key, points in history.items():
        safe_points = []
        if isinstance(points, list):
            safe_points = [
                {
                    "date": point.get("date"),
                    "reading_date": point.get("reading_date"),
                    "value": point.get("value"),
                }
                for point in points
                if isinstance(point, dict)
            ]
        result.append(
            {
                "meter_ref": _anonymous_meter_reference(key),
                "points": safe_points,
            }
        )
    return result


def _diagnostic_data(data: object) -> dict[str, Any]:
    """Create a privacy-preserving snapshot of coordinator data."""
    if not isinstance(data, dict):
        return {"available": False}

    meters = [
        diagnostic
        for row in data.get("meters", [])
        if (diagnostic := _diagnostic_meter(row)) is not None
    ]
    return {
        "available": True,
        "fetched_at": data.get("fetched_at"),
        "best_startdate": data.get("best_startdate"),
        "non_null_readings": data.get("non_null_readings"),
        "attempts": data.get("attempts", []),
        "meters": meters,
        "meter_history_30d": _diagnostic_history(data.get("meter_history_30d")),
        "meter_history_meta": data.get("meter_history_meta", {}),
    }


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return redacted diagnostics for a config entry."""
    coordinator = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    return {
        "config_entry": async_redact_data(dict(entry.data), TO_REDACT),
        "coordinator": _diagnostic_data(
            coordinator.data if coordinator is not None else None
        ),
    }
