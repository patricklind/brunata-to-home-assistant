"""Pure helpers for normalizing and aggregating Brunata meter data."""

from __future__ import annotations

from typing import Any


def normalize_reading_value(value: Any) -> float | int | None:
    """Normalize a Brunata reading into a Home Assistant numeric value."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip().replace(" ", "")
        if not text:
            return None
        if "," in text and "." in text:
            if text.rfind(",") > text.rfind("."):
                text = text.replace(".", "").replace(",", ".")
            else:
                text = text.replace(",", "")
        elif "," in text:
            text = text.replace(",", ".")
        try:
            return float(text)
        except ValueError:
            return None
    return None


def row_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Build the stable key shared by current rows and history points."""
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    return (
        str(meter.get("meterId") or ""),
        str(meter.get("meterSequenceNo") or ""),
        str(meter.get("meterNo") or ""),
        str(meter.get("allocationUnit") or ""),
    )


def history_key(meter_key: tuple[str, str, str, str]) -> str:
    """Convert a row key to the serialized API history key."""
    return "|".join(meter_key)


def history_points_for_meter(
    coordinator_data: dict[str, Any] | None,
    meter_key: tuple[str, str, str, str],
) -> list[dict[str, Any]]:
    """Return valid history point objects for one meter."""
    history = (coordinator_data or {}).get("meter_history_30d")
    if not isinstance(history, dict):
        return []
    points = history.get(history_key(meter_key))
    if not isinstance(points, list):
        return []
    return [point for point in points if isinstance(point, dict)]


def latest_history_value(points: list[dict[str, Any]]) -> float | int | None:
    """Return the newest usable cumulative value from meter history."""
    for point in reversed(points):
        value = normalize_reading_value(point.get("value"))
        if value is not None:
            return value
    return None


def current_or_history_value(
    coordinator_data: dict[str, Any] | None, row: dict[str, Any]
) -> float | int | None:
    """Prefer a current reading, falling back to its historical total."""
    reading = row.get("reading") if isinstance(row.get("reading"), dict) else {}
    current_value = normalize_reading_value(reading.get("value"))
    if current_value is not None:
        return current_value

    points = history_points_for_meter(coordinator_data, row_key(row))
    return latest_history_value(points)


def sum_current_values(
    coordinator_data: dict[str, Any] | None, rows: list[dict[str, Any]]
) -> float | None:
    """Sum all available current or historical meter totals."""
    values = [current_or_history_value(coordinator_data, row) for row in rows]
    numeric_values = [float(value) for value in values if value is not None]
    return round(sum(numeric_values), 3) if numeric_values else None
