"""Sensor entities for Brunata Online."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from . import BrunataDataCoordinator
from .const import DOMAIN

WATER_CONSUMPTION_WINDOWS_DAYS: tuple[int, ...] = (1, 7, 14, 30)
HEATING_CONSUMPTION_WINDOWS_DAYS: tuple[int, ...] = (30,)


def _meter_medium_label(meter_type: Any, allocation_unit: Any) -> str:
    """Map Brunata meter type text to a stable medium label."""
    meter_type_text = str(meter_type).strip().lower() if meter_type is not None else ""
    allocation_unit_text = (
        str(allocation_unit).strip().lower() if allocation_unit is not None else ""
    )

    # Allocation units are the most stable discriminator in Brunata payloads.
    if allocation_unit_text == "k":
        return "cold_water"
    if allocation_unit_text == "w":
        return "hot_water"
    if allocation_unit_text == "o":
        return "heating"

    if "cold water" in meter_type_text or "koldt vand" in meter_type_text:
        return "cold_water"
    if "hot water" in meter_type_text or "varmt vand" in meter_type_text:
        return "hot_water"
    if "heating" in meter_type_text or "opvarmning" in meter_type_text:
        return "heating"
    if meter_type_text == "1":
        return "heating"
    if meter_type_text == "2":
        return "water"

    if "water" in meter_type_text or "vand" in meter_type_text:
        return "water"
    return "unknown"


def _meter_sensor_name(medium: str) -> str:
    """User-facing sensor name based on classified meter medium."""
    return {
        "cold_water": "Cold water",
        "hot_water": "Hot water",
        "heating": "Heating",
        "water": "Water",
    }.get(medium, "Reading")


def _meter_device_name(medium: str, native_unit: str | None, placement: str) -> str:
    """User-facing device name for meter hardware."""
    if medium == "hot_water":
        base = "Water meter (Hot water)"
    elif medium == "cold_water":
        base = "Water meter (Cold water)"
    elif medium == "water":
        base = "Water meter"
    elif medium == "heating" and native_unit == "units":
        base = "Radiator meter (Heating)"
    elif medium == "heating":
        base = "Heat meter (Heating energy)"
    else:
        base = "Meter"

    place = placement.strip()
    return f"{base} - {place}" if place else base


def _is_water_medium(medium: str) -> bool:
    return medium in {"cold_water", "hot_water", "water"}


def _is_heating_medium(medium: str) -> bool:
    return medium == "heating"


def _unit_from_code(unit_code: Any) -> str | None:
    code = str(unit_code).strip() if unit_code is not None else ""
    if code == "8":
        return "m³"
    if code in {"1", "2", "3"}:
        return "units"
    if code in {"4", "9"}:
        return "kWh"
    return None


def _heating_format(medium: str, native_unit: str | None) -> str | None:
    if medium != "heating":
        return None
    return "energy_kwh" if native_unit == "kWh" else "index_units"


def _normalize_reading_value(value: Any) -> float | int | None:
    """Normalize Brunata reading values to numeric values for statistics."""
    if value is None:
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
            # Brunata may return decimal-comma values for water readings.
            text = text.replace(",", ".")
        try:
            return float(text)
        except ValueError:
            return None
    return None


def _parse_reading_datetime(value: Any) -> datetime | None:
    """Parse Brunata reading timestamp to aware UTC datetime."""
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _extract_official_point(
    row: dict[str, Any] | None,
) -> tuple[datetime, float] | None:
    """Extract (reading_date, reading_value) for interpolation."""
    if not isinstance(row, dict):
        return None

    reading = row.get("reading")
    if not isinstance(reading, dict):
        return None

    reading_value = _normalize_reading_value(reading.get("value"))
    reading_date = _parse_reading_datetime(reading.get("readingDate"))

    if reading_value is None or reading_date is None:
        return None
    return reading_date, float(reading_value)


def _supports_distributed_sensor(row: dict[str, Any]) -> bool:
    """Only water/heating meters get distributed-estimate helper sensors."""
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    medium = _meter_medium_label(meter.get("meterType"), meter.get("allocationUnit"))
    unit = _unit_from_code(meter.get("unit"))
    if medium not in {"cold_water", "hot_water", "water", "heating"}:
        return False
    return unit in {"m³", "kWh", "units"}


def _supports_30d_consumption_sensor(row: dict[str, Any]) -> bool:
    """Only known water/heating meters get rolling 30-day sensors."""
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    medium = _meter_medium_label(meter.get("meterType"), meter.get("allocationUnit"))
    unit = _unit_from_code(meter.get("unit"))
    if medium not in {"cold_water", "hot_water", "water", "heating"}:
        return False
    return unit in {"m³", "kWh", "units"}


def _row_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    return (
        str(meter.get("meterId") or ""),
        str(meter.get("meterSequenceNo") or ""),
        str(meter.get("meterNo") or ""),
        str(meter.get("allocationUnit") or ""),
    )


def _history_key_from_row_key(meter_key: tuple[str, str, str, str]) -> str:
    return "|".join(meter_key)


def _history_points_for_meter(
    coordinator_data: dict[str, Any] | None,
    meter_key: tuple[str, str, str, str],
) -> list[dict[str, Any]]:
    history = (coordinator_data or {}).get("meter_history_30d")
    if not isinstance(history, dict):
        return []
    points = history.get(_history_key_from_row_key(meter_key))
    if not isinstance(points, list):
        return []
    return [point for point in points if isinstance(point, dict)]


def _history_delta(points: list[dict[str, Any]]) -> float | None:
    if len(points) < 2:
        return None
    first_value = _normalize_reading_value(points[0].get("value"))
    last_value = _normalize_reading_value(points[-1].get("value"))
    if first_value is None or last_value is None:
        return None
    delta = float(last_value) - float(first_value)
    if delta < 0:
        return None
    return round(delta, 3)


def _window_label(days: int) -> str:
    return "1 day" if days == 1 else f"{days} days"


def _history_point_effective_date(point: dict[str, Any]) -> date | None:
    """Map Brunata history point to the usage day.

    Brunata readings are commonly stamped around 01:00 for the previous day.
    """
    reading_dt = _parse_reading_datetime(point.get("reading_date"))
    if reading_dt is not None:
        effective = reading_dt.date()
        if reading_dt.hour <= 2:
            effective -= timedelta(days=1)
        return effective

    point_date_text = str(point.get("date") or "").strip()
    if not point_date_text:
        return None
    try:
        return date.fromisoformat(point_date_text)
    except ValueError:
        return None


def _history_window_stats(
    points: list[dict[str, Any]], window_days: int
) -> dict[str, Any] | None:
    """Return consumption stats for a rolling window."""
    if len(points) < 2:
        return None

    parsed: list[tuple[date, float]] = []
    for point in points:
        point_date = _history_point_effective_date(point)
        point_value = _normalize_reading_value(point.get("value"))
        if point_date is None or point_value is None:
            continue
        parsed.append((point_date, float(point_value)))

    if len(parsed) < 2:
        return None

    parsed.sort(key=lambda item: item[0])
    end_date, end_value = parsed[-1]
    target_date = end_date - timedelta(days=window_days)

    anchor: tuple[date, float] | None = None
    for point_date, point_value in reversed(parsed[:-1]):
        if point_date <= target_date:
            anchor = (point_date, point_value)
            break

    if anchor is None:
        anchor = parsed[0]

    start_date, start_value = anchor
    if start_date >= end_date:
        return None

    delta = end_value - start_value
    if delta < 0:
        return None

    return {
        "delta": round(delta, 3),
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "start_value": start_value,
        "end_value": end_value,
        "actual_window_days": (end_date - start_date).days,
    }


def _consumption_windows_for_row(row: dict[str, Any]) -> tuple[int, ...]:
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    medium = _meter_medium_label(meter.get("meterType"), meter.get("allocationUnit"))
    if _is_water_medium(medium):
        return WATER_CONSUMPTION_WINDOWS_DAYS
    if _is_heating_medium(medium):
        return HEATING_CONSUMPTION_WINDOWS_DAYS
    return ()


def _all_meter_rows(coordinator_data: dict[str, Any] | None) -> list[dict[str, Any]]:
    rows = (coordinator_data or {}).get("meters")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _rows_for_mediums(
    coordinator_data: dict[str, Any] | None, mediums: set[str]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in _all_meter_rows(coordinator_data):
        meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
        medium = _meter_medium_label(
            meter.get("meterType"), meter.get("allocationUnit")
        )
        if medium in mediums:
            result.append(row)
    return result


def _sum_current_values(rows: list[dict[str, Any]]) -> float | None:
    total = 0.0
    count = 0
    for row in rows:
        reading = row.get("reading") if isinstance(row.get("reading"), dict) else {}
        value = _normalize_reading_value(reading.get("value"))
        if value is None:
            continue
        total += float(value)
        count += 1
    if count == 0:
        return None
    return round(total, 3)


def _sum_window_deltas(
    coordinator_data: dict[str, Any] | None,
    rows: list[dict[str, Any]],
    window_days: int,
) -> float | None:
    total = 0.0
    count = 0
    for row in rows:
        meter_key = _row_key(row)
        points = _history_points_for_meter(coordinator_data, meter_key)
        stats = _history_window_stats(points, window_days)
        if not stats:
            continue
        total += float(stats["delta"])
        count += 1
    if count == 0:
        return None
    return round(total, 3)


def _row_serial(row: dict[str, Any]) -> str | None:
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    serial = meter.get("serialNumber") or meter.get("serialNo") or meter.get("meterNo")
    if serial is None:
        return None
    serial_text = str(serial).strip()
    return serial_text or None


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Brunata sensors from config entry."""
    coordinator: BrunataDataCoordinator = hass.data[DOMAIN][entry.entry_id]

    known_sensors: set[str] = set()

    def _add_new_entities() -> None:
        meters = (coordinator.data or {}).get("meters") or []
        new_entities: list[SensorEntity] = []
        for row in meters:
            if not isinstance(row, dict):
                continue
            key = _row_key(row)
            meter_id = _history_key_from_row_key(key)
            raw_token = f"{meter_id}|raw"
            if raw_token not in known_sensors:
                known_sensors.add(raw_token)
                new_entities.append(BrunataMeterSensor(coordinator, key))

            distributed_token = f"{meter_id}|distributed"
            if distributed_token not in known_sensors and _supports_distributed_sensor(
                row
            ):
                known_sensors.add(distributed_token)
                new_entities.append(BrunataDistributedMeterSensor(coordinator, key))

            if _supports_30d_consumption_sensor(row):
                for window_days in _consumption_windows_for_row(row):
                    last_days_token = f"{meter_id}|last_{window_days}_days"
                    if last_days_token in known_sensors:
                        continue
                    known_sensors.add(last_days_token)
                    new_entities.append(
                        BrunataLastDaysConsumptionSensor(coordinator, key, window_days)
                    )

        aggregate_definitions = (
            ("water_total", {"cold_water", "hot_water", "water"}),
            ("water_cold_total", {"cold_water"}),
            ("water_hot_total", {"hot_water"}),
        )
        for aggregate_key, mediums in aggregate_definitions:
            if not _rows_for_mediums(coordinator.data, mediums):
                continue

            total_token = f"aggregate|{aggregate_key}|total"
            if total_token not in known_sensors:
                known_sensors.add(total_token)
                new_entities.append(
                    BrunataAggregateWaterTotalSensor(
                        coordinator, aggregate_key, mediums
                    )
                )

            for window_days in WATER_CONSUMPTION_WINDOWS_DAYS:
                last_days_token = f"aggregate|{aggregate_key}|last_{window_days}_days"
                if last_days_token in known_sensors:
                    continue
                known_sensors.add(last_days_token)
                new_entities.append(
                    BrunataAggregateWaterLastDaysSensor(
                        coordinator, aggregate_key, mediums, window_days
                    )
                )

        if new_entities:
            async_add_entities(new_entities)

    _add_new_entities()
    entry.async_on_unload(coordinator.async_add_listener(_add_new_entities))


class BrunataMeterSensor(CoordinatorEntity[BrunataDataCoordinator], SensorEntity):
    """Representation of a Brunata meter reading."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: BrunataDataCoordinator,
        meter_key: tuple[str, str, str, str],
    ) -> None:
        super().__init__(coordinator)
        self._meter_key = meter_key

        row = self._current_row
        meter = row.get("meter", {}) if row else {}
        meter_no = meter.get("meterNo") or meter_key[2]
        self._meter_identifier = str(
            meter.get("meterId") or meter_key[0] or meter_no or meter_key[1]
        )
        self._meter_no = str(meter_no or self._meter_identifier)
        self._meter_serial = str(
            meter.get("serialNumber")
            or meter.get("serialNo")
            or meter.get("meterNo")
            or self._meter_identifier
        )
        self._placement = str(meter.get("placement") or "Meter")
        self._meter_medium = _meter_medium_label(
            meter.get("meterType"),
            meter.get("allocationUnit"),
        )
        self._unit_code = meter.get("unit")
        self._native_unit = _unit_from_code(self._unit_code)
        self._device_name = _meter_device_name(
            self._meter_medium,
            self._native_unit,
            self._placement,
        )

        self._attr_unique_id = (
            f"{DOMAIN}_{meter_key[0]}_{meter_key[1]}_{meter_key[2]}_{meter_key[3]}"
        )
        if _is_heating_medium(self._meter_medium):
            self._attr_name = (
                "Heating energy" if self._native_unit == "kWh" else "Heating index"
            )
        else:
            self._attr_name = _meter_sensor_name(self._meter_medium)

    @property
    def _current_row(self) -> dict[str, Any] | None:
        meters = (self.coordinator.data or {}).get("meters") or []
        for row in meters:
            if isinstance(row, dict) and _row_key(row) == self._meter_key:
                return row
        return None

    @property
    def available(self) -> bool:
        return super().available and self._current_row is not None

    @property
    def native_value(self):
        row = self._current_row
        if not row:
            return None
        reading = row.get("reading") if isinstance(row.get("reading"), dict) else {}
        return _normalize_reading_value(reading.get("value"))

    @property
    def native_unit_of_measurement(self) -> str | None:
        return self._native_unit

    @property
    def device_class(self) -> SensorDeviceClass | None:
        if _is_water_medium(self._meter_medium):
            return SensorDeviceClass.WATER
        if _is_heating_medium(self._meter_medium) and self._native_unit == "kWh":
            return SensorDeviceClass.ENERGY
        return None

    @property
    def state_class(self) -> SensorStateClass | None:
        if _is_water_medium(self._meter_medium):
            return SensorStateClass.TOTAL_INCREASING
        if _is_heating_medium(self._meter_medium):
            return SensorStateClass.TOTAL_INCREASING
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        row = self._current_row
        if not row:
            return {}

        meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
        reading = row.get("reading") if isinstance(row.get("reading"), dict) else {}
        history_points = _history_points_for_meter(
            self.coordinator.data, self._meter_key
        )
        history_stats_30d = _history_window_stats(history_points, 30)
        history_meta = (self.coordinator.data or {}).get("meter_history_meta")
        history_updated_at = (
            history_meta.get("updated_at") if isinstance(history_meta, dict) else None
        )

        attrs = {
            "meter_id": meter.get("meterId"),
            "meter_no": meter.get("meterNo"),
            "serial_number": self._meter_serial,
            "meter_sequence_no": meter.get("meterSequenceNo"),
            "placement": meter.get("placement"),
            "meter_type": meter.get("meterType"),
            "meter_medium": _meter_medium_label(
                str(meter.get("meterType") or ""),
                str(meter.get("allocationUnit") or ""),
            ),
            "heating_format": _heating_format(self._meter_medium, self._native_unit),
            "allocation_unit": meter.get("allocationUnit"),
            "unit_code": meter.get("unit"),
            "mounting_date": meter.get("mountingDate"),
            "dismounted_date": meter.get("dismountedDate"),
            "reading_id": reading.get("readingId"),
            "reading_date": reading.get("readingDate"),
            "best_startdate": (self.coordinator.data or {}).get("best_startdate"),
            "history_30d_points": history_points,
            "history_30d_point_count": len(history_points),
            "history_30d_updated_at": history_updated_at,
        }
        if history_stats_30d is not None:
            attrs["consumption_last_30_days"] = history_stats_30d["delta"]
        return attrs

    @property
    def device_info(self) -> DeviceInfo:
        row = self._current_row
        meter = (
            row.get("meter")
            if isinstance(row, dict) and isinstance(row.get("meter"), dict)
            else {}
        )
        meter_type = str(meter.get("meterType") or "Meter")

        return DeviceInfo(
            identifiers={(DOMAIN, f"meter_{self._meter_identifier}")},
            manufacturer="Brunata",
            model=meter_type,
            name=self._device_name,
            serial_number=self._meter_serial,
        )


class BrunataDistributedMeterSensor(BrunataMeterSensor):
    """Estimated distributed total between Brunata daily meter updates."""

    def __init__(
        self,
        coordinator: BrunataDataCoordinator,
        meter_key: tuple[str, str, str, str],
    ) -> None:
        super().__init__(coordinator, meter_key)
        self._attr_unique_id = f"{self._attr_unique_id}_distributed"
        medium_label = _meter_sensor_name(self._meter_medium)
        self._attr_name = f"{medium_label} distributed total"

        self._official_point: tuple[datetime, float] | None = None
        self._anchor_time: datetime | None = None
        self._anchor_value: float | None = None
        self._rate_per_second: float = 0.0

        self._ingest_official_row(self._current_row)

    def _ingest_official_row(self, row: dict[str, Any] | None) -> None:
        point = _extract_official_point(row)
        if point is None:
            return

        if self._official_point is None:
            self._official_point = point
            self._anchor_time, self._anchor_value = point
            self._rate_per_second = 0.0
            return

        prev_time, prev_value = self._official_point
        current_time, current_value = point
        if current_time <= prev_time:
            return

        self._official_point = point
        self._anchor_time = current_time
        self._anchor_value = current_value

        elapsed_seconds = (current_time - prev_time).total_seconds()
        value_delta = current_value - prev_value
        if elapsed_seconds <= 0 or value_delta < 0:
            self._rate_per_second = 0.0
            return

        self._rate_per_second = value_delta / elapsed_seconds

    def _round_estimate(self, value: float) -> float:
        if self._native_unit in {"m³", "kWh"}:
            return round(value, 3)
        return round(value, 2)

    @property
    def native_value(self):
        if self._anchor_value is None or self._anchor_time is None:
            return super().native_value

        if self._rate_per_second <= 0:
            return self._round_estimate(self._anchor_value)

        now = dt_util.utcnow()
        elapsed_seconds = max((now - self._anchor_time).total_seconds(), 0.0)
        estimated_total = self._anchor_value + (self._rate_per_second * elapsed_seconds)
        if estimated_total < self._anchor_value:
            estimated_total = self._anchor_value
        return self._round_estimate(estimated_total)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs = dict(super().extra_state_attributes)
        attrs.update(
            {
                "distributed_estimate": True,
                "distribution_rate_per_hour": round(self._rate_per_second * 3600, 6),
                "distribution_anchor_time": (
                    self._anchor_time.isoformat() if self._anchor_time else None
                ),
                "distribution_anchor_value": self._anchor_value,
            }
        )
        return attrs

    @property
    def state_class(self) -> SensorStateClass | None:
        if _is_water_medium(self._meter_medium):
            return SensorStateClass.TOTAL_INCREASING
        if _is_heating_medium(self._meter_medium):
            return SensorStateClass.TOTAL_INCREASING
        return None

    def _handle_coordinator_update(self) -> None:
        self._ingest_official_row(self._current_row)
        super()._handle_coordinator_update()


class BrunataLastDaysConsumptionSensor(BrunataMeterSensor):
    """Rolling N-day consumption based on Brunata daily points."""

    def __init__(
        self,
        coordinator: BrunataDataCoordinator,
        meter_key: tuple[str, str, str, str],
        window_days: int,
    ) -> None:
        super().__init__(coordinator, meter_key)
        self._window_days = window_days
        self._attr_unique_id = f"{self._attr_unique_id}_last_{window_days}_days"

        if _is_heating_medium(self._meter_medium):
            label = "Heating energy" if self._native_unit == "kWh" else "Heating index"
        else:
            label = _meter_sensor_name(self._meter_medium)
        self._attr_name = f"{label} last {_window_label(window_days)}"

    @property
    def native_value(self):
        points = _history_points_for_meter(self.coordinator.data, self._meter_key)
        stats = _history_window_stats(points, self._window_days)
        return stats["delta"] if stats else None

    @property
    def state_class(self) -> SensorStateClass | None:
        return SensorStateClass.MEASUREMENT

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs = dict(super().extra_state_attributes)
        points = _history_points_for_meter(self.coordinator.data, self._meter_key)
        stats = _history_window_stats(points, self._window_days)
        attrs.update(
            {
                "history_window_days": self._window_days,
                "history_point_count": len(points),
                "history_start_date": stats["start_date"] if stats else None,
                "history_end_date": stats["end_date"] if stats else None,
                "history_start_value": stats["start_value"] if stats else None,
                "history_end_value": stats["end_value"] if stats else None,
                "history_actual_window_days": (
                    stats["actual_window_days"] if stats else None
                ),
            }
        )
        return attrs


class _BrunataAggregateWaterBase(
    CoordinatorEntity[BrunataDataCoordinator], SensorEntity
):
    """Base class for aggregate water sensors."""

    _attr_has_entity_name = True
    _attr_native_unit_of_measurement = "m³"
    _attr_device_class = SensorDeviceClass.WATER

    def __init__(
        self,
        coordinator: BrunataDataCoordinator,
        scope_key: str,
        mediums: set[str],
    ) -> None:
        super().__init__(coordinator)
        self._scope_key = scope_key
        self._mediums = mediums

    @property
    def _rows(self) -> list[dict[str, Any]]:
        return _rows_for_mediums(self.coordinator.data, self._mediums)

    @property
    def available(self) -> bool:
        return super().available and bool(self._rows)

    @property
    def _scope_label(self) -> str:
        if self._scope_key == "water_hot_total":
            return "Hot water"
        if self._scope_key == "water_cold_total":
            return "Cold water"
        return "Water"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, f"aggregate_{self._scope_key}")},
            manufacturer="Brunata",
            model="Virtual aggregate",
            name=f"Brunata {self._scope_label} aggregate",
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        rows = self._rows
        serials = [serial for serial in (_row_serial(row) for row in rows) if serial]
        return {
            "meter_mediums": sorted(self._mediums),
            "source_meter_count": len(rows),
            "source_meter_serials": serials,
        }


class BrunataAggregateWaterTotalSensor(_BrunataAggregateWaterBase):
    """Aggregate total water sensor for Energy/Water dashboard."""

    _attr_state_class = SensorStateClass.TOTAL_INCREASING

    def __init__(
        self,
        coordinator: BrunataDataCoordinator,
        scope_key: str,
        mediums: set[str],
    ) -> None:
        super().__init__(coordinator, scope_key, mediums)
        self._attr_unique_id = f"{DOMAIN}_{scope_key}"
        self._attr_name = f"Brunata {self._scope_label} total"

    @property
    def native_value(self):
        return _sum_current_values(self._rows)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs = dict(super().extra_state_attributes)
        attrs["recommended_for_energy_water_dashboard"] = True
        return attrs


class BrunataAggregateWaterLastDaysSensor(_BrunataAggregateWaterBase):
    """Aggregate N-day water consumption for overview cards."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: BrunataDataCoordinator,
        scope_key: str,
        mediums: set[str],
        window_days: int,
    ) -> None:
        super().__init__(coordinator, scope_key, mediums)
        self._window_days = window_days
        self._attr_unique_id = f"{DOMAIN}_{scope_key}_last_{window_days}_days"
        self._attr_name = (
            f"Brunata {self._scope_label} last {_window_label(window_days)}"
        )

    @property
    def native_value(self):
        return _sum_window_deltas(self.coordinator.data, self._rows, self._window_days)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs = dict(super().extra_state_attributes)
        attrs.update(
            {
                "history_window_days": self._window_days,
                "recommended_for_energy_water_dashboard": False,
            }
        )
        return attrs
