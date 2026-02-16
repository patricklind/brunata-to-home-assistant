"""Sensor entities for Brunata Online."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import BrunataDataCoordinator
from .const import DOMAIN


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


def _is_water_medium(medium: str) -> bool:
    return medium in {"cold_water", "hot_water", "water"}


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


def _row_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    return (
        str(meter.get("meterId") or ""),
        str(meter.get("meterSequenceNo") or ""),
        str(meter.get("meterNo") or ""),
        str(meter.get("allocationUnit") or ""),
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Brunata sensors from config entry."""
    coordinator: BrunataDataCoordinator = hass.data[DOMAIN][entry.entry_id]

    known_keys: set[tuple[str, str, str, str]] = set()

    def _add_new_entities() -> None:
        meters = (coordinator.data or {}).get("meters") or []
        new_entities: list[BrunataMeterSensor] = []
        for row in meters:
            if not isinstance(row, dict):
                continue
            key = _row_key(row)
            if key in known_keys:
                continue
            known_keys.add(key)
            new_entities.append(BrunataMeterSensor(coordinator, key))

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

        self._attr_unique_id = (
            f"{DOMAIN}_{meter_key[0]}_{meter_key[1]}_{meter_key[2]}_{meter_key[3]}"
        )
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
        row = self._current_row
        if not row:
            return None

        meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
        unit_code = str(meter.get("unit") or "")

        if unit_code == "8":
            return "m³"
        if unit_code in {"1", "2", "3"}:
            return "units"
        if unit_code in {"4", "9"}:
            return "kWh"
        return None

    @property
    def device_class(self) -> SensorDeviceClass | None:
        if _is_water_medium(self._meter_medium):
            return SensorDeviceClass.WATER
        return None

    @property
    def state_class(self) -> SensorStateClass | None:
        if _is_water_medium(self._meter_medium):
            return SensorStateClass.TOTAL_INCREASING
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        row = self._current_row
        if not row:
            return {}

        meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
        reading = row.get("reading") if isinstance(row.get("reading"), dict) else {}

        return {
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
            "allocation_unit": meter.get("allocationUnit"),
            "unit_code": meter.get("unit"),
            "mounting_date": meter.get("mountingDate"),
            "dismounted_date": meter.get("dismountedDate"),
            "reading_id": reading.get("readingId"),
            "reading_date": reading.get("readingDate"),
            "best_startdate": (self.coordinator.data or {}).get("best_startdate"),
        }

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
            name=(
                f"{self._placement} {self._meter_no} "
                f"({_meter_sensor_name(self._meter_medium)})"
            ).strip(),
            serial_number=self._meter_serial,
        )
