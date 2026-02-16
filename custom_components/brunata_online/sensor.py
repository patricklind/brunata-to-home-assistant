"""Sensor entities for Brunata Online."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import BrunataDataCoordinator
from .const import DOMAIN


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
        placement = meter.get("placement") or "Meter"

        self._attr_unique_id = (
            f"{DOMAIN}_{meter_key[0]}_{meter_key[1]}_{meter_key[2]}_{meter_key[3]}"
        )
        self._attr_name = f"{placement} {meter_no}".strip()

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
        return reading.get("value")

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
    def extra_state_attributes(self) -> dict[str, Any]:
        row = self._current_row
        if not row:
            return {}

        meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
        reading = row.get("reading") if isinstance(row.get("reading"), dict) else {}

        return {
            "meter_id": meter.get("meterId"),
            "meter_no": meter.get("meterNo"),
            "meter_sequence_no": meter.get("meterSequenceNo"),
            "placement": meter.get("placement"),
            "meter_type": meter.get("meterType"),
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
        consumer = (self.coordinator.data or {}).get("consumer") or {}
        consumer_name = (
            consumer.get("consumerName") if isinstance(consumer, dict) else None
        )
        building_no = consumer.get("buildingNo") if isinstance(consumer, dict) else None

        return DeviceInfo(
            identifiers={(DOMAIN, f"consumer_{building_no}_{consumer_name}")},
            manufacturer="Brunata",
            model="Online",
            name=consumer_name or "Brunata Consumer",
        )
