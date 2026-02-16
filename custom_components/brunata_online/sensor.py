"""Sensor platform for Brunata Online.

This integration currently exposes meter "measuring points" as sensors.
Each sensor represents the latest known meter reading (cumulative value).
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass

from .const import DOMAIN, ICON
from .entity import BrunataOnlineEntity

_LOGGER: logging.Logger = logging.getLogger(__package__)


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Brunata Online sensors based on coordinator data."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    points: dict[str, dict[str, Any]] = (coordinator.data or {}).get(
        "measuring_points"
    ) or {}

    entities: list[BrunataMeasuringPointSensor] = [
        BrunataMeasuringPointSensor(coordinator, entry, point_id)
        for point_id in sorted(points)
    ]
    async_add_entities(entities)


def _coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        # The portal UI is locale-dependent; be permissive.
        v = value.strip().replace(" ", "")
        v = v.replace(",", ".")
        try:
            return float(v)
        except ValueError:
            return None
    return None


def _guess_unit(allo_unit_type: str | None) -> str | None:
    if not allo_unit_type:
        return None
    t = allo_unit_type.lower()
    if "water" in t:
        return "m³"
    if "heating" in t:
        # Many Brunata heating meters are cost allocator "units".
        return "units"
    if "electric" in t or "energy" in t or "power" in t:
        return "kWh"
    return None


class BrunataMeasuringPointSensor(BrunataOnlineEntity, SensorEntity):
    """Sensor for a single measuring point (meter reading)."""

    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_icon = ICON

    def __init__(self, coordinator, config_entry, point_id: str) -> None:
        super().__init__(coordinator, config_entry)
        self._point_id = point_id

    def _point(self) -> dict[str, Any] | None:
        data = self.coordinator.data or {}
        points: dict[str, dict[str, Any]] = data.get("measuring_points") or {}
        return points.get(self._point_id)

    @property
    def unique_id(self) -> str:
        return self._point_id

    @property
    def name(self) -> str:
        p = self._point() or {}
        use = p.get("alloUnitType") or "Meter"
        loc = p.get("connectedTo") or p.get("roomId") or p.get("locationNo") or ""
        serial = p.get("serialNo") or ""
        if loc and serial:
            return f"Brunata {use} {loc} ({serial})"
        if serial:
            return f"Brunata {use} ({serial})"
        return f"Brunata {use} {self._point_id}"

    @property
    def native_value(self) -> float | None:
        p = self._point()
        if not p:
            return None
        return _coerce_float(p.get("meterValue"))

    @property
    def native_unit_of_measurement(self) -> str | None:
        p = self._point() or {}
        return _guess_unit(p.get("alloUnitType"))

    @property
    def device_info(self) -> dict[str, Any]:
        p = self._point() or {}
        building_no = p.get("_buildingNo")
        buildings: dict[str, dict[str, Any]] = (self.coordinator.data or {}).get(
            "buildings"
        ) or {}
        building = buildings.get(str(building_no)) if building_no is not None else None

        # One device per building (if known), else fall back to config entry.
        if building_no is not None:
            name = building.get("buildingName") if isinstance(building, dict) else None
            return {
                "identifiers": {(DOMAIN, str(building_no))},
                "name": name or f"Brunata Building {building_no}",
                "manufacturer": "Brunata",
                "model": "Brunata Online",
            }

        return super().device_info

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs = dict(super().extra_state_attributes or {})
        p = self._point() or {}
        attrs.update(
            {
                "building_no": p.get("_buildingNo"),
                "serial_no": p.get("serialNo"),
                "printed_serial_no": p.get("printedSerialNo"),
                "connected_to": p.get("connectedTo"),
                "allo_unit_type": p.get("alloUnitType"),
                "reading_date": p.get("readingDate"),
                "mounting_date": p.get("mountingDate"),
                "dismounted_date": p.get("dismountedDate"),
                "meter_sequence_no": p.get("meterSequenceNo"),
                "property_no": p.get("propertyNo"),
                "branch_no": p.get("branchNo"),
                "location_no": p.get("locationNo"),
                "raw_unit": p.get("unit"),
            }
        )
        return attrs
