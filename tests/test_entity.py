"""Tests for Brunata Online entity."""

from __future__ import annotations

from datetime import timedelta
import logging
from unittest.mock import AsyncMock

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.brunata_online.const import DOMAIN
from custom_components.brunata_online.entity import BrunataOnlineEntity


class _TestEntity(BrunataOnlineEntity):
    """Concrete test entity."""


async def test_extra_state_attributes_handles_missing_data(hass):
    """Entity attributes should be safe when coordinator data is None."""
    coordinator = DataUpdateCoordinator(
        hass,
        logging.getLogger(__name__),
        name="test",
        update_method=AsyncMock(return_value={}),
        update_interval=timedelta(minutes=5),
    )
    coordinator.data = None

    config_entry = MockConfigEntry(
        domain=DOMAIN,
        data={"username": "user", "password": "pass"},
        entry_id="test_entry",
    )
    entity = _TestEntity(coordinator, config_entry)

    attrs = entity.extra_state_attributes
    assert attrs["fetched_at"] is None
    assert attrs["date"] is None
    assert attrs["integration"] == DOMAIN
