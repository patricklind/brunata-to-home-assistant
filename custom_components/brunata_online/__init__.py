"""Brunata Online integration for Home Assistant."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry, ConfigEntryAuthFailed
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import BrunataAuthError, BrunataOnlineClient
from .const import CONF_PASSWORD, CONF_USERNAME, DOMAIN, PLATFORMS, SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)


type BrunataConfigEntry = ConfigEntry

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Set up integration via YAML (not used)."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: BrunataConfigEntry) -> bool:
    """Set up Brunata from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    session = async_get_clientsession(hass)
    client = BrunataOnlineClient(
        entry.data[CONF_USERNAME],
        entry.data[CONF_PASSWORD],
        session,
    )

    coordinator = BrunataDataCoordinator(hass, client)
    # Let Home Assistant distinguish temporary startup failures (which are
    # retried as ConfigEntryNotReady) from invalid credentials. Continuing with
    # an empty coordinator makes setup appear successful while exposing no
    # entities and prevents Home Assistant's normal repair flow from running.
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: BrunataConfigEntry) -> bool:
    """Unload Brunata config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    return unload_ok


class BrunataDataCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator for Brunata data updates."""

    def __init__(self, hass: HomeAssistant, client: BrunataOnlineClient) -> None:
        self.client = client
        super().__init__(
            hass,
            logger=_LOGGER,
            name=DOMAIN,
            update_interval=SCAN_INTERVAL,
        )

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            return await self.client.async_fetch_data()
        except BrunataAuthError as err:
            raise ConfigEntryAuthFailed(
                "Brunata credentials are no longer valid"
            ) from err
        except Exception as err:  # pylint: disable=broad-except
            raise UpdateFailed(f"Failed to update Brunata data: {err}") from err
