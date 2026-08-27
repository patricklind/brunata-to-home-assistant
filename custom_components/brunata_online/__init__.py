"""Brunata Online integration for Home Assistant."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import BrunataAuthError, BrunataOnlineClient
from .const import CONF_PASSWORD, CONF_USERNAME, DOMAIN, PLATFORMS, SCAN_INTERVAL
from .identity import migrate_aggregate_unique_id

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

    coordinator = BrunataDataCoordinator(hass, client, entry)
    await coordinator.async_refresh()
    if not coordinator.last_update_success:
        _LOGGER.warning(
            "Initial Brunata refresh failed during setup; integration will retry in "
            "background."
        )

    hass.data[DOMAIN][entry.entry_id] = coordinator

    from .frontend import async_register_panel
    from .panel import async_register_websocket

    await async_register_websocket(hass)
    await async_register_panel(hass)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: BrunataConfigEntry) -> bool:
    """Unload Brunata config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
        if not hass.data.get(DOMAIN):
            from .frontend import async_unregister_panel

            await async_unregister_panel(hass)
    return unload_ok


async def async_migrate_entry(hass: HomeAssistant, entry: BrunataConfigEntry) -> bool:
    """Migrate aggregate entity identities without changing entity IDs."""
    if entry.version > 2:
        return False
    if entry.version < 2:
        registry = er.async_get(hass)
        for entity in er.async_entries_for_config_entry(registry, entry.entry_id):
            new_unique_id = migrate_aggregate_unique_id(
                entry.entry_id, entity.unique_id
            )
            if new_unique_id is not None:
                registry.async_update_entity(
                    entity.entity_id, new_unique_id=new_unique_id
                )
        hass.config_entries.async_update_entry(entry, version=2)
    return True


class BrunataDataCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator for Brunata data updates."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: BrunataOnlineClient,
        config_entry: BrunataConfigEntry,
    ) -> None:
        self.client = client
        # Keep compatibility with the integration's HA 2024.6 minimum while
        # exposing the entry title to the multi-account panel.
        self.config_entry = config_entry
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
            raise ConfigEntryAuthFailed(f"Authentication failed: {err}") from err
        except Exception as err:  # pylint: disable=broad-except
            raise UpdateFailed(f"Failed to update Brunata data: {err}") from err
