"""Config flow for Brunata Online."""

from __future__ import annotations

import asyncio
import logging

from aiohttp import ClientError
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import voluptuous as vol

from .api import BrunataAuthError, BrunataOnlineClient
from .const import CONF_PASSWORD, CONF_USERNAME, DOMAIN

_LOGGER = logging.getLogger(__name__)


class BrunataOnlineConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Brunata Online."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    async def async_step_user(self, user_input: dict | None = None):
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME].strip()
            password = user_input[CONF_PASSWORD]

            await self.async_set_unique_id(username.lower())
            self._abort_if_unique_id_configured()

            result = await self._test_credentials(username, password)
            if result == "ok":
                return self.async_create_entry(
                    title=username,
                    data={CONF_USERNAME: username, CONF_PASSWORD: password},
                )
            errors["base"] = result

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def _test_credentials(self, username: str, password: str) -> str:
        try:
            session = async_get_clientsession(self.hass)
            client = BrunataOnlineClient(username, password, session)
            await client.async_fetch_data()
            return "ok"
        except BrunataAuthError as err:
            _LOGGER.warning("Brunata authentication failed: %s", err)
            return "auth"
        except (TimeoutError, asyncio.TimeoutError, ClientError) as err:
            _LOGGER.warning("Brunata connection failed: %r", err)
            return "cannot_connect"
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected Brunata validation error: %s", err)
            return "unknown"

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return BrunataOptionsFlow(config_entry)


class BrunataOptionsFlow(config_entries.OptionsFlow):
    """No options yet."""

    def __init__(self, config_entry) -> None:
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        return self.async_create_entry(title="", data={})
