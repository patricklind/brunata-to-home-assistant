"""Regression tests for Brunata credential reauthentication."""

from __future__ import annotations

from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).parents[1]

homeassistant = types.ModuleType("homeassistant")
homeassistant.__path__ = []
sys.modules.setdefault("homeassistant", homeassistant)

voluptuous = types.ModuleType("voluptuous")
voluptuous.Required = lambda value: value
voluptuous.Schema = lambda value: value
sys.modules.setdefault("voluptuous", voluptuous)

ha_const = types.ModuleType("homeassistant.const")
ha_const.Platform = types.SimpleNamespace(SENSOR="sensor")
sys.modules.setdefault("homeassistant.const", ha_const)


class _ConfigFlow:
    """Minimal Home Assistant config-flow surface used by these tests."""

    def __init_subclass__(cls, **kwargs):
        del kwargs

    def async_show_form(self, **kwargs):
        return {"type": "form", **kwargs}

    def async_abort(self, *, reason):
        return {"type": "abort", "reason": reason}

    def async_update_reload_and_abort(self, entry, *, data):
        self.updated_entry = entry
        self.updated_data = data
        return {"type": "abort", "reason": "reauth_successful"}


config_entries = types.ModuleType("homeassistant.config_entries")
config_entries.ConfigFlow = _ConfigFlow
config_entries.CONN_CLASS_CLOUD_POLL = "cloud_poll"
sys.modules["homeassistant.config_entries"] = config_entries

helpers = sys.modules.get(
    "homeassistant.helpers", types.ModuleType("homeassistant.helpers")
)
helpers.__path__ = []
sys.modules["homeassistant.helpers"] = helpers

aiohttp_client = types.ModuleType("homeassistant.helpers.aiohttp_client")
aiohttp_client.async_get_clientsession = lambda hass: None
sys.modules["homeassistant.helpers.aiohttp_client"] = aiohttp_client

package = sys.modules.get("custom_components", types.ModuleType("custom_components"))
package.__path__ = [str(ROOT / "custom_components")]
integration = types.ModuleType("custom_components.brunata_online")
integration.__path__ = [str(ROOT / "custom_components" / "brunata_online")]
sys.modules["custom_components"] = package
sys.modules["custom_components.brunata_online"] = integration

from custom_components.brunata_online.config_flow import (  # noqa: E402
    BrunataOnlineConfigFlow,
)


class ConfigFlowReauthTests(unittest.IsolatedAsyncioTestCase):
    """Ensure expired credentials can be replaced without recreating an entry."""

    def _flow(self):
        entry = types.SimpleNamespace(
            data={"username": "person@example.com", "password": "old"}
        )
        entries = types.SimpleNamespace(async_get_entry=lambda entry_id: entry)
        flow = BrunataOnlineConfigFlow()
        flow.hass = types.SimpleNamespace(config_entries=entries)
        flow.context = {"entry_id": "entry-id"}
        return flow, entry

    async def test_successful_reauth_preserves_username_and_updates_password(self):
        flow, entry = self._flow()

        async def valid_credentials(username, password):
            self.assertEqual(username, "person@example.com")
            self.assertEqual(password, "new-secret")
            return "ok"

        flow._test_credentials = valid_credentials
        await flow.async_step_reauth(dict(entry.data))
        result = await flow.async_step_reauth_confirm({"password": "new-secret"})

        self.assertEqual(result["reason"], "reauth_successful")
        self.assertIs(flow.updated_entry, entry)
        self.assertEqual(
            flow.updated_data,
            {"username": "person@example.com", "password": "new-secret"},
        )

    async def test_failed_reauth_keeps_flow_open_with_error(self):
        flow, entry = self._flow()

        async def invalid_credentials(username, password):
            return "auth"

        flow._test_credentials = invalid_credentials
        await flow.async_step_reauth(dict(entry.data))
        result = await flow.async_step_reauth_confirm({"password": "wrong"})

        self.assertEqual(result["type"], "form")
        self.assertEqual(result["errors"], {"base": "auth"})


if __name__ == "__main__":
    unittest.main()
