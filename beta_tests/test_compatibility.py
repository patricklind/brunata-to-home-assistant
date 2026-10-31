"""Exercise beta core APIs without depending on the stable-only pytest harness."""

from __future__ import annotations

from pathlib import Path
import tempfile
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock

import probatio
from homeassistant.config_entries import ConfigEntries, ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import Unauthorized

from custom_components.brunata_online import BrunataDataCoordinator
from custom_components.brunata_online.config_flow import BrunataOnlineConfigFlow
from custom_components.brunata_online.frontend import _register_static_path
from custom_components.brunata_online.panel import (
    websocket_panel_data,
    websocket_update_panel_settings,
)
from custom_components.brunata_online.services import (
    async_setup_services,
    async_unload_services,
)


class BetaCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    """Use real beta schemas, services, config entries, and HTTP routes."""

    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.hass = HomeAssistant(self.directory.name)
        self.hass.config_entries = ConfigEntries(self.hass, {})

    async def asyncTearDown(self):
        await self.hass.async_stop(force=True)
        self.directory.cleanup()

    async def test_user_form_accepts_credentials(self):
        flow = BrunataOnlineConfigFlow()
        flow.hass = self.hass
        result = await flow.async_step_user()
        credentials = {"username": "user@example.com", "password": "secret"}
        self.assertEqual(result["data_schema"](credentials), credentials)
        with self.assertRaises(probatio.Invalid):
            result["data_schema"]({"username": "user@example.com"})

    async def test_report_and_csv_actions_validate_and_respond(self):
        await async_setup_services(self.hass)
        response = await self.hass.services.async_call(
            "brunata_online", "generate_report", {}, blocking=True, return_response=True
        )
        self.assertEqual(response, {"period": "week", "accounts": []})
        csv_response = await self.hass.services.async_call(
            "brunata_online", "export_csv", {}, blocking=True, return_response=True
        )
        self.assertEqual(csv_response["content"], "account,meter,date,value\r\n")
        with self.assertRaises(probatio.Invalid):
            await self.hass.services.async_call(
                "brunata_online",
                "generate_report",
                {"period": "invalid"},
                blocking=True,
                return_response=True,
            )
        await async_unload_services(self.hass)
        self.assertFalse(self.hass.services.has_service("brunata_online", "refresh"))

    async def test_panel_settings_schema_accepts_and_rejects_messages(self):
        schema = websocket_update_panel_settings._ws_schema
        message = {
            "id": 1,
            "type": "brunata_online/panel_settings/update",
            "settings": {"precision": 3},
        }
        self.assertEqual(schema(message), message)
        with self.assertRaises(probatio.Invalid):
            schema({**message, "settings": "invalid"})

    async def test_panel_still_requires_an_administrator(self):
        connection = SimpleNamespace(user=SimpleNamespace(is_admin=False))
        with self.assertRaises(Unauthorized):
            websocket_panel_data(
                self.hass, connection, {"id": 1, "type": "brunata_online/panel_data"}
            )

    async def test_coordinator_keeps_explicit_entry_and_fetches_data(self):
        entry = ConfigEntry(
            data={},
            discovery_keys=MappingProxyType({}),
            domain="brunata_online",
            minor_version=1,
            options={},
            source="user",
            subentries_data=None,
            title="Home",
            unique_id=None,
            version=2,
        )
        client = SimpleNamespace(
            async_fetch_data=AsyncMock(return_value={"meters": []})
        )
        coordinator = BrunataDataCoordinator(self.hass, client, entry)
        self.assertIs(coordinator.config_entry, entry)
        await coordinator.async_refresh()
        self.assertTrue(coordinator.last_update_success)
        self.assertEqual(coordinator.data, {"meters": []})
        await coordinator.async_shutdown()

    async def test_panel_static_assets_register_with_beta_http_server(self):
        from homeassistant.components.http import HomeAssistantHTTP
        from homeassistant.components.http.cors import setup_cors

        self.hass.http = HomeAssistantHTTP(
            self.hass,
            server_host="127.0.0.1",
            server_port=0,
            ssl_certificate=None,
            ssl_peer_certificate=None,
            ssl_key=None,
            trusted_proxies=[],
            ssl_profile="modern",
        )
        setup_cors(self.hass.http.app, [])
        asset = Path(self.directory.name) / "panel.js"
        asset.write_text("export const ready = true;", encoding="utf-8")
        await _register_static_path(self.hass, "/brunata-test.js", asset)
        self.assertTrue(
            any(
                route.resource.canonical == "/brunata-test.js"
                for route in self.hass.http.app.router.routes()
            )
        )
