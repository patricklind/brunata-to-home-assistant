"""Register the Brunata Online sidebar panel and its static assets."""

from __future__ import annotations

import hashlib
from pathlib import Path

from homeassistant.components import frontend
from homeassistant.core import HomeAssistant

PANEL_ELEMENT = "brunata-online-panel"
PANEL_URL_PATH = "brunata-online"
PANEL_JS_URL = "/brunata-online/brunata-panel.js"
PANEL_ICON_URL = "/brunata-online/icon.png"
PANEL_REGISTERED = "brunata_online_panel_registered"


async def _register_static_path(
    hass: HomeAssistant, url_path: str, file_path: Path
) -> None:
    """Register a cacheable static file on old and new HA versions."""
    try:
        from homeassistant.components.http import StaticPathConfig
    except ImportError:
        hass.http.register_static_path(url_path, str(file_path), cache_headers=True)
        return

    if hasattr(hass.http, "async_register_static_paths"):
        try:
            await hass.http.async_register_static_paths(
                [StaticPathConfig(url_path, str(file_path), cache_headers=True)]
            )
        except Exception as err:  # Reloading may leave the route registered.
            if "already" not in str(err).lower():
                raise
        return

    hass.http.register_static_path(url_path, str(file_path), cache_headers=True)


async def async_register_panel(hass: HomeAssistant) -> None:
    """Serve and register the Brunata Online sidebar panel once."""
    if hass.data.get(PANEL_REGISTERED):
        return

    base = Path(__file__).parent
    panel_file = base / "www" / "brunata-panel.js"
    icon_file = base / "brand" / "icon.png"
    await _register_static_path(hass, PANEL_JS_URL, panel_file)
    await _register_static_path(hass, PANEL_ICON_URL, icon_file)

    digest = await hass.async_add_executor_job(
        lambda: hashlib.sha256(panel_file.read_bytes()).hexdigest()[:10]
    )
    frontend.async_register_built_in_panel(
        hass,
        component_name="custom",
        sidebar_title="Brunata",
        sidebar_icon="mdi:water-thermometer-outline",
        frontend_url_path=PANEL_URL_PATH,
        config={
            "_panel_custom": {
                "name": PANEL_ELEMENT,
                "module_url": f"{PANEL_JS_URL}?v={digest}",
                "embed_iframe": False,
                "trust_external": False,
            }
        },
        require_admin=False,
    )
    hass.data[PANEL_REGISTERED] = True


async def async_unregister_panel(hass: HomeAssistant) -> None:
    """Remove the sidebar item when the last config entry is unloaded."""
    if hass.data.pop(PANEL_REGISTERED, None):
        frontend.async_remove_panel(hass, PANEL_URL_PATH)
