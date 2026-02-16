"""Constants for Brunata Online integration."""

from __future__ import annotations

from datetime import timedelta

from homeassistant.const import Platform

DOMAIN = "brunata_online"
PLATFORMS: list[Platform] = [Platform.SENSOR]

CONF_USERNAME = "username"
CONF_PASSWORD = "password"

SCAN_INTERVAL = timedelta(hours=1)
