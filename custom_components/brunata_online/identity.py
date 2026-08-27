"""Stable identity helpers for account-scoped aggregate entities."""

from __future__ import annotations

import re

from .const import DOMAIN

AGGREGATE_SCOPES = ("water_total", "water_cold_total", "water_hot_total")
_LEGACY_AGGREGATE_PATTERN = re.compile(
    rf"^{DOMAIN}_(?P<scope>{'|'.join(AGGREGATE_SCOPES)})"
    r"(?P<window>_last_(?:1|7|14|30)_days)?$"
)


def aggregate_device_identifier(entry_id: str, scope_key: str) -> tuple[str, str]:
    """Return an aggregate device identifier isolated to one config entry."""
    return DOMAIN, f"{entry_id}_aggregate_{scope_key}"


def aggregate_unique_id(
    entry_id: str, scope_key: str, window_days: int | None = None
) -> str:
    """Return an aggregate entity unique ID isolated to one config entry."""
    base = f"{DOMAIN}_{entry_id}_{scope_key}"
    return f"{base}_last_{window_days}_days" if window_days is not None else base


def migrate_aggregate_unique_id(entry_id: str, unique_id: str) -> str | None:
    """Map a legacy aggregate unique ID to its account-scoped equivalent."""
    match = _LEGACY_AGGREGATE_PATTERN.fullmatch(unique_id)
    if match is None:
        return None
    return f"{DOMAIN}_{entry_id}_{match.group('scope')}{match.group('window') or ''}"
