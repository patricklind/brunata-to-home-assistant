"""Home Assistant actions for Brunata refresh, reports, and CSV export."""

from __future__ import annotations

import csv
from io import StringIO
from typing import Any

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import Unauthorized

from .analytics import consumption_report
from .const import DOMAIN
from .number import parse_finite_number

SERVICE_REFRESH = "refresh"
SERVICE_GENERATE_REPORT = "generate_report"
SERVICE_EXPORT_CSV = "export_csv"
SERVICES_REGISTERED = f"{DOMAIN}_services_registered"


def _coordinators(hass: HomeAssistant, entry_id: str | None) -> list[Any]:
    coordinators = hass.data.get(DOMAIN, {})
    if entry_id:
        coordinator = coordinators.get(entry_id)
        return [coordinator] if coordinator is not None else []
    return list(coordinators.values())


def _history_for_row(data: dict[str, Any], row: dict[str, Any]) -> list[dict[str, Any]]:
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
    key = "|".join(
        str(meter.get(name) or "")
        for name in ("meterId", "meterSequenceNo", "meterNo", "allocationUnit")
    )
    history = data.get("meter_history_30d")
    points = history.get(key, []) if isinstance(history, dict) else []
    return [point for point in points if isinstance(point, dict)]


def build_report_response(
    coordinators: list[Any], period: str
) -> dict[str, Any]:
    """Build privacy-conscious report data for an action response."""
    accounts: list[dict[str, Any]] = []
    for coordinator in coordinators:
        data = coordinator.data if isinstance(coordinator.data, dict) else {}
        reports = []
        for row in data.get("meters", []):
            if not isinstance(row, dict):
                continue
            meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
            reports.append(
                {
                    "name": str(meter.get("placement") or "Meter"),
                    "unit_code": str(meter.get("unit") or ""),
                    **consumption_report(
                        _history_for_row(data, row), period=period
                    ),
                }
            )
        accounts.append(
            {
                "entry_id": coordinator.config_entry.entry_id,
                "title": coordinator.config_entry.title,
                "fetched_at": data.get("fetched_at"),
                "meters": reports,
            }
        )
    return {"period": period, "accounts": accounts}


def build_csv_response(coordinators: list[Any]) -> dict[str, str]:
    """Return CSV content without writing an arbitrary server-side path."""
    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["account", "meter", "date", "value"])
    for coordinator in coordinators:
        data = coordinator.data if isinstance(coordinator.data, dict) else {}
        for row in data.get("meters", []):
            if not isinstance(row, dict):
                continue
            meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
            name = str(meter.get("placement") or "Meter")
            if name.startswith(("=", "+", "-", "@")):
                name = f"'{name}"
            for point in _history_for_row(data, row):
                value = parse_finite_number(point.get("value"))
                if value is not None:
                    writer.writerow(
                        [
                            coordinator.config_entry.title,
                            name,
                            point.get("date") or point.get("reading_date"),
                            value,
                        ]
                    )
    return {"filename": "brunata-report.csv", "content": output.getvalue()}


async def async_setup_services(hass: HomeAssistant) -> None:
    """Register integration actions once."""
    if hass.data.get(SERVICES_REGISTERED):
        return

    async def require_admin(call: ServiceCall) -> None:
        user_id = call.context.user_id
        if user_id is None:
            return
        user = await hass.auth.async_get_user(user_id)
        if user is None or not user.is_admin:
            raise Unauthorized(context=call.context)

    async def refresh(call: ServiceCall) -> None:
        await require_admin(call)
        for coordinator in _coordinators(hass, call.data.get("entry_id")):
            await coordinator.async_request_refresh()

    async def generate_report(call: ServiceCall) -> dict[str, Any]:
        await require_admin(call)
        return build_report_response(
            _coordinators(hass, call.data.get("entry_id")), call.data["period"]
        )

    async def export_csv(call: ServiceCall) -> dict[str, str]:
        await require_admin(call)
        return build_csv_response(_coordinators(hass, call.data.get("entry_id")))

    entry_schema = {vol.Optional("entry_id"): str}
    hass.services.async_register(DOMAIN, SERVICE_REFRESH, refresh, schema=entry_schema)
    hass.services.async_register(
        DOMAIN,
        SERVICE_GENERATE_REPORT,
        generate_report,
        schema={
            vol.Optional("entry_id"): str,
            vol.Required("period", default="week"): vol.In(
                {"week", "month", "year"}
            ),
        },
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_EXPORT_CSV,
        export_csv,
        schema=entry_schema,
        supports_response=SupportsResponse.ONLY,
    )
    hass.data[SERVICES_REGISTERED] = True


async def async_unload_services(hass: HomeAssistant) -> None:
    """Remove actions after the final config entry unloads."""
    if not hass.data.pop(SERVICES_REGISTERED, False):
        return
    for service in (SERVICE_REFRESH, SERVICE_GENERATE_REPORT, SERVICE_EXPORT_CSV):
        hass.services.async_remove(DOMAIN, service)
