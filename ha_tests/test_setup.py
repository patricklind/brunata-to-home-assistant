"""Home Assistant runtime smoke tests for Brunata Online."""

from unittest.mock import patch

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.brunata_online.const import DOMAIN


async def test_entry_creates_energy_compatible_entities_and_actions(
    hass, freezer
) -> None:
    freezer.move_to("2026-08-28T12:00:00+00:00")
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Home",
        data={"username": "user@example.com", "password": "secret"},
        version=2,
    )
    entry.add_to_hass(hass)
    payload = {
        "fetched_at": "2026-08-28T00:00:00+00:00",
        "meters": [
            {
                "meter": {
                    "meterId": "heat-1",
                    "meterSequenceNo": "1",
                    "meterNo": "42",
                    "allocationUnit": "O",
                    "meterType": "Heating",
                    "unit": "4",
                    "placement": "Living room",
                },
                "reading": {"value": 120, "readingDate": "2026-08-28"},
            }
        ],
        "meter_history_30d": {
            "heat-1|1|42|O": [
                {"date": "2026-08-14", "value": 100},
                {"date": "2026-08-21", "value": 108},
                {"date": "2026-08-28", "value": 120},
            ]
        },
        "meter_history_meta": {"successful_days": 3, "failed_days": 0},
    }

    with (
        patch(
            "custom_components.brunata_online.api.BrunataOnlineClient.async_fetch_data",
            return_value=payload,
        ),
        patch(
            "homeassistant.components.http.HomeAssistantHTTP.start",
            return_value=None,
        ),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert hass.services.has_service(DOMAIN, "refresh")
    assert hass.services.has_service(DOMAIN, "generate_report")
    assert hass.services.has_service(DOMAIN, "export_csv")
    energy_states = [
        state
        for state in hass.states.async_all("sensor")
        if state.attributes.get("recommended_for_energy_dashboard") is True
    ]
    assert len(energy_states) == 1
    assert energy_states[0].attributes["unit_of_measurement"] == "kWh"

    response = await hass.services.async_call(
        DOMAIN,
        "generate_report",
        {"period": "week"},
        blocking=True,
        return_response=True,
    )
    assert response["accounts"][0]["meters"][0]["current"] == 12.0
    assert response["accounts"][0]["title"] == "Home"

    # Real WebSocket validation catches incompatible schema markers after
    # Home Assistant's migration from voluptuous to probatio.
    from custom_components.brunata_online.panel import (
        websocket_update_panel_settings,
    )

    message = websocket_update_panel_settings._ws_schema(
        {
            "id": 1,
            "type": "brunata_online/panel_settings/update",
            "settings": {"precision": 3},
        }
    )
    assert message["settings"] == {"precision": 3}
    await hass.async_stop()


async def test_user_flow_validates_and_creates_entry(hass) -> None:
    """Exercise the form schema against the installed Home Assistant core."""
    from homeassistant import data_entry_flow

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    assert result["type"] is data_entry_flow.FlowResultType.FORM
    user_input = result["data_schema"](
        {"username": "user@example.com", "password": "secret"}
    )
    with (
        patch(
            "custom_components.brunata_online.api."
            "BrunataOnlineClient.async_validate_credentials"
        ),
        patch("custom_components.brunata_online.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input
        )
        await hass.async_block_till_done()
    assert result["type"] is data_entry_flow.FlowResultType.CREATE_ENTRY
    assert result["data"] == user_input
