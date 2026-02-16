"""Test Brunata Online config flow."""

from unittest.mock import patch

from homeassistant import config_entries, data_entry_flow
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.brunata_online.const import (
    DOMAIN,
    PLATFORMS,
    SENSOR,
)

from .const import MOCK_CONFIG


@pytest.fixture(autouse=True)
def bypass_setup_fixture():
    """Prevent setup."""
    with patch(
        "custom_components.brunata_online.async_setup",
        return_value=True,
    ), patch(
        "custom_components.brunata_online.async_setup_entry",
        return_value=True,
    ):
        yield


async def test_successful_config_flow(
    hass, bypass_get_data, enable_custom_integrations
):
    """Test a successful config flow."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    assert result["type"] == data_entry_flow.RESULT_TYPE_FORM
    assert result["step_id"] == "user"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], user_input=MOCK_CONFIG
    )

    assert result["type"] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    assert result["title"] == "test_username"
    assert result["data"] == MOCK_CONFIG
    assert result["result"]


async def test_failed_config_flow(hass, error_on_get_data, enable_custom_integrations):
    """Test a failed config flow due to credential validation failure."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )

    assert result["type"] == data_entry_flow.RESULT_TYPE_FORM
    assert result["step_id"] == "user"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], user_input=MOCK_CONFIG
    )

    assert result["type"] == data_entry_flow.RESULT_TYPE_FORM
    assert result["errors"] == {"base": "auth"}


async def test_options_flow(hass, enable_custom_integrations):
    """Test an options flow."""
    entry = MockConfigEntry(domain=DOMAIN, data=MOCK_CONFIG, entry_id="test")
    entry.add_to_hass(hass)

    await hass.config_entries.async_setup(entry.entry_id)
    result = await hass.config_entries.options.async_init(entry.entry_id)

    assert result["type"] == data_entry_flow.RESULT_TYPE_FORM
    assert result["step_id"] == "user"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={platform: platform != SENSOR for platform in PLATFORMS},
    )

    assert result["type"] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    assert result["title"] == "test_username"

    assert entry.options == {SENSOR: False}
