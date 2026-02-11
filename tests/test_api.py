"""Tests for Brunata Online api."""

from unittest.mock import AsyncMock, patch

from homeassistant.helpers.aiohttp_client import async_get_clientsession

from custom_components.brunata_online.api import BrunataOnlineApiClient


async def test_api_get_data(hass, aioclient_mock):
    """Test async_get_data returns building and measuring point data."""
    api = BrunataOnlineApiClient("test", "test", async_get_clientsession(hass))

    # Mock the token acquisition so we skip real B2C auth
    with patch.object(api, "_ensure_access_token", new_callable=AsyncMock):
        # Set a fake token so _api_get_json builds the auth header
        api._token_state.access_token = "fake-token"
        api._token_state.access_expires_at = 9999999999.0

        # Mock buildings endpoint
        aioclient_mock.get(
            "https://online.brunata.com/online-webservice/v1/rest/buildings",
            json=[{"buildingNo": 123, "buildingName": "Test Building"}],
        )

        # Mock measuring points endpoint (match any query string)
        aioclient_mock.get(
            "https://online.brunata.com/online-webservice/v1/rest/buildings/123/measuringpoints",
            json={
                "measuringPoints": [
                    {
                        "serialNo": "ABC123",
                        "alloUnitType": "Heating",
                        "meterValue": 588,
                        "connectedTo": "Stue",
                    }
                ]
            },
        )

        data = await api.async_get_data()

    assert "buildings" in data
    assert "measuring_points" in data
    assert "123" in data["buildings"]
    assert len(data["measuring_points"]) == 1

    point = list(data["measuring_points"].values())[0]
    assert point["serialNo"] == "ABC123"
    assert point["meterValue"] == 588
