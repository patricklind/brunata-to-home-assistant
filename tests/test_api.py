"""Tests for Brunata Online api."""

from unittest.mock import AsyncMock, patch

from custom_components.brunata_online.api import (
    BrunataOnlineApiClient,
    _TokenState,
    _compute_expiry,
)


async def test_api_get_data():
    """Test async_get_data returns building and measuring point data."""
    api = BrunataOnlineApiClient("test", "test", AsyncMock())

    async def _fake_api_get_json(path, params=None):
        if path == "/buildings":
            return [{"buildingNo": 123, "buildingName": "Test Building"}]
        if path == "/buildings/123/measuringpoints":
            assert params and "date" in params
            return {
                "measuringPoints": [
                    {
                        "serialNo": "ABC123",
                        "alloUnitType": "Heating",
                        "meterValue": 588,
                        "connectedTo": "Stue",
                    }
                ]
            }
        raise AssertionError(f"Unexpected path: {path}")

    with patch.object(api, "_api_get_json", side_effect=_fake_api_get_json):
        data = await api.async_get_data()

    assert "buildings" in data
    assert "measuring_points" in data
    assert "123" in data["buildings"]
    assert len(data["measuring_points"]) == 1

    point = list(data["measuring_points"].values())[0]
    assert point["serialNo"] == "ABC123"
    assert point["meterValue"] == 588


def test_refresh_token_without_expiry_is_still_usable():
    """Treat missing refresh-token expiry as unknown (still usable)."""
    state = _TokenState(refresh_token="refresh-token", refresh_expires_at=0)
    assert state.refresh_valid(now=1700000000)


def test_compute_expiry_uses_default_for_access_tokens():
    """Fallback to default seconds when access expiry fields are missing."""
    now = 1000.0
    expiry = _compute_expiry(
        now=now,
        tokens={},
        on_key="expires_on",
        in_key="expires_in",
        default_seconds=300,
    )
    assert expiry == 1300.0


def test_compute_expiry_returns_unknown_when_no_refresh_expiry():
    """Keep refresh expiry unknown if the token response omits expiry fields."""
    now = 1000.0
    expiry = _compute_expiry(
        now=now,
        tokens={},
        on_key="refresh_token_expires_on",
        in_key="refresh_token_expires_in",
        default_seconds=0,
    )
    assert expiry == 0.0
