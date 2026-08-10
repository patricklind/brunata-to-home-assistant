"""Regression tests for the Brunata API client."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import types
import unittest


def _load_module(name: str, relative_path: str):
    path = Path(__file__).parents[1] / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if importlib.util.find_spec("aiohttp") is None:
    aiohttp = types.ModuleType("aiohttp")

    class ClientError(Exception):
        pass

    class ClientResponseError(ClientError):
        status = 500

    class ClientSession:
        pass

    class ClientTimeout:
        def __init__(self, **kwargs):
            self.options = kwargs

    aiohttp.ClientError = ClientError
    aiohttp.ClientResponseError = ClientResponseError
    aiohttp.ClientSession = ClientSession
    aiohttp.ClientTimeout = ClientTimeout
    sys.modules["aiohttp"] = aiohttp


api = _load_module("brunata_api", "custom_components/brunata_online/api.py")


class CredentialPostUrlTests(unittest.TestCase):
    """Ensure credentials can only be submitted to Brunata's Keycloak realm."""

    def test_accepts_expected_keycloak_action(self) -> None:
        api._validate_credential_post_url(
            "https://online.brunata.com/iam/realms/online-prod/"
            "login-actions/authenticate?session_code=abc"
        )

    def test_rejects_external_or_malformed_actions(self) -> None:
        unsafe_urls = (
            "https://evil.example/login-actions/authenticate",
            "http://online.brunata.com/iam/realms/online-prod/"
            "login-actions/authenticate",
            "https://online.brunata.com:444/iam/realms/online-prod/"
            "login-actions/authenticate",
            "https://online.brunata.com:invalid/iam/realms/online-prod/"
            "login-actions/authenticate",
        )
        for url in unsafe_urls:
            with self.subTest(url=url), self.assertRaises(api.BrunataAuthError):
                api._validate_credential_post_url(url)


class HistoryCacheTests(unittest.IsolatedAsyncioTestCase):
    """Verify partial history refreshes do not erase valid cached totals."""

    async def test_partial_refresh_merges_cached_days(self) -> None:
        client = api.BrunataOnlineClient("user", "password", None)
        today = datetime.now(timezone.utc).date()
        cached_day = (today - timedelta(days=1)).isoformat()
        meter = {
            "meterId": "old-transmitter",
            "meterSequenceNo": "1",
            "meterNo": "water-meter",
            "allocationUnit": "W",
        }
        row = {"meter": meter, "reading": {"value": None}}
        meter_key = client._meter_history_key(row)
        client._history_cache = {
            meter_key: [{"date": cached_day, "value": 42.5, "reading_date": cached_day}]
        }

        async def fake_get_json(path, params=None, **kwargs):
            await asyncio.sleep(0)
            if params and str(params["startdate"]).startswith(today.isoformat()):
                return [
                    {
                        "meter": meter,
                        "reading": {
                            "value": 43.0,
                            "readingDate": today.isoformat(),
                        },
                    }
                ]
            raise api.ClientError("simulated unavailable history day")

        client._api_get_json = fake_get_json
        history, metadata = await client._get_meter_history_30d([row])

        self.assertGreater(metadata["failed_days"], 0)
        self.assertEqual(
            [point["date"] for point in history[meter_key]],
            [cached_day, today.isoformat()],
        )
        self.assertEqual(history[meter_key][0]["value"], 42.5)

    async def test_dismount_day_is_queried_outside_rolling_window(self) -> None:
        client = api.BrunataOnlineClient("user", "password", None)
        dismount_day = (
            datetime.now(timezone.utc).date() - timedelta(days=90)
        ).isoformat()
        meter = {
            "meterId": "old-transmitter",
            "meterSequenceNo": "1",
            "meterNo": "water-meter",
            "allocationUnit": "W",
            "dismountedDate": f"{dismount_day}T12:00:00+00:00",
        }
        row = {"meter": meter, "reading": {"value": None}}

        async def fake_get_json(path, params=None, **kwargs):
            await asyncio.sleep(0)
            if params and str(params["startdate"]).startswith(dismount_day):
                return [
                    {
                        "meter": meter,
                        "reading": {
                            "value": 84.25,
                            "readingDate": meter["dismountedDate"],
                        },
                    }
                ]
            return []

        client._api_get_json = fake_get_json
        history, metadata = await client._get_meter_history_30d([row])
        meter_key = client._meter_history_key(row)

        self.assertEqual(metadata["failed_days"], 0)
        self.assertEqual(history[meter_key][0]["date"], dismount_day)
        self.assertEqual(history[meter_key][0]["value"], 84.25)


class HistoryFallbackTests(unittest.TestCase):
    """Verify API payload normalization for replaced transmitters."""

    def test_missing_reading_uses_latest_valid_history_value(self) -> None:
        row = {
            "meter": {
                "meterId": "old",
                "meterSequenceNo": "1",
                "meterNo": "hot-water",
                "allocationUnit": "W",
            },
            "reading": {"value": None},
        }
        meter_key = api.BrunataOnlineClient._meter_history_key(row)

        api.BrunataOnlineClient._apply_history_fallbacks(
            [row],
            {
                meter_key: [
                    {"value": "12,5"},
                    {"value": "invalid"},
                    {"value": None},
                ]
            },
        )

        self.assertEqual(row["reading"]["value"], 12.5)
        self.assertIs(row["reading"]["historicalFallback"], True)

    def test_current_zero_is_not_replaced(self) -> None:
        row = {
            "meter": {"meterId": "current"},
            "reading": {"value": 0},
        }
        meter_key = api.BrunataOnlineClient._meter_history_key(row)

        api.BrunataOnlineClient._apply_history_fallbacks(
            [row], {meter_key: [{"value": 99}]}
        )

        self.assertEqual(row["reading"], {"value": 0})

    def test_boolean_is_not_a_valid_meter_value(self) -> None:
        self.assertIsNone(api._to_float(True))


if __name__ == "__main__":
    unittest.main()
