"""Regression tests for the Brunata API client."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).parents[1]


def _load_module(name: str, relative_path: str):
    path = ROOT / relative_path
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


package = types.ModuleType("custom_components")
package.__path__ = [str(ROOT / "custom_components")]
integration = types.ModuleType("custom_components.brunata_online")
integration.__path__ = [str(ROOT / "custom_components" / "brunata_online")]
sys.modules["custom_components"] = package
sys.modules["custom_components.brunata_online"] = integration

_load_module(
    "custom_components.brunata_online.number",
    "custom_components/brunata_online/number.py",
)
api = _load_module(
    "custom_components.brunata_online.api",
    "custom_components/brunata_online/api.py",
)
debug_client = _load_module("brunata_debug_client", "fetch_brunata_data.py")


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


class CurrentMeterSelectionTests(unittest.IsolatedAsyncioTestCase):
    """Verify current values are selected independently for each meter."""

    async def test_uses_newest_valid_reading_per_meter(self) -> None:
        client = api.BrunataOnlineClient("user", "password", None)
        client._build_date_candidates = lambda: ["2026-07-01", "2026-08-01"]

        cold_meter = {"meterId": "cold", "allocationUnit": "K"}
        hot_meter = {"meterId": "hot", "allocationUnit": "W"}
        responses = {
            "2026-07-01": [
                {
                    "meter": cold_meter,
                    "reading": {"value": 100, "readingDate": "2026-07-01"},
                },
                {
                    "meter": hot_meter,
                    "reading": {"value": 20, "readingDate": "2026-07-01"},
                },
            ],
            "2026-08-01": [
                {
                    "meter": cold_meter,
                    "reading": {"value": 110, "readingDate": "2026-08-01"},
                },
                {
                    "meter": hot_meter,
                    "reading": {"value": 25, "readingDate": "2026-08-15"},
                },
            ],
        }

        async def fake_get_json(path, params=None, **kwargs):
            return responses[str(params["startdate"])]

        client._api_get_json = fake_get_json
        best_date, rows, _attempts = await client._get_best_meter_rows()
        values = {row["meter"]["meterId"]: row["reading"]["value"] for row in rows}

        self.assertEqual(best_date, "2026-08-01")
        self.assertEqual(values, {"cold": 110, "hot": 25})

    async def test_newer_empty_reading_does_not_replace_valid_value(self) -> None:
        client = api.BrunataOnlineClient("user", "password", None)
        client._build_date_candidates = lambda: ["2026-07-01", "2026-08-01"]
        meter = {"meterId": "cold", "allocationUnit": "K"}

        async def fake_get_json(path, params=None, **kwargs):
            if params["startdate"] == "2026-07-01":
                return [
                    {
                        "meter": meter,
                        "reading": {"value": 100, "readingDate": "2026-07-01"},
                    }
                ]
            return [{"meter": meter, "reading": {"value": None}}]

        client._api_get_json = fake_get_json
        _best_date, rows, _attempts = await client._get_best_meter_rows()

        self.assertEqual(rows[0]["reading"]["value"], 100)

    async def test_date_candidates_are_fetched_concurrently(self) -> None:
        client = api.BrunataOnlineClient("user", "password", None)
        client._build_date_candidates = lambda: [
            "2026-08-01",
            "2026-08-02",
            "2026-08-03",
            "2026-08-04",
        ]
        active_requests = 0
        maximum_active_requests = 0

        async def fake_get_json(path, params=None, **kwargs):
            nonlocal active_requests, maximum_active_requests
            active_requests += 1
            maximum_active_requests = max(maximum_active_requests, active_requests)
            await asyncio.sleep(0)
            active_requests -= 1
            return []

        client._api_get_json = fake_get_json
        await client._get_best_meter_rows()

        self.assertGreater(maximum_active_requests, 1)


class DebugClientMeterSelectionTests(unittest.TestCase):
    """Keep the standalone export client consistent with the integration."""

    def test_uses_newest_valid_reading_per_meter(self) -> None:
        cold_meter = {"meterId": "cold", "allocationUnit": "K"}
        hot_meter = {"meterId": "hot", "allocationUnit": "W"}
        responses = {
            "2026-07-01": [
                {
                    "meter": cold_meter,
                    "reading": {"value": 100, "readingDate": "2026-07-01"},
                },
                {
                    "meter": hot_meter,
                    "reading": {"value": 20, "readingDate": "2026-07-01"},
                },
            ],
            "2026-08-01": [
                {
                    "meter": cold_meter,
                    "reading": {"value": 110, "readingDate": "2026-08-01"},
                },
                {
                    "meter": hot_meter,
                    "reading": {"value": 25, "readingDate": "2026-08-15"},
                },
            ],
        }

        original_candidates = debug_client.build_date_candidates
        original_get_json = debug_client.api_get_json
        try:
            debug_client.build_date_candidates = lambda: [
                "2026-07-01",
                "2026-08-01",
            ]
            debug_client.api_get_json = lambda _session, _token, _path, params: (
                responses[params["startdate"]]
            )
            best_date, rows, _attempts = debug_client.pick_best_meter_payload(
                None, "token"
            )
        finally:
            debug_client.build_date_candidates = original_candidates
            debug_client.api_get_json = original_get_json

        values = {row["meter"]["meterId"]: row["reading"]["value"] for row in rows}
        self.assertEqual(best_date, "2026-08-01")
        self.assertEqual(values, {"cold": 110, "hot": 25})

    def test_newer_invalid_reading_does_not_replace_numeric_value(self) -> None:
        row = {
            "meter": {
                "meterId": "cold",
                "meterSequenceNo": "1",
                "meterNo": "100",
                "allocationUnit": "K",
            }
        }
        responses = {
            "2026-07-01": [{**row, "reading": {"value": "10,5"}}],
            "2026-08-01": [{**row, "reading": {"value": "invalid"}}],
        }

        original_candidates = debug_client.build_date_candidates
        original_get_json = debug_client.api_get_json
        try:
            debug_client.build_date_candidates = lambda: [
                "2026-07-01",
                "2026-08-01",
            ]
            debug_client.api_get_json = lambda _session, _token, _path, params: (
                responses[params["startdate"]]
            )
            _best_date, rows, _attempts = debug_client.pick_best_meter_payload(
                None, "token"
            )
        finally:
            debug_client.build_date_candidates = original_candidates
            debug_client.api_get_json = original_get_json

        self.assertEqual(rows[0]["reading"]["value"], "10,5")


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

    def test_non_finite_values_are_not_valid_meter_values(self) -> None:
        for value in (float("nan"), float("inf"), "-Infinity", "NaN"):
            with self.subTest(value=value):
                self.assertIsNone(api._to_float(value))


if __name__ == "__main__":
    unittest.main()
