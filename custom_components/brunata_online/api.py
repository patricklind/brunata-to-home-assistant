"""Async API client for Brunata Online."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import os
import re
import secrets
import time
from typing import Any
import urllib.parse

from aiohttp import ClientResponseError, ClientSession, ClientTimeout
import requests

BASE_URL = "https://online.brunata.com"
API_BASE_URL = f"{BASE_URL}/online-webservice/v1/rest"
AUTH_BASE_URL = f"{BASE_URL}/online-auth-webservice/v1/rest"

OAUTH2_PROFILE = "B2C_1_signin_username"
AUTHN_URL = (
    "https://brunatab2cprod.b2clogin.com/"
    f"brunatab2cprod.onmicrosoft.com/{OAUTH2_PROFILE}"
)

CLIENT_ID = "e1d10965-78dc-4051-a1e5-251483e74d03"
REDIRECT_URI = f"{BASE_URL}/auth-response"

DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

REQUEST_TIMEOUT = ClientTimeout(total=30)


class BrunataAuthError(Exception):
    """Raised when authentication against Brunata Online fails."""


@dataclass
class _TokenState:
    access_token: str | None = None
    access_expires_at: float = 0.0
    refresh_token: str | None = None
    refresh_expires_at: float = 0.0

    def access_valid(self, now: float) -> bool:
        return bool(self.access_token) and now < (self.access_expires_at - 60)

    def refresh_valid(self, now: float) -> bool:
        return bool(self.refresh_token) and now < (self.refresh_expires_at - 60)


class BrunataOnlineClient:
    """Client used by the HA integration."""

    def __init__(self, username: str, password: str, session: ClientSession) -> None:
        self._username = username
        self._password = password
        self._session = session

        self._token = _TokenState()
        self._token_lock = asyncio.Lock()
        self._best_startdate: str | None = None

    async def async_fetch_data(self) -> dict[str, Any]:
        """Fetch consumer and meter data."""
        await self._ensure_access_token()

        consumer = await self._api_get_json("/consumer")
        best_date, meters, attempts = await self._get_best_meter_rows()

        filtered: list[dict[str, Any]] = []
        for row in meters:
            if not isinstance(row, dict):
                continue
            meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
            if meter.get("allocationUnit") == "P":
                continue
            filtered.append(row)

        filtered.sort(key=lambda x: self._meter_sequence(x))

        return {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "consumer": consumer,
            "best_startdate": best_date,
            "meters": filtered,
            "non_null_readings": self._count_non_null_readings(filtered),
            "attempts": attempts,
        }

    async def _get_best_meter_rows(
        self,
    ) -> tuple[str | None, list[dict[str, Any]], list[dict[str, Any]]]:
        attempts: list[dict[str, Any]] = []

        preferred_dates: list[str] = []
        if self._best_startdate:
            preferred_dates.append(self._best_startdate)

        candidates = preferred_dates + [
            d for d in self._build_date_candidates() if d not in preferred_dates
        ]

        best_date: str | None = None
        best_rows: list[dict[str, Any]] = []
        best_score = (-1, -1)

        for startdate in candidates:
            try:
                rows = await self._api_get_json(
                    "/consumer/meters", params={"startdate": startdate}
                )
                if not isinstance(rows, list):
                    attempts.append(
                        {
                            "startdate": startdate,
                            "status": "ok_non_list",
                            "rows": 0,
                            "non_null": 0,
                        }
                    )
                    continue

                non_null = self._count_non_null_readings(rows)
                row_count = len(rows)
                attempts.append(
                    {
                        "startdate": startdate,
                        "status": "ok",
                        "rows": row_count,
                        "non_null": non_null,
                    }
                )

                score = (non_null, row_count)
                if score > best_score:
                    best_score = score
                    best_date = startdate
                    best_rows = rows
            except Exception as err:  # pylint: disable=broad-except
                attempts.append(
                    {
                        "startdate": startdate,
                        "status": "error",
                        "error": str(err),
                    }
                )

        if best_date:
            self._best_startdate = best_date

        return best_date, best_rows, attempts

    async def _api_get_json(
        self, path: str, params: dict[str, str] | None = None
    ) -> Any:
        await self._ensure_access_token()

        url = f"{API_BASE_URL}{path}"
        headers = {
            **DEFAULT_HEADERS,
            "Authorization": f"Bearer {self._token.access_token}",
            "Accept": "application/json, text/plain, */*",
        }

        try:
            async with self._session.get(
                url, params=params, headers=headers, timeout=REQUEST_TIMEOUT
            ) as resp:
                resp.raise_for_status()
                return await resp.json()
        except ClientResponseError as err:
            if err.status == 401:
                await self._ensure_access_token(force=True)
                headers["Authorization"] = f"Bearer {self._token.access_token}"
                async with self._session.get(
                    url, params=params, headers=headers, timeout=REQUEST_TIMEOUT
                ) as resp:
                    resp.raise_for_status()
                    return await resp.json()
            raise

    async def _ensure_access_token(self, force: bool = False) -> None:
        async with self._token_lock:
            now = time.time()
            if not force and self._token.access_valid(now):
                return

            if self._token.refresh_valid(now):
                try:
                    tokens = await self._refresh_tokens(self._token.refresh_token or "")
                    self._update_token_state(tokens)
                    return
                except Exception:  # pylint: disable=broad-except
                    self._token = _TokenState()

            tokens = await asyncio.to_thread(self._auth_sync)
            self._update_token_state(tokens)

    async def _refresh_tokens(self, refresh_token: str) -> dict[str, Any]:
        variants = (
            {"refresh_token": refresh_token},
            {
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "scope": f"{CLIENT_ID} offline_access",
                "refresh_token": refresh_token,
            },
        )

        last_error: str | None = None
        for data in variants:
            async with self._session.post(
                f"{AUTH_BASE_URL}/oauth/token",
                data=data,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": DEFAULT_HEADERS["User-Agent"],
                },
                timeout=REQUEST_TIMEOUT,
            ) as resp:
                text = await resp.text()
                if resp.status < 400:
                    return await resp.json()
                last_error = f"{resp.status}: {text[:300]}"

        raise BrunataAuthError(f"Refresh failed ({last_error})")

    def _update_token_state(self, tokens: dict[str, Any]) -> None:
        now = time.time()
        access_token = tokens.get("access_token")
        if not access_token:
            raise BrunataAuthError("No access_token in token response")

        expires_in = _to_int(tokens.get("expires_in"), 300)
        refresh_expires_in = _to_int(tokens.get("refresh_token_expires_in"), 0)

        self._token = _TokenState(
            access_token=str(access_token),
            access_expires_at=now + expires_in,
            refresh_token=(
                str(tokens.get("refresh_token")) if tokens.get("refresh_token") else None
            ),
            refresh_expires_at=(
                now + refresh_expires_in if refresh_expires_in > 0 else 0.0
            ),
        )

    def _auth_sync(self) -> dict[str, Any]:
        code_verifier = secrets.token_hex(28)

        with requests.Session() as session:
            session.headers.update(DEFAULT_HEADERS)

            authorize_params = {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": f"{CLIENT_ID} offline_access",
                "response_type": "code",
                "code_challenge": code_verifier,
                "code_challenge_method": "plain",
            }

            req_code = session.get(
                f"{AUTH_BASE_URL}/authorize",
                params=authorize_params,
                timeout=30,
            )
            req_code.raise_for_status()

            tx = _extract_transaction_id(str(req_code.url), req_code.text)
            csrf = _extract_csrf_token(req_code)

            self_asserted = session.post(
                f"{AUTHN_URL}/SelfAsserted",
                params={"tx": tx, "p": OAUTH2_PROFILE},
                data={
                    "request_type": "RESPONSE",
                    "logonIdentifier": self._username,
                    "password": self._password,
                },
                headers={
                    "Referer": str(req_code.url),
                    "X-Csrf-Token": csrf,
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": (
                        f"{urllib.parse.urlparse(str(req_code.url)).scheme}://"
                        f"{urllib.parse.urlparse(str(req_code.url)).netloc}"
                    ),
                },
                allow_redirects=False,
                timeout=30,
            )
            if self_asserted.status_code >= 400:
                error_text = _extract_b2c_error_text(self_asserted.text)
                raise BrunataAuthError(
                    error_text
                    or f"Credential submit failed ({self_asserted.status_code})"
                )

            try:
                payload = self_asserted.json()
            except ValueError:
                payload = {}
            if isinstance(payload, dict):
                status = str(payload.get("status", ""))
                if status and status not in {"200", "201"}:
                    error_text = _extract_b2c_error_text(str(payload)) or str(
                        payload.get("message") or ""
                    )
                    raise BrunataAuthError(
                        error_text or f"Credential submit returned status {status}"
                    )

            confirmed = session.get(
                f"{AUTHN_URL}/api/CombinedSigninAndSignup/confirmed",
                params={
                    "rememberMe": "false",
                    "csrf_token": csrf,
                    "tx": tx,
                    "p": OAUTH2_PROFILE,
                },
                allow_redirects=False,
                timeout=30,
            )
            if confirmed.status_code >= 400:
                error_text = _extract_b2c_error_text(confirmed.text)
                raise BrunataAuthError(
                    error_text
                    or f"Signin confirmation failed ({confirmed.status_code})"
                )

            redirect_location = _extract_location_url(confirmed)
            parsed = urllib.parse.urlparse(redirect_location)
            code = (urllib.parse.parse_qs(parsed.query).get("code") or [None])[0]
            if not code:
                raise BrunataAuthError("Authorization code missing in redirect")

            token_payloads = (
                {
                    "client_id": CLIENT_ID,
                    "code_verifier": code_verifier,
                    "code": code,
                },
                {
                    "grant_type": "authorization_code",
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "scope": f"{CLIENT_ID} offline_access",
                    "code_verifier": code_verifier,
                    "code": code,
                },
            )

            last_error: str | None = None
            for payload in token_payloads:
                resp = session.post(
                    f"{AUTH_BASE_URL}/oauth/token",
                    data=payload,
                    headers={
                        "Accept": "application/json, text/plain, */*",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": DEFAULT_HEADERS["User-Agent"],
                    },
                    timeout=30,
                )
                if resp.status_code < 400:
                    return resp.json()
                last_error = f"{resp.status_code}: {resp.text[:300]}"

            raise BrunataAuthError(f"Token exchange failed ({last_error})")

    @staticmethod
    def _build_date_candidates(days_back: int = 14) -> list[str]:
        now = datetime.now(timezone.utc)
        result: list[str] = []
        for offset in range(days_back, -1, -1):
            day: date = (now - timedelta(days=offset)).date()
            iso_day = day.isoformat()
            result.extend(
                [
                    iso_day,
                    f"{iso_day}T00:00:00Z",
                    f"{iso_day}T00:00:00.000Z",
                    f"{iso_day}T00:00:00+01:00",
                    f"{iso_day}T00:00:00.000+01:00",
                    f"{iso_day}T12:00:00+01:00",
                    f"{iso_day}T23:59:59+01:00",
                ]
            )
        # preserve order while removing duplicates
        return list(dict.fromkeys(result))

    @staticmethod
    def _count_non_null_readings(rows: list[dict[str, Any]]) -> int:
        count = 0
        for row in rows:
            reading = row.get("reading") if isinstance(row, dict) else None
            if isinstance(reading, dict) and reading.get("value") is not None:
                count += 1
        return count

    @staticmethod
    def _meter_sequence(row: dict[str, Any]) -> int:
        meter = row.get("meter") if isinstance(row, dict) else None
        if not isinstance(meter, dict):
            return 0
        seq = meter.get("meterSequenceNo")
        try:
            return int(seq)
        except (TypeError, ValueError):
            return 0


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_transaction_id(page_url: str, page_html: str) -> str:
    parsed = urllib.parse.urlparse(page_url)
    qs = urllib.parse.parse_qs(parsed.query)
    for key in ("tx", "transId", "transactionId"):
        val = (qs.get(key) or [None])[0]
        if val:
            return str(val)

    patterns = (
        r'"transId"\s*:\s*"([^"]+)"',
        r"'transId'\s*:\s*'([^']+)'",
        r"\btransId\b\s*[:=]\s*\"([^\"]+)\"",
        r"\btransId\b\s*[:=]\s*'([^']+)'",
        r'"tx"\s*:\s*"([^"]+)"',
        r"'tx'\s*:\s*'([^']+)'",
    )
    for pattern in patterns:
        match = re.search(pattern, page_html)
        if match:
            return str(match.group(1))

    raise BrunataAuthError("Could not extract transaction id (tx/transId)")


def _extract_csrf_token(response: requests.Response) -> str:
    token = response.cookies.get("x-ms-cpim-csrf")
    if token:
        return str(token)

    patterns = (
        r'name="csrf_token"\s+value="([^"]+)"',
        r'"csrf"\s*:\s*"([^"]+)"',
        r'"csrfToken"\s*:\s*"([^"]+)"',
    )
    for pattern in patterns:
        match = re.search(pattern, response.text)
        if match:
            return str(match.group(1))

    raise BrunataAuthError("Could not extract CSRF token")


def _extract_location_url(response: requests.Response) -> str:
    location = response.headers.get("Location")
    if location:
        return location

    for pattern in (
        r"""location\.href\s*=\s*["']([^"']+)["']""",
        r"""url=([^"'>\s]+)""",
    ):
        match = re.search(pattern, response.text, flags=re.IGNORECASE)
        if match:
            return str(match.group(1))

    raise BrunataAuthError("Auth redirect location missing")


def _extract_b2c_error_text(payload: str) -> str | None:
    patterns = (
        r"(AADB2C\d+:[^\r\n<]+)",
        r'"message"\s*:\s*"([^"]+)"',
        r'"userMessage"\s*:\s*"([^"]+)"',
        r'"error_description"\s*:\s*"([^"]+)"',
    )
    for pattern in patterns:
        match = re.search(pattern, payload, flags=re.IGNORECASE)
        if match:
            return str(match.group(1)).strip()
    return None


__all__ = ["BrunataAuthError", "BrunataOnlineClient"]
