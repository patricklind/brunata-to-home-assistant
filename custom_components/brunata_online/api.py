"""Async API client for Brunata Online."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import html
import re
import secrets
import time
from typing import Any
import urllib.parse

from aiohttp import ClientError, ClientResponseError, ClientSession, ClientTimeout
import requests

BASE_URL = "https://online.brunata.com"
API_BASE_URL = f"{BASE_URL}/online-webservice/v2/rest"
AUTH_BASE_URL = f"{BASE_URL}/online-auth-webservice/v1/rest"

# Brunata migrated its identity provider from Azure AD B2C to Keycloak
# (realm "online-prod") around 2026-05. Authentication now goes through the
# standard Keycloak authorization-code + PKCE flow.
KEYCLOAK_REALM_URL = f"{BASE_URL}/iam/realms/online-prod"
KEYCLOAK_AUTH_URL = f"{KEYCLOAK_REALM_URL}/protocol/openid-connect/auth"

CLIENT_ID = "82770188-c92e-4d16-927d-a15c472eda55"
REDIRECT_URI = f"{BASE_URL}/mybrunata/auth-redirect"
OAUTH_SCOPE = "openid offline_access"

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

REQUEST_TIMEOUT = ClientTimeout(total=45, connect=15, sock_connect=15, sock_read=30)
METER_REQUEST_TIMEOUT = ClientTimeout(total=10, connect=5, sock_connect=5, sock_read=8)
HISTORY_REQUEST_TIMEOUT = ClientTimeout(total=8, connect=3, sock_connect=3, sock_read=5)
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
MAX_API_ATTEMPTS = 3
AUTH_REQUEST_TIMEOUT: tuple[int, int] = (30, 90)
AUTH_MAX_ATTEMPTS = 3
HISTORY_DAYS_BACK = 30
HISTORY_REFRESH_INTERVAL = timedelta(hours=12)
MAX_HISTORY_PARALLEL_REQUESTS = 4


class BrunataAuthError(Exception):
    """Raised when authentication against Brunata Online fails."""


class BrunataConnectionError(Exception):
    """Raised when connection to Brunata Online cannot be established."""


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
        self._history_cache: dict[str, list[dict[str, Any]]] = {}
        self._history_updated_at: datetime | None = None

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
        meter_history_30d: dict[str, list[dict[str, Any]]] = {}
        meter_history_meta: dict[str, Any] = {
            "days_back": HISTORY_DAYS_BACK,
            "cached": False,
            "disabled": False,
        }
        try:
            meter_history_30d, meter_history_meta = await asyncio.wait_for(
                self._get_meter_history_30d(filtered),
                timeout=25,
            )
        except (TimeoutError, asyncio.TimeoutError):
            meter_history_meta.update(
                {"timeout": True, "reason": "history_fetch_timed_out"}
            )
        except Exception as err:  # pylint: disable=broad-except
            meter_history_meta.update(
                {"error": type(err).__name__, "reason": "history_fetch_failed"}
            )

        self._apply_history_fallbacks(filtered, meter_history_30d)

        return {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "consumer": consumer,
            "best_startdate": best_date,
            "meters": filtered,
            "non_null_readings": self._count_non_null_readings(filtered),
            "attempts": attempts,
            "meter_history_30d": meter_history_30d,
            "meter_history_meta": meter_history_meta,
        }

    async def async_validate_credentials(self) -> None:
        """Validate credentials and basic API reachability.

        This is intentionally lightweight for config flow validation.
        """
        await self._ensure_access_token()
        await self._api_get_json("/consumer")

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
        best_score = (-1, -1, -1)

        for startdate in candidates:
            try:
                rows = await self._api_get_json(
                    "/consumer/meters",
                    params={"startdate": startdate},
                    timeout=METER_REQUEST_TIMEOUT,
                    max_attempts=1,
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

                score = (non_null, row_count, startdate)
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

    async def _get_meter_history_30d(
        self, current_rows: list[dict[str, Any]]
    ) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
        now_utc = datetime.now(timezone.utc)
        current_meter_keys: set[str] = set()
        for row in current_rows:
            meter_key = self._meter_history_key(row)
            if meter_key:
                current_meter_keys.add(meter_key)

        cache_is_fresh = (
            self._history_updated_at is not None
            and (now_utc - self._history_updated_at) < HISTORY_REFRESH_INTERVAL
        )
        if cache_is_fresh and current_meter_keys.issubset(self._history_cache.keys()):
            return self._history_cache, {
                "days_back": HISTORY_DAYS_BACK,
                "cached": True,
                "updated_at": self._history_updated_at.isoformat(),
                "requested_days": 0,
                "successful_days": 0,
                "failed_days": 0,
            }

        day_values: list[date] = [
            (now_utc - timedelta(days=offset)).date()
            for offset in range(HISTORY_DAYS_BACK, -1, -1)
        ]
        # A dismounted transmitter's final value remains part of the physical
        # meter total even after its date falls outside the rolling history
        # window. Re-query that event day so the baseline also survives restarts.
        for row in current_rows:
            meter = row.get("meter") if isinstance(row.get("meter"), dict) else {}
            dismounted_date = _to_date(meter.get("dismountedDate"))
            if dismounted_date is not None and dismounted_date <= now_utc.date():
                day_values.append(dismounted_date)
        day_values = sorted(set(day_values))
        startdate_suffixes = self._history_startdate_suffixes()
        semaphore = asyncio.Semaphore(MAX_HISTORY_PARALLEL_REQUESTS)

        async def _fetch_day(
            day_value: date,
        ) -> tuple[str, list[dict[str, Any]] | None]:
            async with semaphore:
                for startdate in self._history_startdate_variants(
                    day_value, startdate_suffixes
                ):
                    try:
                        rows = await self._api_get_json(
                            "/consumer/meters",
                            params={"startdate": startdate},
                            timeout=HISTORY_REQUEST_TIMEOUT,
                            max_attempts=1,
                        )
                    except Exception:  # pylint: disable=broad-except
                        continue
                    if isinstance(rows, list):
                        return day_value.isoformat(), rows
                return day_value.isoformat(), None

        day_results = await asyncio.gather(*(_fetch_day(day) for day in day_values))

        meter_daily: dict[str, dict[str, dict[str, Any]]] = {}
        successful_days = 0
        failed_days = 0

        for day_iso, rows in day_results:
            if rows is None:
                failed_days += 1
                continue
            successful_days += 1
            for row in rows:
                if not isinstance(row, dict):
                    continue
                meter_key = self._meter_history_key(row)
                if not meter_key:
                    continue
                reading = row.get("reading")
                if not isinstance(reading, dict):
                    continue
                value = _to_float(reading.get("value"))
                if value is None:
                    continue
                meter_daily.setdefault(meter_key, {})[day_iso] = {
                    "date": day_iso,
                    "value": value,
                    "reading_date": reading.get("readingDate"),
                }

        if successful_days == 0 and self._history_cache:
            return self._history_cache, {
                "days_back": HISTORY_DAYS_BACK,
                "cached": True,
                "stale_cache": True,
                "updated_at": (
                    self._history_updated_at.isoformat()
                    if self._history_updated_at
                    else None
                ),
                "requested_days": len(day_values),
                "successful_days": 0,
                "failed_days": len(day_values),
            }

        history: dict[str, list[dict[str, Any]]] = {}
        for meter_key, by_day in meter_daily.items():
            history[meter_key] = [by_day[day] for day in sorted(by_day.keys())]

        # Preserve valid cached days when only part of a refresh succeeds. The
        # final reading of a dismounted transmitter may be the baseline for its
        # replacement, so losing it would make the aggregate total decrease.
        requested_days = {day.isoformat() for day in day_values}
        if failed_days and self._history_cache:
            for meter_key, cached_points in self._history_cache.items():
                by_day = {
                    str(point.get("date")): point
                    for point in cached_points
                    if isinstance(point, dict)
                    and str(point.get("date")) in requested_days
                }
                by_day.update(
                    {
                        str(point.get("date")): point
                        for point in history.get(meter_key, [])
                        if isinstance(point, dict) and point.get("date")
                    }
                )
                if by_day:
                    history[meter_key] = [by_day[day] for day in sorted(by_day)]

        for meter_key in current_meter_keys:
            history.setdefault(meter_key, [])

        self._history_cache = history
        self._history_updated_at = now_utc

        return history, {
            "days_back": HISTORY_DAYS_BACK,
            "cached": False,
            "updated_at": now_utc.isoformat(),
            "requested_days": len(day_values),
            "successful_days": successful_days,
            "failed_days": failed_days,
        }

    async def _api_get_json(
        self,
        path: str,
        params: dict[str, str] | None = None,
        *,
        timeout: ClientTimeout | None = None,
        max_attempts: int = MAX_API_ATTEMPTS,
    ) -> Any:
        await self._ensure_access_token()

        url = f"{API_BASE_URL}{path}"
        last_error: Exception | None = None
        request_timeout = timeout or REQUEST_TIMEOUT

        for attempt in range(1, max_attempts + 1):
            headers = {
                **DEFAULT_HEADERS,
                "Authorization": f"Bearer {self._token.access_token}",
                "Accept": "application/json, text/plain, */*",
            }
            try:
                async with self._session.get(
                    url, params=params, headers=headers, timeout=request_timeout
                ) as resp:
                    resp.raise_for_status()
                    return await resp.json()
            except ClientResponseError as err:
                if err.status == 401:
                    await self._ensure_access_token(force=True)
                    continue
                if err.status in RETRYABLE_STATUS_CODES and attempt < max_attempts:
                    last_error = err
                    await asyncio.sleep(attempt)
                    continue
                raise
            except (asyncio.TimeoutError, TimeoutError, ClientError) as err:
                last_error = err
                if attempt < max_attempts:
                    await asyncio.sleep(attempt)
                    continue
                raise

        if last_error:
            raise last_error
        raise BrunataAuthError(f"Unexpected empty API response loop for {path}")

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
                "scope": OAUTH_SCOPE,
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
                str(tokens.get("refresh_token"))
                if tokens.get("refresh_token")
                else None
            ),
            refresh_expires_at=(
                now + refresh_expires_in if refresh_expires_in > 0 else 0.0
            ),
        )

    def _auth_sync(self) -> dict[str, Any]:
        last_error: requests.RequestException | None = None

        for attempt in range(1, AUTH_MAX_ATTEMPTS + 1):
            try:
                # Match the browser app; Brunata uses a long hex PKCE verifier.
                code_verifier = secrets.token_hex(48)
                code_challenge = _pkce_s256_challenge(code_verifier)

                with requests.Session() as session:
                    session.headers.update(DEFAULT_HEADERS)

                    # 1. Load the Keycloak login page. This sets the
                    #    AUTH_SESSION_ID / KC_RESTART cookies that the
                    #    credential POST below depends on.
                    authorize_params = {
                        "client_id": CLIENT_ID,
                        "redirect_uri": REDIRECT_URI,
                        "scope": OAUTH_SCOPE,
                        "response_type": "code",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                    }

                    login_page = session.get(
                        KEYCLOAK_AUTH_URL,
                        params=authorize_params,
                        timeout=AUTH_REQUEST_TIMEOUT,
                    )
                    login_page.raise_for_status()

                    # 2. The login form posts to a one-time
                    #    login-actions/authenticate URL carrying
                    #    session_code / execution / tab_id.
                    form_action = _extract_login_form_action(login_page.text)
                    _validate_credential_post_url(form_action)

                    # 3. Submit credentials. On success Keycloak answers with a
                    #    302 to redirect_uri?code=...; on failure it re-renders
                    #    the login page with an inline error message.
                    login = session.post(
                        form_action,
                        data={
                            "username": self._username,
                            "password": self._password,
                            "credentialId": "",
                        },
                        headers={
                            "Referer": str(login_page.url),
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Origin": BASE_URL,
                        },
                        allow_redirects=False,
                        timeout=AUTH_REQUEST_TIMEOUT,
                    )
                    if login.status_code not in {301, 302, 303, 307, 308}:
                        error_text = _extract_keycloak_error_text(login.text)
                        raise BrunataAuthError(
                            error_text
                            or f"Credential submit failed ({login.status_code})"
                        )

                    redirect_location = login.headers.get("Location", "")
                    parsed = urllib.parse.urlparse(redirect_location)
                    code = (urllib.parse.parse_qs(parsed.query).get("code") or [None])[
                        0
                    ]
                    if not code:
                        raise BrunataAuthError("Authorization code missing in redirect")

                    # 4. Exchange the code for tokens at the Brunata auth service.
                    token_payload = {
                        "client_id": CLIENT_ID,
                        "redirect_uri": REDIRECT_URI,
                        "scope": OAUTH_SCOPE,
                        "code": code,
                        "grant_type": "authorization_code",
                        "code_verifier": code_verifier,
                    }
                    resp = session.post(
                        f"{AUTH_BASE_URL}/oauth/token",
                        data=token_payload,
                        headers={
                            "Accept": "application/json, text/plain, */*",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "User-Agent": DEFAULT_HEADERS["User-Agent"],
                            "Referer": REDIRECT_URI,
                        },
                        timeout=AUTH_REQUEST_TIMEOUT,
                    )
                    if resp.status_code < 400:
                        return resp.json()

                    raise BrunataAuthError(
                        f"Token exchange failed ({resp.status_code}: {resp.text[:300]})"
                    )
            except BrunataAuthError:
                raise
            except requests.RequestException as err:
                last_error = err
                if attempt < AUTH_MAX_ATTEMPTS:
                    time.sleep(attempt)
                    continue
                raise BrunataConnectionError(
                    f"Brunata auth request failed ({type(err).__name__}): {err}"
                ) from err

        raise BrunataConnectionError(
            f"Brunata auth flow failed after {AUTH_MAX_ATTEMPTS} attempts: {last_error}"
        )

    @staticmethod
    def _build_date_candidates() -> list[str]:
        today: date = datetime.now(timezone.utc).date()
        first_of_month = today.replace(day=1)
        first_of_previous_month = (first_of_month - timedelta(days=1)).replace(day=1)

        anchor_days = [
            today - timedelta(days=14),
            today - timedelta(days=13),
            today - timedelta(days=7),
            today - timedelta(days=1),
            today,
            first_of_month,
            first_of_previous_month,
        ]

        result: list[str] = []
        for day in anchor_days:
            iso_day = day.isoformat()
            result.extend([f"{iso_day}T00:00:00Z", iso_day])

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

    @classmethod
    def _apply_history_fallbacks(
        cls,
        rows: list[dict[str, Any]],
        history: dict[str, list[dict[str, Any]]],
    ) -> None:
        """Fill missing current readings from the newest historical total.

        Normalizing the payload here keeps transmitter replacement handling out
        of Home Assistant's entity layer and avoids changing sensor.py, which is
        frequently updated independently.
        """
        for row in rows:
            reading = row.get("reading")
            if (
                isinstance(reading, dict)
                and _to_float(reading.get("value")) is not None
            ):
                continue

            points = history.get(cls._meter_history_key(row))
            if not isinstance(points, list):
                continue
            fallback = None
            for point in reversed(points):
                if not isinstance(point, dict):
                    continue
                fallback = _to_float(point.get("value"))
                if fallback is not None:
                    break
            if fallback is None:
                continue

            if not isinstance(reading, dict):
                reading = {}
                row["reading"] = reading
            reading["value"] = fallback
            reading["historicalFallback"] = True

    @staticmethod
    def _meter_history_key(row: dict[str, Any]) -> str:
        meter = row.get("meter") if isinstance(row, dict) else None
        if not isinstance(meter, dict):
            return ""
        return "|".join(
            [
                str(meter.get("meterId") or ""),
                str(meter.get("meterSequenceNo") or ""),
                str(meter.get("meterNo") or ""),
                str(meter.get("allocationUnit") or ""),
            ]
        )

    def _history_startdate_suffixes(self) -> list[str]:
        startdate = self._best_startdate
        candidates: list[str] = []

        if startdate:
            match = re.match(r"^\d{4}-\d{2}-\d{2}(.*)$", startdate)
            if match:
                suffix = match.group(1)
                if suffix:
                    candidates.append(suffix)

        # Brunata rejects date-only startdate in many cases; keep explicit time.
        candidates.extend(["T00:00:00Z", "T00:00:00.000Z", "T00:00:00+01:00"])
        return list(dict.fromkeys(candidates))

    @staticmethod
    def _history_startdate_variants(day_value: date, suffixes: list[str]) -> list[str]:
        day_iso = day_value.isoformat()
        return [f"{day_iso}{suffix}" for suffix in suffixes if suffix]

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


def _to_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip().replace(" ", "")
        if not text:
            return None
        if "," in text and "." in text:
            if text.rfind(",") > text.rfind("."):
                text = text.replace(".", "").replace(",", ".")
            else:
                text = text.replace(",", "")
        elif "," in text:
            text = text.replace(",", ".")
        try:
            return float(text)
        except ValueError:
            return None
    return None


def _to_date(value: Any) -> date | None:
    """Parse the date portion of a Brunata timestamp."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def _pkce_s256_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _extract_login_form_action(page_html: str) -> str:
    """Return the Keycloak login form action URL.

    The Keycloak login template posts credentials to a one-time
    ``login-actions/authenticate`` URL carrying ``session_code`` /
    ``execution`` / ``tab_id`` query parameters.
    """
    patterns = (
        r'<form[^>]*\bid="kc-form-login"[^>]*\baction="([^"]+)"',
        r'action="([^"]*login-actions/authenticate[^"]*)"',
    )
    for pattern in patterns:
        match = re.search(pattern, page_html, flags=re.IGNORECASE)
        if match:
            return html.unescape(match.group(1))

    raise BrunataAuthError("Could not locate Keycloak login form")


def _validate_credential_post_url(url: str) -> None:
    """Reject a login form that could send credentials outside Brunata."""
    parsed = urllib.parse.urlparse(url)
    expected = urllib.parse.urlparse(BASE_URL)
    try:
        port = parsed.port
    except ValueError as err:
        raise BrunataAuthError(
            "Keycloak returned an unsafe credential form URL"
        ) from err
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected.hostname
        or port not in {None, 443}
        or not parsed.path.startswith("/iam/realms/online-prod/login-actions/")
    ):
        raise BrunataAuthError("Keycloak returned an unsafe credential form URL")


def _extract_keycloak_error_text(page_html: str) -> str | None:
    """Extract the inline error from a re-rendered Keycloak login page."""
    patterns = (
        r'class="[^"]*kc-feedback-text[^"]*"[^>]*>(.*?)</span>',
        r'class="[^"]*alert-error[^"]*"[^>]*>(.*?)</div>',
        r'id="input-error[^"]*"[^>]*>(.*?)<',
    )
    for pattern in patterns:
        match = re.search(pattern, page_html, flags=re.IGNORECASE | re.DOTALL)
        if match:
            text = re.sub(r"<[^>]+>", " ", match.group(1))
            text = re.sub(r"\s+", " ", html.unescape(text)).strip()
            if text:
                return text
    return None


__all__ = ["BrunataAuthError", "BrunataConnectionError", "BrunataOnlineClient"]
