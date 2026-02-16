"""Brunata Online API Client (Home Assistant integration).

This module implements:
- Azure AD B2C username/password login (OAuth2 code+PKCE) for Brunata Online
- API calls against https://online.brunata.com/online-webservice/v1/rest

The implementation is intentionally defensive:
- token refresh when possible
- fall back to full login when refresh is not possible
- retry once on 401
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import re
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from aiohttp import ClientResponseError, ClientSession, ClientTimeout
import requests

_LOGGER: logging.Logger = logging.getLogger(__package__)

BASE_URL = "https://online.brunata.com"
API_BASE_URL = f"{BASE_URL}/online-webservice/v1/rest"
AUTH_BASE_URL = f"{BASE_URL}/online-auth-webservice/v1/rest"

OAUTH2_PROFILE = "B2C_1_signin_username"
AUTHN_URL = (
    f"https://brunatab2cprod.b2clogin.com/brunatab2cprod.onmicrosoft.com/{OAUTH2_PROFILE}"
)
OAUTH2_URL = f"{AUTHN_URL}/oauth2/v2.0"

# Two known Brunata Online OAuth client configs exist in production.
# - PRIMARY: used by the "Resident Portal" (React) on online.brunata.com
# - SECONDARY: used by the main portal on online.brunata.com
CLIENT_ID_PRIMARY = "e1d10965-78dc-4051-a1e5-251483e74d03"
REDIRECT_PRIMARY = f"{BASE_URL}/auth-response"

CLIENT_ID_SECONDARY = "82770188-c92e-4d16-927d-a15c472eda55"
REDIRECT_SECONDARY = f"{BASE_URL}/auth-redirect"

DEFAULT_HEADERS: dict[str, str] = {
    # Keep this UA stable to avoid triggering bot heuristics.
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


class BrunataOnlineAuthError(Exception):
    """Raised when authentication fails."""


@dataclass
class _TokenState:
    access_token: str | None = None
    token_type: str = "Bearer"
    access_expires_at: float = 0.0  # epoch seconds
    refresh_token: str | None = None
    refresh_expires_at: float = 0.0  # epoch seconds
    client_id: str | None = None
    redirect_uri: str | None = None

    def access_valid(self, now: float) -> bool:
        return bool(self.access_token) and now < (self.access_expires_at - 60)

    def refresh_valid(self, now: float) -> bool:
        # Some Azure responses omit refresh-token expiry fields.
        # In that case refresh_expires_at stays <= 0 and we treat it as unknown-but-usable.
        return bool(self.refresh_token) and (
            self.refresh_expires_at <= 0 or now < (self.refresh_expires_at - 60)
        )


def _to_base64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").replace("=", "")


def _new_code_verifier() -> str:
    verifier = _to_base64url_no_pad(os.urandom(40))
    # Azure B2C accepts unreserved chars; keep it simple.
    return re.sub(r"[^a-zA-Z0-9]+", "", verifier)


def _code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return _to_base64url_no_pad(digest)


def _epoch_from_token_field(value: Any) -> float | None:
    """Parse AAD-style *expires_on* fields if present."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compute_expiry(
    now: float,
    tokens: dict[str, Any],
    on_key: str,
    in_key: str,
    default_seconds: float = 0,
) -> float:
    """Return epoch seconds for expiry, with a conservative fallback."""
    ts = _epoch_from_token_field(tokens.get(on_key))
    if ts is not None and ts > 0:
        return ts
    try:
        seconds = float(tokens.get(in_key, 0))
    except (TypeError, ValueError):
        seconds = 0
    if seconds <= 0:
        seconds = default_seconds
    return now + seconds


class BrunataOnlineApiClient:
    """Brunata Online API Client used by the Home Assistant integration."""

    def __init__(self, username: str, password: str, session: ClientSession) -> None:
        self._username = username
        self._password = password
        self._session = session
        self._session.headers.update(DEFAULT_HEADERS)

        self._token_state = _TokenState()
        self._token_lock = asyncio.Lock()

    async def async_get_data(self) -> dict[str, Any]:
        """Fetch data that will back Home Assistant entities."""
        # Get meter values (measuring points) for "today" in UTC.
        # The API expects an ISO string; the portal uses Luxon DateTime.toISO().
        date_dt = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        date_param = date_dt.isoformat().replace("+00:00", "Z")

        buildings: list[dict[str, Any]] = await self._api_get_json("/buildings")
        buildings_by_no: dict[str, dict[str, Any]] = {}
        points_by_id: dict[str, dict[str, Any]] = {}

        for b in buildings:
            building_no = b.get("buildingNo")
            if building_no is None:
                continue
            building_no = str(building_no)
            buildings_by_no[building_no] = b

            try:
                points = await self._api_get_json(
                    f"/buildings/{urllib.parse.quote(building_no)}/measuringpoints",
                    params={"date": date_param},
                )
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.debug("Failed fetching measuring points for building %s: %s", building_no, err)
                continue

            # API shape in the webapp is { measuringPoints: [...] }.
            if isinstance(points, dict) and "measuringPoints" in points:
                points_list = points.get("measuringPoints") or []
            else:
                points_list = points if isinstance(points, list) else []

            for p in points_list:
                if not isinstance(p, dict):
                    continue
                serial = p.get("serialNo") or p.get("printedSerialNo") or p.get("meterSequenceNo")
                point_key = str(serial) if serial is not None else str(len(points_by_id))
                point_id = f"{building_no}:{point_key}"
                p["_buildingNo"] = building_no
                p["_id"] = point_id
                points_by_id[point_id] = p

        return {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "buildings": buildings_by_no,
            "measuring_points": points_by_id,
            "date": date_param,
        }

    async def _api_get_json(self, path: str, params: dict[str, str] | None = None) -> Any:
        """GET JSON from Brunata Online API, retrying once on 401."""
        await self._ensure_access_token()

        url = f"{API_BASE_URL}{path}"
        headers = {"Authorization": f"{self._token_state.token_type} {self._token_state.access_token}"}

        try:
            async with self._session.get(
                url, params=params, headers=headers, timeout=REQUEST_TIMEOUT
            ) as resp:
                resp.raise_for_status()
                return await resp.json()
        except ClientResponseError as e:
            if e.status == 401:
                # Token likely expired/revoked; force refresh and retry once.
                await self._ensure_access_token(force=True)
                headers = {"Authorization": f"{self._token_state.token_type} {self._token_state.access_token}"}
                async with self._session.get(
                    url, params=params, headers=headers, timeout=REQUEST_TIMEOUT
                ) as resp:
                    resp.raise_for_status()
                    return await resp.json()
            raise

    async def _ensure_access_token(self, force: bool = False) -> None:
        """Ensure we have a valid access token in self._token_state."""
        async with self._token_lock:
            now = time.time()
            if not force and self._token_state.access_valid(now):
                return

            # Try refresh token first (if any).
            if self._token_state.refresh_valid(now) and self._token_state.client_id:
                try:
                    tokens = await self._refresh_tokens(
                        client_id=self._token_state.client_id,
                        refresh_token=self._token_state.refresh_token or "",
                    )
                    self._update_token_state(tokens, client_id=self._token_state.client_id, redirect_uri=self._token_state.redirect_uri)
                    return
                except Exception as err:  # pylint: disable=broad-except
                    _LOGGER.debug("Refresh token failed; falling back to full login: %s", err)
                    self._token_state = _TokenState()

            # Full login (try primary, then secondary config).
            last_err: Exception | None = None
            for client_id, redirect_uri in (
                (CLIENT_ID_PRIMARY, REDIRECT_PRIMARY),
                (CLIENT_ID_SECONDARY, REDIRECT_SECONDARY),
            ):
                for challenge_method in ("S256", "plain"):
                    try:
                        tokens = await asyncio.to_thread(
                            self._b2c_auth_sync,
                            client_id=client_id,
                            redirect_uri=redirect_uri,
                            code_challenge_method=challenge_method,
                        )
                        self._update_token_state(
                            tokens, client_id=client_id, redirect_uri=redirect_uri
                        )
                        return
                    except Exception as err:  # pylint: disable=broad-except
                        last_err = err
                        continue

            raise BrunataOnlineAuthError("Failed to authenticate against Brunata Online") from last_err

    async def _refresh_tokens(self, client_id: str, refresh_token: str) -> dict[str, Any]:
        data = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "scope": f"{client_id} offline_access",
            "refresh_token": refresh_token,
        }
        async with self._session.post(
            f"{OAUTH2_URL}/token", data=data, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT
        ) as resp:
            # Keep the error body, but don't log tokens.
            _ = await resp.text()
            if resp.status >= 400:
                raise BrunataOnlineAuthError(f"Refresh token request failed ({resp.status})")
            try:
                return await resp.json()
            except Exception as err:  # pylint: disable=broad-except
                raise BrunataOnlineAuthError("Failed to parse refresh token response") from err

    def _update_token_state(self, tokens: dict[str, Any], client_id: str, redirect_uri: str | None) -> None:
        now = time.time()
        access = tokens.get("access_token")
        if not access:
            raise BrunataOnlineAuthError("No access_token in token response")

        token_type = tokens.get("token_type") or "Bearer"
        access_expires_at = _compute_expiry(
            now, tokens, "expires_on", "expires_in", default_seconds=300
        )
        refresh_expires_at = _compute_expiry(
            now,
            tokens,
            "refresh_token_expires_on",
            "refresh_token_expires_in",
            default_seconds=0,
        )

        self._token_state = _TokenState(
            access_token=str(access),
            token_type=str(token_type),
            access_expires_at=float(access_expires_at),
            refresh_token=str(tokens.get("refresh_token")) if tokens.get("refresh_token") else None,
            refresh_expires_at=float(refresh_expires_at),
            client_id=client_id,
            redirect_uri=redirect_uri,
        )

    def _b2c_auth_sync(
        self, client_id: str, redirect_uri: str, code_challenge_method: str
    ) -> dict[str, Any]:
        """Blocking Azure B2C login flow. Run in a thread via asyncio.to_thread()."""
        code_verifier = _new_code_verifier()
        code_challenge = (
            code_verifier
            if code_challenge_method == "plain"
            else _code_challenge_s256(code_verifier)
        )

        with requests.Session() as s:
            s.headers.update(DEFAULT_HEADERS)

            # 1) Get initial auth page (follows redirects to B2C login HTML).
            req_code = s.get(
                f"{AUTH_BASE_URL}/authorize",
                params={
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": f"{client_id} offline_access",
                    "response_type": "code",
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                },
                timeout=30,
            )
            req_code.raise_for_status()

            csrf_token = req_code.cookies.get("x-ms-cpim-csrf")
            if not csrf_token:
                raise BrunataOnlineAuthError("Missing CSRF cookie during B2C auth")

            # 2) Extract transaction ID from the login HTML.
            settings_match = re.search(r"var SETTINGS = (\{[^;]*\});", req_code.text)
            if not settings_match:
                raise BrunataOnlineAuthError("Failed to locate B2C SETTINGS in login page")

            settings_txt = settings_match.group(1)
            trans_match = re.search(r'"transId"\s*:\s*"([^"]+)"', settings_txt)
            if not trans_match:
                # Fallback for slightly different formatting
                trans_match = re.search(r'transId"\s*:\s*"([^"]+)"', settings_txt)
            if not trans_match:
                raise BrunataOnlineAuthError("Failed to extract transaction id from login page")
            transaction_id = trans_match.group(1)

            # 3) Post credentials.
            s.post(
                f"{AUTHN_URL}/SelfAsserted",
                params={"tx": transaction_id, "p": OAUTH2_PROFILE},
                data={
                    "request_type": "RESPONSE",
                    "logonIdentifier": self._username,
                    "password": self._password,
                },
                headers={
                    "Referer": str(req_code.url),
                    "X-Csrf-Token": csrf_token,
                    "X-Requested-With": "XMLHttpRequest",
                },
                allow_redirects=False,
                timeout=30,
            )

            # 4) Confirm login, capture auth code via redirect Location.
            req_auth = s.get(
                f"{AUTHN_URL}/api/CombinedSigninAndSignup/confirmed",
                params={
                    "rememberMe": "false",
                    "csrf_token": csrf_token,
                    "tx": transaction_id,
                    "p": OAUTH2_PROFILE,
                },
                allow_redirects=False,
                timeout=30,
            )
            location = req_auth.headers.get("Location")
            if not location:
                raise BrunataOnlineAuthError("Missing redirect Location while retrieving auth code")
            if not location.startswith(redirect_uri):
                raise BrunataOnlineAuthError("Unexpected redirect target while retrieving auth code")

            parsed = urllib.parse.urlparse(location)
            qs = urllib.parse.parse_qs(parsed.query)
            code = (qs.get("code") or [None])[0]
            if not code:
                raise BrunataOnlineAuthError("Auth code not found in redirect URL")

            # 5) Exchange code for tokens.
            token_resp = s.post(
                f"{OAUTH2_URL}/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": f"{client_id} offline_access",
                    "code": code,
                    "code_verifier": code_verifier,
                },
                timeout=30,
            )
            token_resp.raise_for_status()
            return token_resp.json()
