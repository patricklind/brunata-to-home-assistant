#!/usr/bin/env python3
"""Fetch meter data from online.brunata.com into JSON/CSV.

Environment variables (from .env):
  - BRUNATA_USERNAME
  - BRUNATA_PASSWORD
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any
import urllib.parse

from dotenv import load_dotenv
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

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

REQUEST_TIMEOUT = 30
OUT_DIR = Path("output")
OUT_JSON = OUT_DIR / "brunata_data.json"
OUT_CSV = OUT_DIR / "brunata_meters.csv"


class BrunataAuthError(Exception):
    """Raised when Brunata auth fails."""


@dataclass
class TokenData:
    access_token: str
    refresh_token: str | None
    raw: dict[str, Any]


def _new_code_verifier(length: int = 56) -> str:
    """Frontend uses a 56-char hex code verifier/challenge with method=plain."""
    if length % 2 != 0:
        raise ValueError("length must be even")
    return secrets.token_hex(length // 2)


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


def authenticate(username: str, password: str) -> tuple[requests.Session, TokenData]:
    """Run Brunata's browser-like auth flow and return bearer token."""
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    code_verifier = _new_code_verifier(56)
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
        timeout=REQUEST_TIMEOUT,
    )
    req_code.raise_for_status()

    tx = _extract_transaction_id(str(req_code.url), req_code.text)
    csrf = _extract_csrf_token(req_code)

    self_asserted = session.post(
        f"{AUTHN_URL}/SelfAsserted",
        params={"tx": tx, "p": OAUTH2_PROFILE},
        data={
            "request_type": "RESPONSE",
            "logonIdentifier": username,
            "password": password,
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
        timeout=REQUEST_TIMEOUT,
    )
    if self_asserted.status_code >= 400:
        err = _extract_b2c_error_text(self_asserted.text)
        raise BrunataAuthError(
            err or f"Credential submit failed ({self_asserted.status_code})"
        )

    try:
        payload = self_asserted.json()
    except ValueError:
        payload = {}
    if isinstance(payload, dict):
        status = str(payload.get("status", ""))
        if status and status not in {"200", "201"}:
            err = _extract_b2c_error_text(str(payload)) or str(
                payload.get("message") or ""
            )
            raise BrunataAuthError(err or f"Credential submit returned status {status}")

    confirmed = session.get(
        f"{AUTHN_URL}/api/CombinedSigninAndSignup/confirmed",
        params={
            "rememberMe": "false",
            "csrf_token": csrf,
            "tx": tx,
            "p": OAUTH2_PROFILE,
        },
        allow_redirects=False,
        timeout=REQUEST_TIMEOUT,
    )
    if confirmed.status_code >= 400:
        err = _extract_b2c_error_text(confirmed.text)
        raise BrunataAuthError(err or f"Signin confirmation failed ({confirmed.status_code})")

    redirect_location = _extract_location_url(confirmed)
    parsed = urllib.parse.urlparse(redirect_location)
    code = (urllib.parse.parse_qs(parsed.query).get("code") or [None])[0]
    if not code:
        raise BrunataAuthError("Authorization code missing in redirect")

    token_payload_variants = (
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

    token_response = None
    last_error = None
    for data in token_payload_variants:
        resp = session.post(
            f"{AUTH_BASE_URL}/oauth/token",
            data=data,
            headers={
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": DEFAULT_HEADERS["User-Agent"],
            },
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code < 400:
            token_response = resp
            break
        last_error = f"{resp.status_code}: {resp.text[:300]}"

    if token_response is None:
        raise BrunataAuthError(f"Token exchange failed ({last_error})")

    tokens = token_response.json()
    access_token = tokens.get("access_token")
    if not access_token:
        raise BrunataAuthError("No access_token in token response")

    return (
        session,
        TokenData(
            access_token=str(access_token),
            refresh_token=(
                str(tokens["refresh_token"]) if tokens.get("refresh_token") else None
            ),
            raw=tokens,
        ),
    )


def api_get_json(
    session: requests.Session,
    token: str,
    path: str,
    params: dict[str, str] | None = None,
) -> Any:
    url = f"{API_BASE_URL}{path}"
    resp = session.get(
        url,
        params=params,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": DEFAULT_HEADERS["User-Agent"],
        },
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def build_date_candidates(days_back: int = 14) -> list[str]:
    """Try several date encodings. We keep the one with most non-null readings."""
    now_utc = datetime.now(timezone.utc)
    out: list[str] = []
    for offset in range(days_back, -1, -1):
        d = (now_utc - timedelta(days=offset)).date()
        iso_day = d.isoformat()
        out.extend(
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
    # De-duplicate while preserving order
    return list(dict.fromkeys(out))


def count_non_null_values(meters: Any) -> int:
    if not isinstance(meters, list):
        return 0
    count = 0
    for row in meters:
        if not isinstance(row, dict):
            continue
        reading = row.get("reading")
        if isinstance(reading, dict) and reading.get("value") is not None:
            count += 1
    return count


def pick_best_meter_payload(
    session: requests.Session, token: str
) -> tuple[str | None, list[dict[str, Any]], list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    best_date: str | None = None
    best_rows: list[dict[str, Any]] = []
    best_score = (-1, -1)  # (non_null_readings, rows_count)

    for start_date in build_date_candidates():
        try:
            rows = api_get_json(
                session,
                token,
                "/consumer/meters",
                params={"startdate": start_date},
            )
            if not isinstance(rows, list):
                attempts.append(
                    {
                        "startdate": start_date,
                        "status": "ok_non_list",
                        "rows": 0,
                        "non_null": 0,
                    }
                )
                continue
            non_null = count_non_null_values(rows)
            row_count = len(rows)
            attempts.append(
                {
                    "startdate": start_date,
                    "status": "ok",
                    "rows": row_count,
                    "non_null": non_null,
                }
            )
            score = (non_null, row_count)
            if score > best_score:
                best_score = score
                best_date = start_date
                best_rows = rows
        except requests.HTTPError as err:
            attempts.append(
                {"startdate": start_date, "status": "http_error", "error": str(err)}
            )
        except Exception as err:  # pylint: disable=broad-except
            attempts.append(
                {"startdate": start_date, "status": "error", "error": str(err)}
            )

    return best_date, best_rows, attempts


def to_csv_rows(meters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in meters:
        meter = item.get("meter") if isinstance(item, dict) else {}
        reading = item.get("reading") if isinstance(item, dict) else {}
        if not isinstance(meter, dict):
            meter = {}
        if not isinstance(reading, dict):
            reading = {}

        rows.append(
            {
                "meter_no": meter.get("meterNo"),
                "placement": meter.get("placement"),
                "meter_type": meter.get("meterType"),
                "allocation_unit": meter.get("allocationUnit"),
                "unit_code": meter.get("unit"),
                "reading_value": reading.get("value"),
                "reading_date": reading.get("readingDate"),
                "mounting_date": meter.get("mountingDate"),
                "dismounted_date": meter.get("dismountedDate"),
                "meter_id": meter.get("meterId"),
                "meter_sequence_no": meter.get("meterSequenceNo"),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "meter_no",
        "placement",
        "meter_type",
        "allocation_unit",
        "unit_code",
        "reading_value",
        "reading_date",
        "mounting_date",
        "dismounted_date",
        "meter_id",
        "meter_sequence_no",
    ]
    with path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    load_dotenv()
    username = os.getenv("BRUNATA_USERNAME")
    password = os.getenv("BRUNATA_PASSWORD")
    if not username or not password:
        print("Missing BRUNATA_USERNAME or BRUNATA_PASSWORD in environment/.env")
        return 1

    try:
        session, token_data = authenticate(username, password)
    except Exception as err:  # pylint: disable=broad-except
        print(f"Authentication failed: {err}")
        return 2

    try:
        consumer = api_get_json(session, token_data.access_token, "/consumer")
    except Exception as err:  # pylint: disable=broad-except
        print(f"Failed to fetch /consumer: {err}")
        return 3

    best_date, meters, attempts = pick_best_meter_payload(session, token_data.access_token)
    try:
        super_units = api_get_json(
            session, token_data.access_token, "/consumer/superallocationunits"
        )
    except Exception:
        super_units = None

    result = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "consumer": consumer,
        "best_startdate": best_date,
        "meter_rows_count": len(meters),
        "non_null_readings": count_non_null_values(meters),
        "meters": meters,
        "consumer_superallocationunits": super_units,
        "attempts": attempts,
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    write_csv(OUT_CSV, to_csv_rows(meters))

    print(f"Wrote JSON: {OUT_JSON}")
    print(f"Wrote CSV : {OUT_CSV}")
    print(f"Consumer  : {consumer.get('consumerName') if isinstance(consumer, dict) else '?'}")
    print(f"Best date : {best_date}")
    print(f"Rows      : {len(meters)}")
    print(f"Readings  : {count_non_null_values(meters)} non-null")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
