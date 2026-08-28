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
import html
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
API_BASE_URL = f"{BASE_URL}/online-webservice/v2/rest"
AUTH_BASE_URL = f"{BASE_URL}/online-auth-webservice/v1/rest"

# Brunata migrated from Azure AD B2C to Keycloak (realm "online-prod") in 2026-05.
KEYCLOAK_AUTH_URL = f"{BASE_URL}/iam/realms/online-prod/protocol/openid-connect/auth"
CLIENT_ID = "82770188-c92e-4d16-927d-a15c472eda55"
REDIRECT_URI = f"{BASE_URL}/mybrunata/auth-redirect"
OAUTH_SCOPE = "openid offline_access"

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


def _extract_login_form_action(page_html: str) -> str:
    """Return the Keycloak login form action URL (login-actions/authenticate)."""
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


def _pkce_s256_challenge(code_verifier: str) -> str:
    import base64
    import hashlib

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def authenticate(username: str, password: str) -> tuple[requests.Session, TokenData]:
    """Run Brunata's Keycloak auth flow and return a bearer token."""
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    code_verifier = secrets.token_hex(48)
    code_challenge = _pkce_s256_challenge(code_verifier)

    # 1. Load the Keycloak login page (sets AUTH_SESSION_ID / KC_RESTART cookies).
    login_page = session.get(
        KEYCLOAK_AUTH_URL,
        params={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": OAUTH_SCOPE,
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        timeout=REQUEST_TIMEOUT,
    )
    login_page.raise_for_status()

    # 2. Submit credentials to the one-time login-actions/authenticate URL.
    form_action = _extract_login_form_action(login_page.text)
    _validate_credential_post_url(form_action)
    login = session.post(
        form_action,
        data={"username": username, "password": password, "credentialId": ""},
        headers={
            "Referer": str(login_page.url),
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": BASE_URL,
        },
        allow_redirects=False,
        timeout=REQUEST_TIMEOUT,
    )
    if login.status_code not in {301, 302, 303, 307, 308}:
        err = _extract_keycloak_error_text(login.text)
        raise BrunataAuthError(err or f"Credential submit failed ({login.status_code})")

    redirect_location = login.headers.get("Location", "")
    parsed = urllib.parse.urlparse(redirect_location)
    code = (urllib.parse.parse_qs(parsed.query).get("code") or [None])[0]
    if not code:
        raise BrunataAuthError("Authorization code missing in redirect")

    # 3. Exchange the code for tokens at the Brunata auth service.
    resp = session.post(
        f"{AUTH_BASE_URL}/oauth/token",
        data={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": OAUTH_SCOPE,
            "code": code,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        },
        headers={
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": DEFAULT_HEADERS["User-Agent"],
            "Referer": REDIRECT_URI,
        },
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code >= 400:
        raise BrunataAuthError(
            f"Token exchange failed ({resp.status_code}: {resp.text[:300]})"
        )

    tokens = resp.json()
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


def meter_key(row: dict[str, Any]) -> str:
    """Return the stable identity shared by a meter across API snapshots."""
    meter = row.get("meter") if isinstance(row.get("meter"), dict) else None
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


def reading_score(row: dict[str, Any], start_date: str) -> tuple[int, str, str]:
    """Rank a meter row by validity and freshness."""
    reading = row.get("reading")
    value_is_valid = int(
        isinstance(reading, dict)
        and reading.get("value") is not None
        and not isinstance(reading.get("value"), bool)
    )
    reading_date = (
        str(reading.get("readingDate") or "") if isinstance(reading, dict) else ""
    )
    return value_is_valid, reading_date, start_date


def pick_best_meter_payload(
    session: requests.Session, token: str
) -> tuple[str | None, list[dict[str, Any]], list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    best_date: str | None = None
    best_rows_by_meter: dict[str, tuple[tuple[int, str, str], dict[str, Any]]] = {}

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
            best_date = max(best_date or start_date, start_date)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                key = meter_key(row)
                if not key:
                    continue
                score = reading_score(row, start_date)
                existing = best_rows_by_meter.get(key)
                if existing is None or score > existing[0]:
                    best_rows_by_meter[key] = (score, row)
        except requests.HTTPError as err:
            attempts.append(
                {"startdate": start_date, "status": "http_error", "error": str(err)}
            )
        except Exception as err:  # pylint: disable=broad-except
            attempts.append(
                {"startdate": start_date, "status": "error", "error": str(err)}
            )

    best_rows = [item[1] for item in best_rows_by_meter.values()]
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
        best_date, meters, attempts = pick_best_meter_payload(
            session, token_data.access_token
        )
        try:
            super_units = api_get_json(
                session, token_data.access_token, "/consumer/superallocationunits"
            )
        except Exception:
            super_units = None
    except Exception as err:  # pylint: disable=broad-except
        print(f"Failed to fetch Brunata data: {err}")
        return 3
    finally:
        session.close()

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
    consumer_name = consumer.get("consumerName") if isinstance(consumer, dict) else "?"
    print(f"Consumer  : {consumer_name}")
    print(f"Best date : {best_date}")
    print(f"Rows      : {len(meters)}")
    print(f"Readings  : {count_non_null_values(meters)} non-null")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
