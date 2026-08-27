# Security Best-Practices Review

## Executive summary

The integration has a small, read-only attack surface. One high-severity access
control issue in the sidebar panel was identified and fixed; no critical or
unresolved high-severity findings remain. Authentication uses HTTPS,
PKCE with a cryptographically secure verifier, validates the Keycloak credential
POST destination before transmitting credentials, keeps tokens in memory, and
applies bounded request timeouts and retries.

One vulnerable development/runtime dependency used by the standalone diagnostic
client was found and upgraded. Automated source scanning reported two low-level
items; both were reviewed as non-exploitable/intentional behavior and are
documented below.

## Critical

None identified.

## High

### SEC-004 — Panel meter data available to non-admin users (fixed)

- Affected files: `custom_components/brunata_online/panel.py` and
  `custom_components/brunata_online/frontend.py`
- Finding: the sidebar and its WebSocket data command were available to every
  authenticated Home Assistant user. The payload includes meter placement,
  number, readings, and history.
- Impact: a non-administrator with HA access could read private consumption and
  meter information.
- Fix: the sidebar declares `require_admin=True`, and the WebSocket command is
  independently protected with `websocket_api.require_admin`. The settings
  update command uses the same independent admin check, validates its values,
  and persists only normalized display preferences.
- Verification: `tests/test_panel.py` asserts both commands carry the admin
  requirement and verifies settings normalization and persistence.

## Medium

### SEC-005 — Authentication failures did not initiate reauthentication (fixed)

- Affected files: `custom_components/brunata_online/__init__.py` and
  `custom_components/brunata_online/config_flow.py`
- Finding: rejected credentials became a generic coordinator update failure.
- Impact: the integration stayed unavailable without offering a supported path
  to replace the stored password.
- Fix: authentication failures now raise `ConfigEntryAuthFailed`; the reauth
  flow validates the replacement password, preserves the username and existing
  entry, and reloads the integration.
- Verification: success and failure paths are covered by
  `tests/test_config_flow.py`.

## Low

### SEC-001 — Vulnerable `python-dotenv` release (fixed)

- Affected file: `requirements.txt:1`
- Finding: `pip-audit` identified `python-dotenv 1.0.1` as affected by
  `PYSEC-2026-2270`.
- Impact: the standalone diagnostic client loads Brunata credentials from an
  environment file, so defects in this boundary deserve prompt remediation.
- Fix: upgraded to the audited fixed release, `python-dotenv 1.2.2`.
- Verification: `python -m pip_audit -r requirements.txt` reports no known
  vulnerabilities.

## Informational findings

### SEC-002 — Broad exception handling during history-format fallback

- Affected file: `custom_components/brunata_online/api.py:293`
- Finding: Bandit B112 flags the `except Exception: continue` used while trying
  alternative Brunata date formats.
- Assessment: intentional and bounded. Each attempt has a strict timeout, the
  number of variants is fixed, and complete day failure is counted in returned
  history metadata. It does not bypass authentication or validation.
- Action: no code change; retaining fallback behavior avoids breaking accounts
  whose Brunata endpoint accepts only one date representation.

### SEC-003 — Configuration key named `password`

- Affected file: `custom_components/brunata_online/const.py:13`
- Finding: Bandit B105 interprets the string `"password"` as a hardcoded secret.
- Assessment: false positive. This is a Home Assistant configuration field name,
  not a credential value.
- Action: no code change.

## Scope and limitations

- Reviewed Python integration code, OAuth/PKCE handling, external HTTP calls,
  configuration flow, local diagnostic tooling, dependency declarations, and CI.
- Secret-history searches found no supplied account credential in tracked Git
  history.
- The project has no database, upload surface, application-owned cookies,
  writable external API, or server-rendered HTML. It does have a custom
  JavaScript sidebar panel and authenticated Home Assistant WebSocket command;
  their authorization and output-encoding boundaries were included in scope.
- Home Assistant runtime storage and platform-level secret protection remain the
  responsibility of the host Home Assistant installation.
- A live non-admin/admin authorization test was not available in the static
  review environment.
