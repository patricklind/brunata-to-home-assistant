# Security Best-Practices Review

## Executive summary

The integration has a small, read-only attack surface and no critical, high, or
medium-severity security findings were identified. Authentication uses HTTPS,
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

None identified.

## Medium

None identified.

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
- The project has no database, upload surface, application-owned web frontend,
  cookies, authorization roles, writable API, or server-rendered HTML; related
  controls are not applicable.
- Home Assistant runtime storage and platform-level secret protection remain the
  responsibility of the host Home Assistant installation.
