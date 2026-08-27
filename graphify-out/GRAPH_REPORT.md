# Graph Report - brunata-to-home-assistant  (2026-08-27)

## Corpus Check
- 21 files · ~11,360 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 475 nodes · 979 edges · 24 communities (19 shown, 5 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 72 edges (avg confidence: 0.54)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `fd09373f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]

## God Nodes (most connected - your core abstractions)
1. `BrunataOnlineClient` - 35 edges
2. `Any` - 31 edges
3. `SensorDeviceClass` - 25 edges
4. `SensorStateClass` - 25 edges
5. `BrunataAuthError` - 24 edges
6. `BrunataMeterSensor` - 17 edges
7. `Any` - 14 edges
8. `datetime` - 14 edges
9. `_BrunataAggregateWaterBase` - 14 edges
10. `_current_or_history_value()` - 13 edges

## Surprising Connections (you probably didn't know these)
- `Brunata Online integration` --collects_feature_requests_for--> `Feature request template`  [INFERRED]
  custom_components/brunata_online/manifest.json → .github/ISSUE_TEMPLATE/feature_request.md
- `Brunata Online integration` --collects_bug_reports_for--> `Issue report template`  [INFERRED]
  custom_components/brunata_online/manifest.json → .github/ISSUE_TEMPLATE/issue.md
- `Brunata Online integration` --validates--> `HACS validation`  [EXTRACTED]
  custom_components/brunata_online/manifest.json → .github/workflows/tests.yaml
- `Brunata Online integration` --validates--> `Hassfest validation`  [EXTRACTED]
  custom_components/brunata_online/manifest.json → .github/workflows/tests.yaml
- `Brunata Online integration` --extends--> `Home Assistant`  [EXTRACTED]
  custom_components/brunata_online/manifest.json → README.md

## Import Cycles
- 1-file cycle: `custom_components/brunata_online/sensor.py -> custom_components/brunata_online/sensor.py`
- 2-file cycle: `custom_components/brunata_online/const.py -> custom_components/brunata_online/sensor.py -> custom_components/brunata_online/const.py`
- 3-file cycle: `custom_components/brunata_online/__init__.py -> custom_components/brunata_online/api.py -> custom_components/brunata_online/sensor.py -> custom_components/brunata_online/__init__.py`
- 3-file cycle: `custom_components/brunata_online/__init__.py -> custom_components/brunata_online/const.py -> custom_components/brunata_online/sensor.py -> custom_components/brunata_online/__init__.py`

## Communities (24 total, 5 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.07
Nodes (51): BrunataAuthError, BrunataConnectionError, BrunataOnlineClient, _extract_keycloak_error_text(), _extract_login_form_action(), _pkce_s256_challenge(), Async API client for Brunata Online., Validate credentials and basic API reachability.          This is intentionally (+43 more)

### Community 1 - "Community 1"
Cohesion: 0.06
Nodes (71): AddEntitiesCallback, Constants for Brunata Online integration., _all_meter_rows(), async_setup_entry(), _BrunataAggregateWaterBase, BrunataAggregateWaterLastDaysSensor, BrunataAggregateWaterTotalSensor, BrunataDistributedMeterSensor (+63 more)

### Community 2 - "Community 2"
Cohesion: 0.07
Nodes (37): Brunata Daily Cold Water, Brunata Daily Hot Water, Brunata Daily Water Limit, Brunata Daily Water, Brunata Hot Water Share This Month, Brunata Hot Water Share Today, Brunata Daily Water Limit Exceeded, Brunata Monthly Cold Water (+29 more)

### Community 3 - "Community 3"
Cohesion: 0.11
Nodes (23): _anonymous_meter_reference(), async_get_config_entry_diagnostics(), _diagnostic_data(), _diagnostic_history(), _diagnostic_meter(), _meter_key(), Diagnostics support for Brunata Online., Return redacted diagnostics for a config entry. (+15 more)

### Community 4 - "Community 4"
Cohesion: 0.07
Nodes (30): Aggregate water sensors, Bearer token, Black, Brunata Online integration, Brunata Online, Home Assistant config flow, Danish config-flow translation, debugpy (+22 more)

### Community 5 - "Community 5"
Cohesion: 0.08
Nodes (18): Exception, ClientError, ClientResponseError, ClientSession, ClientTimeout, CredentialPostUrlTests, CurrentMeterSelectionTests, DebugClientMeterSelectionTests (+10 more)

### Community 6 - "Community 6"
Cohesion: 0.10
Nodes (44): api_get_json(), authenticate(), BrunataAuthError, build_date_candidates(), count_non_null_values(), _extract_keycloak_error_text(), _extract_login_form_action(), main() (+36 more)

### Community 7 - "Community 7"
Cohesion: 0.12
Nodes (14): already_configured, config, abort, error, step, password, username, auth (+6 more)

### Community 8 - "Community 8"
Cohesion: 0.12
Nodes (14): already_configured, config, abort, error, step, password, username, auth (+6 more)

### Community 9 - "Community 9"
Cohesion: 0.30
Nodes (10): codeowners, config_flow, documentation, domain, iot_class, issue_tracker, loggers, name (+2 more)

### Community 10 - "Community 10"
Cohesion: 0.33
Nodes (5): content_in_root, country, homeassistant, name, render_readme

### Community 11 - "Community 11"
Cohesion: 0.50
Nodes (4): Brunata Online Brand Logo, Brunata Wordmark, Online Wordmark, Red and Blue Divider

### Community 12 - "Community 12"
Cohesion: 0.67
Nodes (3): Dependabot, GitHub Actions dependencies, pip dependencies

### Community 13 - "Community 13"
Cohesion: 0.67
Nodes (3): GitHub Release, Integration manifest version, Release from tag workflow

### Community 19 - "Community 19"
Cohesion: 0.12
Nodes (15): 1. Install with HACS, 2. Add integration, 3. Add water totals to Energy dashboard, Architecture & Internal Flow, Authentication Flow, brunata-to-home-assistant, Connectivity Requirements, Features (+7 more)

### Community 20 - "Community 20"
Cohesion: 0.17
Nodes (11): Critical, Executive summary, High, Informational findings, Low, Medium, Scope and limitations, SEC-001 — Vulnerable `python-dotenv` release (fixed) (+3 more)

### Community 21 - "Community 21"
Cohesion: 0.40
Nodes (4): Configuration, Debug log, Describe the bug, Version of the custom_component

## Knowledge Gaps
- **86 isolated node(s):** `*.yaml`, `ClientSession`, `ClientTimeout`, `HomeAssistant`, `ConfigEntry` (+81 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `datetime` connect `Community 1` to `Community 0`, `Community 5`, `Community 6`?**
  _High betweenness centrality (0.208) - this node is a cross-community bridge._
- **Why does `requests` connect `Community 0` to `Community 4`, `Community 6`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `str` (e.g. with `SensorDeviceClass` and `SensorStateClass`) actually correct?**
  _`str` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 10 inferred relationships involving `BrunataOnlineClient` (e.g. with `BrunataOnlineConfigFlow` and `BrunataOptionsFlow`) actually correct?**
  _`BrunataOnlineClient` has 10 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `Any` (e.g. with `SensorDeviceClass` and `SensorStateClass`) actually correct?**
  _`Any` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 21 inferred relationships involving `SensorDeviceClass` (e.g. with `AddEntitiesCallback` and `_BrunataAggregateWaterBase`) actually correct?**
  _`SensorDeviceClass` has 21 INFERRED edges - model-reasoned connections that need verification._
- **Are the 21 inferred relationships involving `SensorStateClass` (e.g. with `AddEntitiesCallback` and `_BrunataAggregateWaterBase`) actually correct?**
  _`SensorStateClass` has 21 INFERRED edges - model-reasoned connections that need verification._