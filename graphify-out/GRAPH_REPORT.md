# Graph Report - . (2026-08-26)

## Corpus Check

- Corpus is ~10,777 words - fits in a single context window. You may not need a graph.

## Summary

- 323 nodes · 702 edges · 19 communities (15 shown, 4 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 69 edges (avg confidence: 0.53)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)

- [[_COMMUNITY_Async Brunata API Client|Async Brunata API Client]]
- [[_COMMUNITY_Meter Entity State|Meter Entity State]]
- [[_COMMUNITY_Water Insights Package|Water Insights Package]]
- [[_COMMUNITY_Aggregate Water Sensors|Aggregate Water Sensors]]
- [[_COMMUNITY_Project Documentation and CI|Project Documentation and CI]]
- [[_COMMUNITY_API Regression Tests|API Regression Tests]]
- [[_COMMUNITY_Standalone Debug Client|Standalone Debug Client]]
- [[_COMMUNITY_Danish Translation|Danish Translation]]
- [[_COMMUNITY_English Translation|English Translation]]
- [[_COMMUNITY_Integration Manifest|Integration Manifest]]
- [[_COMMUNITY_HACS Metadata|HACS Metadata]]
- [[_COMMUNITY_Brand Assets|Brand Assets]]
- [[_COMMUNITY_Dependency Automation|Dependency Automation]]
- [[_COMMUNITY_Release Workflow|Release Workflow]]
- [[_COMMUNITY_Debugger Configuration|Debugger Configuration]]
- [[_COMMUNITY_Editor Configuration|Editor Configuration]]
- [[_COMMUNITY_Development Tasks|Development Tasks]]
- [[_COMMUNITY_Repository Automation|Repository Automation]]

## God Nodes (most connected - your core abstractions)

1. `str` - 44 edges
2. `BrunataOnlineClient` - 31 edges
3. `Any` - 31 edges
4. `SensorDeviceClass` - 24 edges
5. `SensorStateClass` - 24 edges
6. `BrunataAuthError` - 20 edges
7. `str` - 19 edges
8. `BrunataMeterSensor` - 15 edges
9. `Any` - 14 edges
10. `_BrunataAggregateWaterBase` - 12 edges

## Surprising Connections (you probably didn't know these)

- `Brunata Online integration` --collects_feature_requests_for--> `Feature request template` [INFERRED]
  custom_components/brunata_online/manifest.json → .github/ISSUE_TEMPLATE/feature_request.md
- `Brunata Online integration` --collects_bug_reports_for--> `Issue report template` [INFERRED]
  custom_components/brunata_online/manifest.json → .github/ISSUE_TEMPLATE/issue.md
- `Brunata Online integration` --extends--> `Home Assistant` [EXTRACTED]
  custom_components/brunata_online/manifest.json → README.md
- `Brunata Online integration` --creates--> `Per-meter sensors` [EXTRACTED]
  custom_components/brunata_online/manifest.json → README.md
- `Brunata Online integration` --validates--> `HACS validation` [EXTRACTED]
  custom_components/brunata_online/manifest.json → .github/workflows/tests.yaml

## Import Cycles

- 1-file cycle: `custom_components/brunata_online/sensor.py -> custom_components/brunata_online/sensor.py`
- 2-file cycle: `custom_components/brunata_online/const.py -> custom_components/brunata_online/sensor.py -> custom_components/brunata_online/const.py`
- 3-file cycle: `custom_components/brunata_online/__init__.py -> custom_components/brunata_online/api.py -> custom_components/brunata_online/sensor.py -> custom_components/brunata_online/__init__.py`
- 3-file cycle: `custom_components/brunata_online/__init__.py -> custom_components/brunata_online/const.py -> custom_components/brunata_online/sensor.py -> custom_components/brunata_online/__init__.py`

## Communities (19 total, 4 thin omitted)

### Community 0 - "Async Brunata API Client"

Cohesion: 0.10
Nodes (33): BrunataAuthError, BrunataConnectionError, BrunataOnlineClient, \_extract_keycloak_error_text(), \_extract_login_form_action(), \_pkce_s256_challenge(), \_to_date(), \_to_float() (+25 more)

### Community 1 - "Meter Entity State"

Cohesion: 0.13
Nodes (32): \_all_meter_rows(), BrunataDistributedMeterSensor, \_consumption_windows_for_row(), \_current_or_history_value(), \_extract_official_point(), \_heating_format(), \_history_delta(), \_history_key_from_row_key() (+24 more)

### Community 2 - "Water Insights Package"

Cohesion: 0.07
Nodes (37): Brunata Daily Cold Water, Brunata Daily Hot Water, Brunata Daily Water Limit, Brunata Daily Water, Brunata Hot Water Share This Month, Brunata Hot Water Share Today, Brunata Daily Water Limit Exceeded, Brunata Monthly Cold Water (+29 more)

### Community 3 - "Aggregate Water Sensors"

Cohesion: 0.14
Nodes (17): AddEntitiesCallback, async_setup_entry(), \_BrunataAggregateWaterBase, BrunataAggregateWaterLastDaysSensor, BrunataAggregateWaterTotalSensor, BrunataLastDaysConsumptionSensor, BrunataMeterSensor, \_is_heating_medium() (+9 more)

### Community 4 - "Project Documentation and CI"

Cohesion: 0.08
Nodes (29): Aggregate water sensors, Bearer token, Black, Brunata Online integration, Brunata Online, Home Assistant config flow, Danish config-flow translation, debugpy (+21 more)

### Community 5 - "API Regression Tests"

Cohesion: 0.10
Nodes (11): Path, ClientError, ClientResponseError, ClientSession, ClientTimeout, CredentialPostUrlTests, CurrentMeterSelectionTests, HistoryCacheTests (+3 more)

### Community 6 - "Standalone Debug Client"

Cohesion: 0.30
Nodes (18): api_get_json(), authenticate(), BrunataAuthError, build_date_candidates(), count_non_null_values(), \_extract_keycloak_error_text(), \_extract_login_form_action(), main() (+10 more)

### Community 7 - "Danish Translation"

Cohesion: 0.13
Nodes (14): already_configured, config, abort, error, step, password, username, auth (+6 more)

### Community 8 - "English Translation"

Cohesion: 0.13
Nodes (14): already_configured, config, abort, error, step, password, username, auth (+6 more)

### Community 9 - "Integration Manifest"

Cohesion: 0.18
Nodes (10): codeowners, config_flow, documentation, domain, iot_class, issue_tracker, loggers, name (+2 more)

### Community 10 - "HACS Metadata"

Cohesion: 0.33
Nodes (5): content_in_root, country, homeassistant, name, render_readme

### Community 11 - "Brand Assets"

Cohesion: 0.50
Nodes (4): Brunata Online Brand Logo, Brunata Wordmark, Online Wordmark, Red and Blue Divider

### Community 12 - "Dependency Automation"

Cohesion: 0.67
Nodes (3): Dependabot, GitHub Actions dependencies, pip dependencies

### Community 13 - "Release Workflow"

Cohesion: 0.67
Nodes (3): GitHub Release, Integration manifest version, Release from tag workflow

## Knowledge Gaps

- **71 isolated node(s):** `name`, `content_in_root`, `country`, `homeassistant`, `render_readme` (+66 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions

_Questions this graph is uniquely positioned to answer:_

- **Why does `datetime` connect `Meter Entity State` to `Async Brunata API Client`, `Aggregate Water Sensors`, `API Regression Tests`, `Standalone Debug Client`?**
  _High betweenness centrality (0.180) - this node is a cross-community bridge._
- **Why does `requests` connect `Project Documentation and CI` to `Async Brunata API Client`, `Standalone Debug Client`?**
  _High betweenness centrality (0.110) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `str` (e.g. with `SensorDeviceClass` and `SensorStateClass`) actually correct?**
  _`str` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 10 inferred relationships involving `BrunataOnlineClient` (e.g. with `BrunataOnlineConfigFlow` and `BrunataOptionsFlow`) actually correct?**
  _`BrunataOnlineClient` has 10 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `Any` (e.g. with `SensorDeviceClass` and `SensorStateClass`) actually correct?**
  _`Any` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 20 inferred relationships involving `SensorDeviceClass` (e.g. with `Any` and `str`) actually correct?**
  _`SensorDeviceClass` has 20 INFERRED edges - model-reasoned connections that need verification._
- **Are the 20 inferred relationships involving `SensorStateClass` (e.g. with `Any` and `str`) actually correct?**
  _`SensorStateClass` has 20 INFERRED edges - model-reasoned connections that need verification._
