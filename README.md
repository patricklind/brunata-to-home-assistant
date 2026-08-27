# brunata-to-home-assistant

> [!IMPORTANT]
>
> **Reporting a bug:** Before opening a [GitHub issue](https://github.com/patricklind/brunata-to-home-assistant/issues), update to the latest release and include:
>
> - the Brunata Online integration version and Home Assistant version;
> - a clear description of the expected and actual result;
> - the affected meter type and the relevant dates/values shown by Brunata and Home Assistant;
> - steps to reproduce the problem;
> - relevant debug logs; and
> - the diagnostics file from **Settings → Devices & services → Brunata Online → three-dot menu → Download diagnostics**.
>
> Never post your password, access token, cookies, or unredacted personal information. The integration diagnostics exclude credentials, consumer details, placement, serial numbers, and raw meter IDs, but retain reading values and dates needed for troubleshooting.

> [!WARNING]
> We are aware that there are issues in the codebase.
> This is a hobby project maintained in spare time.
> Fixes and improvements are implemented when time allows.
> Do not deploy in production without proper validation.

`brunata_online` is a Home Assistant custom integration that authenticates against Brunata Online and creates water/heating meter sensors from `online.brunata.com`.

---

> [!IMPORTANT]
> Home Assistant should be treated as the Source of Truth for automations and dashboards.
> This integration is read-only and only syncs data from Brunata to Home Assistant.

---

## Visual Overview

![Brunata logo](assets/brunata-logo.svg)

```mermaid
flowchart LR
    B["Brunata Online<br/>online.brunata.com"] --> I["brunata_online integration"]
    I --> HA["Home Assistant entities"]
    HA --> E["Energy/Water dashboard"]
```

---

## Architecture & Internal Flow

### Runtime Execution Flow

```mermaid
flowchart TD
    A["Config Entry setup"] --> B["Validate credentials"]
    B --> C["Fetch consumer + meter rows"]
    C --> D["Build per-meter sensors"]
    D --> E["Build aggregate water sensors"]
    E --> F["Coordinator refresh each hour"]
```

---

### Authentication Flow

```mermaid
flowchart TD
    A["Username/password from HA config flow"] --> B["Brunata authorize endpoint"]
    B --> C["Keycloak credential form"]
    C --> D["Get auth code redirect"]
    D --> E["Token exchange"]
    E --> F["Bearer token for API requests"]
```

---

### History + Windowed Consumption

```mermaid
flowchart LR
    A["Daily meter snapshots (up to 30 days)"] --> B["History cache"]
    B --> C["Per-meter last 1/7/14/30 days"]
    B --> D["Aggregate water last 1/7/14/30 days"]
    B --> E["Distributed estimate sensor"]
```

---

## Features

- Config-flow setup in Home Assistant UI (no YAML config required)
- Per-meter sensors for water and heating
- Per-meter rolling consumption sensors:
  - Water: last `1`, `7`, `14`, `30` days
  - Heating: last `30` days
- Aggregate water sensors for Energy dashboard:
  - `sensor.brunata_water_total`
  - `sensor.brunata_cold_water_total`
  - `sensor.brunata_hot_water_total`
- Aggregate water rolling sensors:
  - `... last 1 day`, `... last 7 days`, `... last 14 days`, `... last 30 days`
- Includes serial number and meter metadata in sensor attributes

> [!NOTE]
> Sync direction is strictly one-way: Brunata -> Home Assistant.
> No write operations are performed against Brunata meters.

---

## Quick Start

### 1. Install with HACS

1. Open **HACS** in Home Assistant.
2. Go to **Integrations**.
3. Click menu (three dots) -> **Custom repositories**.
4. Add repository URL:
   - `https://github.com/patricklind/brunata-to-home-assistant`
5. Select category: **Integration**.
6. Install **Brunata Online**.
7. Restart Home Assistant.

---

### 2. Add integration

1. Go to **Settings** -> **Devices & Services**.
2. Click **Add Integration**.
3. Search for **Brunata Online**.
4. Enter Brunata username/email and password.

---

### 3. Add water totals to Energy dashboard

In Home Assistant:

`Settings -> Dashboards -> Energy -> Water`

Use one of:

- `sensor.brunata_water_total` (all water meters)
- `sensor.brunata_cold_water_total`
- `sensor.brunata_hot_water_total`

> [!IMPORTANT]
> Use the `..._total` sensors for Energy/Water.
> `last N days` sensors are period deltas for cards/analysis, not cumulative meters.

---

## Connectivity Requirements

Home Assistant must be able to reach:

- `https://online.brunata.com`

> [!CAUTION]
> If logins fail with timeout from Home Assistant but work from browser, verify host networking/MTU.
> MTU `1500` has been required in multiple environments.

---

## Local Debug Script

This repo includes a standalone script to test login and data retrieval:

```bash
python3 fetch_brunata_data.py
```

Environment variables (from `.env`):

- `BRUNATA_USERNAME`
- `BRUNATA_PASSWORD`

Output files:

- `output/brunata_data.json`
- `output/brunata_meters.csv`

---

## Troubleshooting

1. **Cannot connect / timeout**

   - Confirm DNS and outbound HTTPS from Home Assistant host/container.
   - Test:
     - `curl -I https://online.brunata.com`

2. **Credentials rejected in HA, but browser works**

   - Usually network/timeouts from HA host, not wrong credentials.
   - Check Home Assistant logs for `TimeoutError` / `ReadTimeout`.

3. **No history/last N days values**

   - Integration needs sufficient daily points.
   - First refresh may expose empty `last N days` until history cache is filled.

4. **A water transmitter was replaced**

   - Brunata may stop returning a current value for the old transmitter while
     the new transmitter reports only consumption since the exchange.
   - The total sensors retain the old transmitter's latest historical reading
     as the baseline and add the replacement transmitter's reading.

5. **A meter shows an old or unexpectedly low total**

   - Open `Settings -> Devices & services -> Brunata Online`.
   - Choose the three-dot menu and **Download diagnostics**.
   - Attach the JSON file to the GitHub issue together with the expected total.
   - Credentials, consumer details, placement, serial numbers, and raw meter IDs
     are excluded. Reading values and dates remain because they are required to
     diagnose date selection and replaced transmitters.

---

## Optional Water Insights Package

[`examples/brunata_water_insights.yaml`](examples/brunata_water_insights.yaml)
adds useful Home Assistant helpers without changing the integration's read-only
behavior:

- daily and monthly total, cold-water, and hot-water utility meters;
- today's and this month's hot-water share;
- an adjustable daily water limit;
- a persistent notification when that limit is exceeded.

To use it:

1. Enable packages in `configuration.yaml`:

   ```yaml
   homeassistant:
     packages: !include_dir_named packages
   ```

2. Copy the example to
   `/config/packages/brunata_water_insights.yaml`.
3. Restart Home Assistant.
4. Set **Brunata daily water limit** under
   `Settings -> Devices & services -> Helpers`. A value of `0` disables alerts.

The package expects the integration's default aggregate entity IDs. If you have
renamed those entities, update the three `source:` values in the package first.

The first daily/monthly Utility Meter cycle is partial. Use the official
`..._total` sensors as Utility Meter sources; do not use the distributed
estimate or rolling `last N days` sensors for billing/statistics.

---

## Maintainer: Tag + Release

1. Bump version in:
   - `custom_components/brunata_online/manifest.json`
2. Commit and push `main`.
3. Create tag:
   - `git tag vX.Y.Z` (the tag must be `v` followed by the manifest version)
   - `git push origin vX.Y.Z`
4. Workflow `Release from tag` publishes GitHub Release automatically.

The workflow rejects a tag that does not match the version in the integration
manifest, preventing the Releases and Tags pages from advertising different
versions.

> [!CAUTION]
> If tags are pushed from HTTPS token without `workflow` scope, workflow-file changes may be rejected.
