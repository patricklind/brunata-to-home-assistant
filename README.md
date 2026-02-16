# Brunata Online (Home Assistant)

<p align="center">
  <img src="assets/brunata-logo.svg" alt="Brunata logo" width="280" />
</p>

Custom integration for Home Assistant that reads meter values from [online.brunata.com](https://online.brunata.com).

## Install with HACS

1. Open **HACS** in Home Assistant.
2. Go to **Integrations**.
3. Click menu (three dots) -> **Custom repositories**.
4. Add repository URL:
   - `https://github.com/patricklind/brunata-to-home-assistant`
5. Category: **Integration**.
6. Install **Brunata Online**.
7. Restart Home Assistant.

## Configure

1. Go to **Settings** -> **Devices & Services** -> **Add Integration**.
2. Search for **Brunata Online**.
3. Enter your Brunata username/email and password.

## Notes

- The integration logs in using Brunata's web auth flow.
- Data is fetched from the resident meter endpoints.
- Each meter sensor includes 30-day history in attributes (`history_30d_points`) and
  calculated 30-day consumption (`consumption_last_30_days`) when available.
- The integration also creates dedicated per-meter sensors for rolling
  `... last 30 days` consumption.
- If Brunata changes web endpoints, this integration may need updates.
