# Brunata Online Custom Integration for Home Assistant

[![hacs][hacsbadge]][hacs]
[![GitHub Release][releases-shield]][releases]
[![License][license-shield]](LICENSE)

This integration allows Home Assistant to read meter values from the [Brunata Online][brunata] Portal.
Brunata is an IoT-enabled utilities provider that's part of the Minol-ZENNER Group, mostly providing utilities to housing cooperatives in the EEA.

This integration is not endorsed by Brunata and could stop functioning at any time.

## Supported meters

- Heating meters (units)
- Cold water meters (m3)
- Hot water meters (m3)
- Energy meters (kWh)

Each meter is exposed as a Home Assistant sensor with the latest reading.

## Installation via HACS

1. Open HACS in Home Assistant
2. Click the 3-dot menu and select **Custom repositories**
3. Paste: `https://github.com/patricklind/brunata-to-home-assistant`
4. Category: **Integration**
5. Click **Add**, then **Download**
6. Restart Home Assistant

## Configuration

1. Go to **Settings** > **Devices & Services** > **Add Integration**
2. Search for **Brunata Online**
3. Enter your Brunata Online credentials (the same you use on [online.brunata.com][brunata])

## Credits

Based on [@YukiElectronics](https://github.com/YukiElectronics)'s [ha-brunata][ha-brunata] integration.

Azure AD B2C login flow based on [@itchannel](https://github.com/itchannel)'s [FordPass Integration][fordpass].

---

[brunata]: https://online.brunata.com
[ha-brunata]: https://github.com/YukiElectronics/ha-brunata
[fordpass]: https://github.com/itchannel/fordpass-ha
[hacs]: https://hacs.xyz
[hacsbadge]: https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge
[license-shield]: https://img.shields.io/github/license/patricklind/brunata-to-home-assistant.svg?style=for-the-badge
[releases-shield]: https://img.shields.io/github/release/patricklind/brunata-to-home-assistant.svg?style=for-the-badge
[releases]: https://github.com/patricklind/brunata-to-home-assistant/releases
