# Changelog

All notable changes are documented here. Stable releases use `vX.Y.Z`; beta
releases use `vX.Y.Z-beta.N` and are published as GitHub prereleases.

## Unreleased

## 1.0.38 - 2026-08-28

### Added

- Weekly, monthly, and yearly comparison reports with explicit insufficient-history states.
- Monthly water and heating budgets in the administrator panel.
- Chart date filters, 7/14/30-day zoom, and CSV download.
- `brunata_online.refresh`, `brunata_online.generate_report`, and
  `brunata_online.export_csv` Home Assistant actions.
- Aggregate cumulative heating-energy sensor for the Energy dashboard when
  physical kWh meters are available.
- Home Assistant runtime smoke-test job and expanded privacy-safe diagnostics.

### Changed

- GitHub prerelease tags no longer replace the latest stable release.
- Reduced startup latency by fetching bounded meter-date candidates concurrently.
- Initial coordinator failures now use Home Assistant's standard retry lifecycle.

### Fixed

- Prevented long sequential meter discovery from causing config-entry setup to be
  cancelled before Brunata Online responded.
- Pinned the Home Assistant test harness to a compatible `josepy` major version.
- Fixed Home Assistant action schemas and rolling energy sensor state classes.
- Removed accidentally committed Playwright runtime artifacts.

## 1.0.36 - 2026-08-28

- Hardened numeric readings and CLI selection against invalid/non-finite data.
- Improved panel reload behavior, focus visibility, and status semantics.
- Updated CI actions and dependency validation.
