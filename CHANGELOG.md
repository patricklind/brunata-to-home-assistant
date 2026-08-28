# Changelog

All notable changes are documented here. Stable releases use `vX.Y.Z`; beta
releases use `vX.Y.Z-beta.N` and are published as GitHub prereleases.

## Unreleased

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

## 1.0.36 - 2026-08-28

- Hardened numeric readings and CLI selection against invalid/non-finite data.
- Improved panel reload behavior, focus visibility, and status semantics.
- Updated CI actions and dependency validation.
