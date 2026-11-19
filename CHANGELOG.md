# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-19

### Added
- Microsoft 365: `Connect-T0M365`, `Invoke-T0M365AdminInventory` (roles, PIM, group-held roles, hidden admin apps, MFA methods and enforcement through Security Defaults, Conditional Access and per-user MFA) and `Get-T0M365Domain`.
- Google Workspace: `targetzero gws admins` (roles, 2-Step Verification, second factors actually used, separate admin accounts) and `targetzero gws domains`.
- Vendor collectors from config exports: `targetzero vendors fortigate` and `targetzero vendors panos` (admins, MFA, trusted hosts, management on internet-facing interfaces, firmware version).
- External checks: `targetzero external scan` (nmap or built-in, approved list, optional Shodan InternetDB), `external discover` (crt.sh, zone files, M365/GWS domains, merged into the inventory) and `external kev` (CISA KEV with NVD version ranges).
- Register counts: `targetzero registers manual-admins | inventory | findings`.
- `Export-T0AdminSummary` and shared test cases (`tests/shared/`) that keep the Python and PowerShell counting rules identical.
- `account_type` column in the admin record (service accounts count for Zero 1, not Zero 2).
- Docs: setup for Microsoft 365, Google Workspace, external checks and vendor collectors.

### Fixed
- PowerShell schema validation missed failures that `Test-Json` reports only through its return value (for example a pattern mismatch in an item id).

## [0.1.0] - 2026-11-19

### Added
- Output contract: CSV records plus a JSON count summary per check (`schema/summary.schema.json`).
- Record schemas for admins, inventory, findings, exceptions and alert tests.
- Configuration file `targetzero.yaml` with schema and example.
- Python package `targetzero` with `init`, `scorecard` and `validate` commands.
- Exception checks: unsigned, undated, longer than 90 days or expired exceptions are reported as gaps.
- Scorecard with Day 1 baseline, open exceptions and weekly history (`scorecard.csv`, `scorecard.json`, `history.csv`).
- PowerShell module `TargetZero` with the same config loader and output writer for the Microsoft scripts.
- Register templates and the recovery page template.
- CI: ruff, mypy, pytest, PSScriptAnalyzer, Pester and a secret scan; actions and images pinned to commit hashes and digests, kept current by Dependabot.
- The Target 0 campaign document (`TargetZero.pdf`), licensed CC BY 4.0.
