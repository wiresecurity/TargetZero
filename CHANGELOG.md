# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

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
