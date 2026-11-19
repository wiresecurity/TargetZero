# TargetZero

Tooling for **Target 0**: seven security counts, each brought to zero within 15 days. Anything that cannot reach zero becomes a signed, dated exception.

| # | Target |
| --- | --- |
| 1 | Admin accounts with full, permanent access |
| 2 | Admin accounts without MFA |
| 3 | Admin accounts not monitored |
| 4 | Public IPs not behind a firewall, WAF or CDN |
| 5 | Public IPs without a technology inventory |
| 6 | Public IPs or domains with known vulnerabilities past deadline |
| 7 | Internet-facing applications without a tested recovery plan |

TargetZero counts each one from live data, helps you fix what it finds on Microsoft 365 and Google Workspace, and fills in the scorecard. It is built for small IT teams: no SIEM, no extra licences, CSV and JSON output.

> **Status: 0.1 (foundation).** This release has the configuration, output formats, registers and scorecard. Inventory and change scripts for M365, Google Workspace, external exposure and vendor devices follow in 0.2 to 0.4. See [CHANGELOG.md](CHANGELOG.md).

## How it works

```
 M365 / Entra ID  ─ PowerShell ─┐
 Google Workspace ─ Python ─────┤   output/<date>/<zero>_<source>_<name>.csv           records
 External checks  ─ Python ─────┼─▶ output/<date>/<zero>_<source>_<name>.summary.json  counts
 Vendor devices   ─ Python ─────┤                         │
 Registers (CSV, by hand) ──────┘                         ▼
                                       targetzero scorecard ─▶ scorecard.csv / .json, history.csv
```

- **Microsoft stack in PowerShell, everything else in Python.**
- **Read-only by default.** Change scripts follow *plan → review → apply* and run as a dry run unless you pass `-Apply` / `--apply`.
- **One output contract.** Any tool can feed the scorecard by writing a valid summary; see [docs/output-contract.md](docs/output-contract.md).
- **No data leaves your machine** except calls to the platform APIs, your own systems and public reference data.

## Quick start

Requirements: Python 3.11+ and, for the Microsoft scripts, PowerShell 7.4+.

```bash
pip install -e .                  # from a clone; "pip install targetzero" once published
mkdir my-target0 && cd my-target0
targetzero init                   # creates targetzero.yaml and registers/
# edit targetzero.yaml: organisation, owners, break-glass accounts, scope
targetzero scorecard              # builds the scorecard from today's results
```

See [docs/quickstart.md](docs/quickstart.md) for the full walk-through.

## Commands (0.1)

| Command | What it does |
| --- | --- |
| `targetzero init [dir]` | Creates `targetzero.yaml`, `privileged_roles.yaml` and empty registers. Never overwrites existing files. |
| `targetzero scorecard [--date YYYY-MM-DD]` | Combines the summaries of a run date, applies valid exceptions, keeps the Day 1 baseline and history. |
| `targetzero validate FILE...` | Checks summaries and register CSVs against the schemas. |

PowerShell: `Import-Module ./powershell/TargetZero` gives `Import-T0Config`, `Get-T0RunDirectory`, `Export-T0Record` and `Export-T0Summary`.

## The Target 0 document

The campaign itself, with the reasoning, the 15-day plan and the scorecard, is in [TargetZero.pdf](TargetZero.pdf). You may share and adapt it under [CC BY 4.0](LICENSE-DOCS), with credit to Wire Security.

## Legal

Scan and inventory only systems you own or are authorised to assess. You are responsible for the changes you apply with this tooling; review every plan before applying it.

## Licence

Copyright 2026 Wire Security.

- Code, schemas, templates and technical docs: [Apache License, Version 2.0](LICENSE).
- The Target 0 document (`TargetZero.pdf`): [Creative Commons Attribution 4.0 International](LICENSE-DOCS).

Security issues: see [SECURITY.md](SECURITY.md). Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).
