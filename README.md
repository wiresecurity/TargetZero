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

> **Status: 0.2 (baseline).** Everything needed for the Day 1 numbers: admin and MFA inventories for Microsoft 365 and Google Workspace, FortiGate and PAN-OS config collectors, the external exposure scan, asset discovery and the known-exploited-vulnerability check. Change scripts follow in 0.3. See [CHANGELOG.md](CHANGELOG.md).

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

## What it checks (0.2)

| Zero | Microsoft 365 (PowerShell) | Google Workspace (Python) | Devices and internet (Python) |
| --- | --- | --- | --- |
| 1, 2 | `Invoke-T0M365AdminInventory` | `targetzero gws admins` | `targetzero vendors fortigate\|panos FILE...`, `targetzero registers manual-admins` |
| 3 | | | `registers/alert_tests.csv` (by hand) |
| 4 | | | `targetzero external scan --authorised`, vendor collectors |
| 5 | `Get-T0M365Domain` | `targetzero gws domains` | `targetzero external discover`, `targetzero registers inventory` |
| 6 | | | `targetzero external kev`, `targetzero registers findings` |
| 7 | | | `registers/recovery/` (by hand) |

Then `targetzero scorecard` combines everything. Setup per platform: [Microsoft 365](docs/setup-m365.md), [Google Workspace](docs/setup-gws.md), [external checks](docs/external.md), [vendor collectors](docs/vendors.md).

Other commands: `targetzero init` (set up a working folder), `targetzero validate FILE...` (check summaries and registers against the schemas).

## The Target 0 document

The campaign itself, with the reasoning, the 15-day plan and the scorecard, is in [TargetZero.pdf](TargetZero.pdf). You may share and adapt it under [CC BY 4.0](LICENSE-DOCS), with credit to Wire Security.

## Legal

Scan and inventory only systems you own or are authorised to assess. You are responsible for the changes you apply with this tooling; review every plan before applying it.

## Licence

Copyright 2026 Wire Security.

- Code, schemas, templates and technical docs: [Apache License, Version 2.0](LICENSE).
- The Target 0 document (`TargetZero.pdf`): [Creative Commons Attribution 4.0 International](LICENSE-DOCS).

Security issues: see [SECURITY.md](SECURITY.md). Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).
