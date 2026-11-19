# Quick start

This walk-through sets up TargetZero for one organisation. It takes about 15 minutes.

## 1. Install

Python 3.11 or later:

```bash
pip install targetzero
```

Until the package is published on PyPI, install from a clone: `pip install -e .` in the repository folder.

For the Microsoft 365 scripts (from release 0.2), PowerShell 7.4 or later:

```powershell
Install-Module powershell-yaml -Scope CurrentUser
Import-Module ./powershell/TargetZero
```

## 2. Create a working folder

Keep your data **outside** the repository. It contains admin names and network details.

```bash
mkdir ~/target0-acme && cd ~/target0-acme
targetzero init
```

This creates:

| File | Purpose |
| --- | --- |
| `targetzero.yaml` | Your configuration |
| `privileged_roles.yaml` | Which roles count as full admin |
| `registers/approved_exposure.csv` | Ports you allow on the internet (Zero 4) |
| `registers/manual_admins.csv` | Admins on systems without a collector: firewall, VPN, hypervisor, backup, SaaS (Zero 1, 2) |
| `registers/inventory.csv` | One row per public IP, domain and subdomain (Zero 5) |
| `registers/findings.csv` | Known vulnerabilities on public assets (Zero 6) |
| `registers/alert_tests.csv` | Monthly odd-hour admin logon tests (Zero 3) |
| `registers/exceptions.csv` | Signed exceptions |
| `registers/recovery/_template.md` | Recovery page template (Zero 7) |

## 3. Fill in the configuration

Open `targetzero.yaml` and set at least:

- `organisation`
- `owners`: one owner per count
- `break_glass`: your two emergency accounts per platform. Scripts never change them.
- `scope`: the domains and IP ranges you own. External checks never go outside this list.

Check it:

```bash
targetzero scorecard
```

All seven targets show **no data** until the first checks have run. That is on purpose: missing data is never shown as zero.

## 4. Run the checks

From release 0.2 the inventory scripts write their results to `output/<today>/`. Until then you can fill the registers by hand and check them:

```bash
targetzero validate registers/*.csv
```

## 5. Record exceptions

For anything that cannot reach zero, add a row to `registers/exceptions.csv`:

| Column | Example |
| --- | --- |
| id | EXC-001 |
| zero | 4 |
| items | `external:203.0.113.5/tcp-3389` (ids from the summary, separated by `;`) |
| description | Legacy accounting app needs RDP until migration in January |
| compensating_control | Source IP allow-list to the accountant's office, MFA gateway |
| accepted_by | J. Smith, CEO |
| signed_date | 2026-11-19 |
| expiry_date | 2027-02-15 (at most 90 days later) |

Without a signer or expiry date, it is not an exception but a gap, and the scorecard lists it as one.

## 6. Report

```bash
targetzero scorecard
```

The scorecard is written to `output/<today>/scorecard.csv` and `scorecard.json`. The trend is in `output/history.csv`. Report it weekly until all seven read zero, then monthly.
