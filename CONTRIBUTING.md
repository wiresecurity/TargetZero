# Contributing to TargetZero

Thank you for helping. TargetZero is used by small IT teams on production tenants, so the bar is: **safe, readable, tested**.

## Ground rules

- **Language per platform.** Microsoft (M365, Entra ID, Active Directory, Azure, Hyper-V): PowerShell in `powershell/`. Everything else (Google Workspace, external checks, vendor collectors): Python in `python/`.
- **Output contract.** Every check writes CSV records and a `*.summary.json` that passes `schema/summary.schema.json`. Use the helpers: `Export-T0Record` / `Export-T0Summary` in PowerShell, `write_csv` / `write_summary` in Python. Item ids must be stable between runs, or exceptions stop matching.
- **Read-only first.** Inventory code uses read-only scopes and roles. Code that changes anything must:
  - read a reviewed CSV plan rather than decide on its own;
  - default to a dry run (`-WhatIf` / `--dry-run`); apply only with `-Apply` / `--apply`;
  - write a before/after log and a rollback file;
  - never touch the break-glass accounts from the config.
- **No alerting.** Alert policies, watchers and notifications are out of scope.
- **No real data.** Fixtures must be synthetic or fully scrubbed: no tenant ids, real domains, public IPs (use `example.com` and `203.0.113.0/24`), names or keys.
- Every source file starts with `# SPDX-License-Identifier: Apache-2.0`.

## Development setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check . && mypy && pytest
```

```powershell
Install-Module Pester, PSScriptAnalyzer, powershell-yaml -Scope CurrentUser
Invoke-ScriptAnalyzer -Path powershell -Recurse -Settings powershell/PSScriptAnalyzerSettings.psd1
Invoke-Pester powershell/Tests
```

## Pull requests

- One check or fix per pull request.
- Add tests with recorded API responses; CI never talks to a real tenant or device.
- Update `CHANGELOG.md` under *Unreleased*.
- By contributing you agree that your contribution is licensed under the Apache License 2.0 (section 5 of the licence).
