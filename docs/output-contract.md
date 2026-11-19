# Output contract

Everything that produces a Target 0 count writes two files into the run folder of the day:

```
output/<YYYY-MM-DD>/<zero>_<source>_<name>.csv            records: one row per thing checked
output/<YYYY-MM-DD>/<zero>_<source>_<name>.summary.json   count: what the scorecard reads
```

- `zero`: 1 to 7, the Target 0 count this check feeds.
- `source`: the platform or system, lowercase, e.g. `m365`, `gws`, `external`, `fortigate`, `manual`.
- `name`: the check, lowercase, e.g. `admins`, `mfa`, `exposure`.

The scorecard reads **only** the summaries. Any tool, in any language, can feed it by writing a summary that passes [`schema/summary.schema.json`](../schema/summary.schema.json).

## Summary

```json
{
  "schema_version": "1.0",
  "zero": 1,
  "source": "m365",
  "name": "admins",
  "tool": "Get-T0M365Admin",
  "tool_version": "0.2.0",
  "run_date": "2026-11-19",
  "generated_at": "2026-11-19T08:12:44+00:00",
  "count": 2,
  "complete": true,
  "notes": ["PIM not licensed: permanent assignments cannot be made eligible"],
  "record_file": "1_m365_admins.csv",
  "items": [
    { "id": "m365:jane@example.com/global-administrator", "reason": "Permanent Global Administrator" },
    { "id": "m365:sp/backup-app", "reason": "App with RoleManagement.ReadWrite.Directory" }
  ]
}
```

Rules beyond the schema (checked by `targetzero validate` and the helpers):

1. `count` equals the number of `items`.
2. Item ids are unique (case-sensitive), have the form `<source>:<identifier>`, and contain no spaces or semicolons.
3. **Ids are stable**: the same admin, port or finding gets the same id on every run. Exceptions refer to these ids; if they change, the exception stops matching and the item is counted again.
4. `complete` is `false` when the check could not see everything: a missing permission, a missing licence, an unreachable device. The scorecard then shows the target as *incomplete* instead of trusting the number.

## How the scorecard counts

| Situation | Today | Status |
| --- | --- | --- |
| No summary for the target | `-` | no data |
| A summary is invalid or `complete` is false | count | incomplete |
| Items found | count | open |
| No items | 0 | zero |

- Items with the same id from different summaries are counted once.
- Items listed in a **valid** exception for the same target are moved from *Today* to *excepted items*. An exception is valid when description, compensating control, signer, signed date and expiry date are filled in, it is not expired, and it runs at most 90 days. Anything else is listed as a gap.
- The first count seen for a target is stored in `output/baseline.json` as its **Day 1** value.
- `output/history.csv` gets one row per target per run date. Re-running a date replaces that date's rows.

## Writing the files

PowerShell:

```powershell
$config = Import-T0Config
$dir = Get-T0RunDirectory -Config $config
$csv = Export-T0Record -RunDirectory $dir -Zero 1 -Source m365 -Name admins -Records $rows -Property id, account, role
Export-T0Summary -RunDirectory $dir -Zero 1 -Source m365 -Name admins -Items $items -Tool 'My-Script' -RecordFile (Split-Path -Leaf $csv)
```

Python:

```python
from datetime import date
from targetzero.common.config import load_config
from targetzero.common.output import run_dir, write_csv, write_summary

config = load_config()
today = date.today()
directory = run_dir(config.output_dir, today)
write_csv(directory / "1_gws_admins.csv", rows, fieldnames)
write_summary(directory, zero=1, source="gws", name="admins", items=items,
              tool="my-script", run_date=today, record_file="1_gws_admins.csv")
```

## Record files

Record CSVs are for people: they hold every row checked, not only the counted ones. The admin, inventory, findings, exceptions and alert test formats are defined in [`schema/`](../schema). Use `Y` / `N` for yes/no columns and `YYYY-MM-DD` for dates.
