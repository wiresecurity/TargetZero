# SPDX-License-Identifier: Apache-2.0
"""Turn unified admin records into the Zero 1 and Zero 2 counts.

Records are one row per account and role. Counts are per account:

- Zero 1: the account holds at least one privileged role permanently and is
  not a break-glass account.
- Zero 2: the account is not a service account and either has no MFA method
  that counts (none, does-not-count, unknown) or MFA is not enforced for it.

The PowerShell module implements the same rules (Export-T0AdminSummary); keep
both in step.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import date
from pathlib import Path

from targetzero.common.ids import make_id
from targetzero.common.output import base_name, write_csv, write_summary

FIELDS = (
    "id",
    "source",
    "system",
    "account",
    "role",
    "account_type",
    "privileged",
    "permanent",
    "end_date",
    "mfa_class",
    "mfa_enforced",
    "separate_admin_account",
    "break_glass",
    "last_logon",
    "last_verified",
    "notes",
)
MFA_RANK = {"none": 0, "does-not-count": 1, "unknown": 2, "mfa": 3, "phishing-resistant": 4}
ENFORCED_RANK = {"N": 0, "unknown": 1, "Y": 2}


def record_id(source: str, system: str, account: str, role: str) -> str:
    return make_id(source, system, account, role)


def account_id(source: str, system: str, account: str) -> str:
    return make_id(source, system, account)


def count_items(
    records: Iterable[Mapping[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Return (zero1_items, zero2_items) for a list of admin records."""
    accounts: dict[str, list[Mapping[str, str]]] = {}
    for r in records:
        accounts.setdefault(account_id(r["source"], r["system"], r["account"]), []).append(r)

    zero1, zero2 = [], []
    for item_id, rows in sorted(accounts.items()):
        permanent = sorted(
            {r["role"] for r in rows if r["privileged"] == "Y" and r["permanent"] == "Y"}
        )
        if permanent and not any(r["break_glass"] == "Y" for r in rows):
            zero1.append({"id": item_id, "reason": "Permanent " + ", ".join(permanent)})

        if all(r.get("account_type") == "service" for r in rows):
            continue
        mfa = min((r["mfa_class"] for r in rows), key=lambda c: MFA_RANK.get(c, 0))
        enforced = min((r["mfa_enforced"] for r in rows), key=lambda e: ENFORCED_RANK.get(e, 0))
        if MFA_RANK.get(mfa, 0) < MFA_RANK["mfa"] or enforced != "Y":
            zero2.append({"id": item_id, "reason": f"MFA: {mfa}; enforced: {enforced}"})
    return zero1, zero2


def write_admin_outputs(
    directory: Path,
    *,
    source: str,
    records: Sequence[Mapping[str, str]],
    tool: str,
    run_date: date,
    complete: bool = True,
    notes: Sequence[str] = (),
) -> list[Path]:
    """Write <1>_<source>_admins.csv plus the Zero 1 and Zero 2 summaries."""
    record_file = f"{base_name(1, source, 'admins')}.csv"
    rows = [{f: r.get(f, "") for f in FIELDS} for r in records]
    paths = [write_csv(directory / record_file, rows, FIELDS)]
    zero1, zero2 = count_items(rows)
    for zero, name, items in ((1, "admins", zero1), (2, "mfa", zero2)):
        paths.append(
            write_summary(
                directory,
                zero=zero,
                source=source,
                name=name,
                items=items,
                tool=tool,
                run_date=run_date,
                complete=complete,
                notes=notes,
                record_file=record_file,
            )
        )
    return paths
