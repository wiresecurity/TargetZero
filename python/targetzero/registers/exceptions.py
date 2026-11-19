# SPDX-License-Identifier: Apache-2.0
"""Check registers/exceptions.csv against the Target 0 rules.

An exception is valid only when it says what and why, names a compensating
control, is signed by a manager on a date, and expires at most 90 days after
signing. Anything else is a gap, not an exception.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from targetzero.common.output import read_csv
from targetzero.common.schema import validate

REQUIRED = (
    "description", "compensating_control", "accepted_by", "signed_date", "expiry_date", "items",
)


@dataclass
class ExceptionRecord:
    id: str
    zero: int | None
    items: set[str]
    expiry_date: date | None
    problems: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.problems


def _parse_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def check_row(row: dict[str, str], run_date: date, max_days: int) -> ExceptionRecord:
    problems = validate(row, "exceptions")
    for column in REQUIRED:
        if not row.get(column):
            problems.append(f"{column} is empty")
    signed = _parse_date(row.get("signed_date", ""))
    expiry = _parse_date(row.get("expiry_date", ""))
    if signed and signed > run_date:
        problems.append(f"signed_date {signed} is in the future")
    if expiry and expiry < run_date:
        problems.append(f"expired on {expiry}")
    if signed and expiry:
        if expiry <= signed:
            problems.append("expiry_date is not after signed_date")
        elif (expiry - signed).days > max_days:
            problems.append(f"runs {(expiry - signed).days} days; the maximum is {max_days}")
    zero = row.get("zero", "")
    items = {i.strip() for i in row.get("items", "").split(";") if i.strip()}
    return ExceptionRecord(
        id=row.get("id") or "(no id)",
        zero=int(zero) if zero.isdigit() else None,
        items=items,
        expiry_date=expiry,
        problems=sorted(set(problems), key=problems.index),
    )


def load_exceptions(path: Path, run_date: date, max_days: int = 90) -> list[ExceptionRecord]:
    """Read and check every exception. A missing file means no exceptions."""
    if not path.exists():
        return []
    records = [check_row(row, run_date, max_days) for row in read_csv(path)]
    seen: set[str] = set()
    for record in records:
        if record.id in seen:
            record.problems.append("duplicate id")
        seen.add(record.id)
    return records
