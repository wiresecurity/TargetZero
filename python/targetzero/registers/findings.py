# SPDX-License-Identifier: Apache-2.0
"""registers/findings.csv: merge new findings and count those past deadline (Zero 6)."""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Mapping
from datetime import UTC, date, datetime
from pathlib import Path

from targetzero.common.config import Config
from targetzero.common.output import read_csv, run_dir, write_csv, write_summary

FIELDS = (
    "id",
    "asset_id",
    "vulnerability",
    "title",
    "severity",
    "published",
    "deadline",
    "status",
    "action",
    "owner",
    "closed_date",
    "notes",
)
# Statuses that still count. "exception" stays counted here; the scorecard
# subtracts it only when a valid, signed exception covers the id.
COUNTED = ("open", "exception")


def path_for(config: Config) -> Path:
    return config.registers_dir / "findings.csv"


def load(config: Config) -> list[dict[str, str]]:
    path = path_for(config)
    return read_csv(path) if path.exists() else []


def save(config: Config, rows: list[dict[str, str]]) -> Path:
    path = path_for(config)
    if path.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copyfile(path, path.with_name(f"{path.name}.{stamp}.bak"))
    return write_csv(path, [{f: r.get(f, "") for f in FIELDS} for r in rows], FIELDS)


def merge(
    rows: list[dict[str, str]], new: Iterable[Mapping[str, str]]
) -> tuple[list[dict[str, str]], int]:
    """Add findings whose id is not in the register yet. Existing rows are left alone."""
    known = {r["id"] for r in rows}
    added = 0
    for finding in new:
        if finding["id"] not in known:
            rows.append({f: finding.get(f, "") for f in FIELDS})
            known.add(finding["id"])
            added += 1
    return rows, added


def parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def count(
    config: Config,
    run_date: date,
    now: datetime | None = None,
    notes: Iterable[str] = (),
    complete: bool = True,
) -> list[Path]:
    """Write 6_findings_overdue.csv and its summary."""
    now = now or datetime.now(UTC)
    rows = load(config)
    records, items = [], []
    for row in rows:
        deadline = parse_time(row.get("deadline", ""))
        overdue = row.get("status") in COUNTED and (deadline is None or deadline < now)
        records.append({**{f: row.get(f, "") for f in FIELDS}, "overdue": "Y" if overdue else "N"})
        if overdue:
            reason = f"{row.get('vulnerability')} on {row.get('asset_id')}, " + (
                f"deadline {row['deadline']}" if deadline else "no valid deadline"
            )
            items.append({"id": row["id"], "reason": reason})
    directory = run_dir(config.output_dir, run_date)
    record_file = "6_findings_overdue.csv"
    return [
        write_csv(directory / record_file, records, (*FIELDS, "overdue")),
        write_summary(
            directory,
            zero=6,
            source="findings",
            name="overdue",
            items=items,
            tool="targetzero registers findings",
            run_date=run_date,
            complete=complete,
            notes=list(notes),
            record_file=record_file,
        ),
    ]
