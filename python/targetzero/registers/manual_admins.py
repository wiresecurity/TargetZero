# SPDX-License-Identifier: Apache-2.0
"""Count the admins in registers/manual_admins.csv (systems without a collector)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from targetzero.admins import record_id, write_admin_outputs
from targetzero.common.config import Config
from targetzero.common.output import read_csv, run_dir
from targetzero.common.schema import validate

SOURCE = "manual"


def with_defaults(row: dict[str, str]) -> dict[str, str]:
    """Fill in source and id when left empty, as people are told to do."""
    row["source"] = row.get("source") or SOURCE
    row["id"] = row.get("id") or record_id(
        row["source"], row.get("system", ""), row.get("account", ""), row.get("role", "")
    )
    return row


def run(config: Config, run_date: date) -> list[Path]:
    path = config.registers_dir / "manual_admins.csv"
    rows = read_csv(path) if path.exists() else []
    notes = [] if path.exists() else [f"{path.name} not found: no manual admins counted"]
    records = []
    for n, row in enumerate(rows, start=2):
        problems = validate(with_defaults(row), "admins")
        if problems:
            notes.append(f"row {n} skipped: {'; '.join(problems)}")
            continue
        # Manual rows keep their own source name only if it is "manual"; otherwise ids from
        # different files could collide with collector output.
        row["source"] = SOURCE
        records.append(row)
    return write_admin_outputs(
        run_dir(config.output_dir, run_date),
        source=SOURCE,
        records=records,
        tool="targetzero registers manual-admins",
        run_date=run_date,
        complete=not any(n.startswith("row ") for n in notes) and path.exists(),
        notes=notes,
    )
