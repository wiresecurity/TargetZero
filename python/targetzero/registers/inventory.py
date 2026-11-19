# SPDX-License-Identifier: Apache-2.0
"""registers/inventory.csv: merge discovered assets and count incomplete rows (Zero 5)."""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from pathlib import Path

from targetzero.common.config import Config
from targetzero.common.output import read_csv, run_dir, write_csv, write_summary

FIELDS = (
    "id",
    "asset",
    "type",
    "ip",
    "owner",
    "purpose",
    "product",
    "version",
    "vendor_supported",
    "eol_date",
    "behind_waf",
    "internet_facing_app",
    "status",
    "last_reviewed",
    "notes",
)
REQUIRED = ("owner", "purpose", "product", "version")
# Columns that discovery may overwrite. Everything else belongs to people.
MACHINE_COLUMNS = ("ip",)


def path_for(config: Config) -> Path:
    return config.registers_dir / "inventory.csv"


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
    rows: list[dict[str, str]], discovered: Iterable[Mapping[str, str]]
) -> tuple[list[dict[str, str]], int, int]:
    """Add new assets as unreviewed rows and refresh machine columns.

    Returns (rows, added, updated). Hand-filled columns are never changed.
    """
    by_asset = {r["asset"].lower(): r for r in rows}
    added = updated = 0
    for found in discovered:
        key = found["asset"].lower()
        existing = by_asset.get(key)
        if existing is None:
            row = {f: "" for f in FIELDS} | dict(found)
            row["asset"] = key
            row["status"] = "unreviewed"
            rows.append(row)
            by_asset[key] = row
            added += 1
            continue
        for column in MACHINE_COLUMNS:
            value = found.get(column, "")
            if value and existing.get(column) != value:
                existing[column] = value
                updated += 1
    return rows, added, updated


def problems(row: Mapping[str, str], run_date: date, max_age_days: int) -> list[str]:
    found = [f"{c} empty" for c in REQUIRED if not row.get(c)]
    if row.get("vendor_supported") not in ("Y", "N"):
        found.append("vendor_supported not Y or N")
    if row.get("status") == "unreviewed":
        found.append("unreviewed")
    reviewed = row.get("last_reviewed", "")
    try:
        age = (run_date - date.fromisoformat(reviewed)).days if reviewed else None
    except ValueError:
        age = None
        found.append("last_reviewed not a date")
    if not reviewed:
        found.append("never reviewed")
    elif age is not None and age > max_age_days:
        found.append(f"last reviewed {age} days ago")
    return found


def count(
    config: Config, run_date: date, notes: Iterable[str] = (), complete: bool = True
) -> list[Path]:
    """Write 5_inventory_rows.csv and its summary."""
    max_age = config.threshold("inventory_review_days", 90)
    rows = [r for r in load(config) if r.get("status") != "retired"]
    records, items = [], []
    for row in rows:
        issues = problems(row, run_date, max_age)
        if row.get("vendor_supported") == "N":
            issues_note = "vendor no longer supports this product: replace it or take it offline"
        else:
            issues_note = ""
        records.append(
            {
                **{f: row.get(f, "") for f in FIELDS},
                "problems": "; ".join(issues),
                "warning": issues_note,
            }
        )
        if issues:
            items.append({"id": row["id"], "reason": "; ".join(issues)})
    directory = run_dir(config.output_dir, run_date)
    record_file = "5_inventory_rows.csv"
    notes = list(notes)
    if not path_for(config).exists():
        notes.append("registers/inventory.csv not found")
        complete = False
    return [
        write_csv(directory / record_file, records, (*FIELDS, "problems", "warning")),
        write_summary(
            directory,
            zero=5,
            source="inventory",
            name="rows",
            items=items,
            tool="targetzero registers inventory",
            run_date=run_date,
            complete=complete,
            notes=notes,
            record_file=record_file,
        ),
    ]
