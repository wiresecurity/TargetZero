# SPDX-License-Identifier: Apache-2.0
"""Write records (CSV) and count summaries (JSON) in the TargetZero output contract.

Layout: <output_dir>/<YYYY-MM-DD>/<zero>_<source>_<name>.csv
        <output_dir>/<YYYY-MM-DD>/<zero>_<source>_<name>.summary.json
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from targetzero import __version__
from targetzero.common.schema import validate_summary


def run_dir(output_dir: Path, run_date: date) -> Path:
    path = output_dir / run_date.isoformat()
    path.mkdir(parents=True, exist_ok=True)
    return path


def base_name(zero: int, source: str, name: str) -> str:
    return f"{zero}_{source}_{name}"


def read_csv(path: Path) -> list[dict[str, str]]:
    # utf-8-sig: files saved by Excel start with a byte order mark.
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = csv.DictReader(handle)
        return [{k: (v or "").strip() for k, v in row.items() if k} for row in rows]


def write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fieldnames: Sequence[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="raise")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: "" if v is None else v for k, v in row.items()})
    return path


def write_summary(
    directory: Path,
    *,
    zero: int,
    source: str,
    name: str,
    items: Sequence[Mapping[str, str]],
    tool: str,
    run_date: date,
    complete: bool = True,
    notes: Sequence[str] = (),
    record_file: str | None = None,
    tool_version: str = __version__,
) -> Path:
    """Validate and write a count summary. Raises ValueError when it breaks the contract."""
    summary: dict[str, Any] = {
        "schema_version": "1.0",
        "zero": zero,
        "source": source,
        "name": name,
        "tool": tool,
        "tool_version": tool_version,
        "run_date": run_date.isoformat(),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "count": len(items),
        "complete": complete,
        "notes": list(notes),
        "items": [{"id": i["id"], "reason": i["reason"]} for i in items],
    }
    if record_file:
        summary["record_file"] = record_file
    problems = validate_summary(summary)
    if problems:
        raise ValueError("Summary does not match the schema:\n  " + "\n  ".join(problems))
    path = directory / f"{base_name(zero, source, name)}.summary.json"
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return path
