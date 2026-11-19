# SPDX-License-Identifier: Apache-2.0
"""Build the Target 0 scorecard from the count summaries of one run date.

Rules:
- A count with no summary is "no data", never zero.
- Items covered by a valid exception are not in "today"; they are shown as
  excepted items, and the exceptions themselves as open exceptions.
- The first count seen for each target becomes its Day 1 baseline.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from targetzero.common.config import Config
from targetzero.common.output import write_csv
from targetzero.common.schema import validate_summary
from targetzero.registers.exceptions import ExceptionRecord, load_exceptions

TARGETS = {
    1: "Admins with full, permanent access",
    2: "Admins without MFA",
    3: "Admins not monitored",
    4: "Public IPs not behind firewall, WAF or CDN",
    5: "Public IPs without inventory",
    6: "Public IPs or domains with known vulnerabilities past deadline",
    7: "Internet-facing apps without tested recovery page",
}

ROW_FIELDS = (
    "zero",
    "target",
    "day_1",
    "today",
    "excepted_items",
    "open_exceptions",
    "status",
    "owner",
    "sources",
)
HISTORY_FIELDS = ("run_date", "zero", "today", "excepted_items", "open_exceptions", "status")


@dataclass
class Row:
    zero: int
    target: str
    owner: str
    day_1: int | None = None
    today: int | None = None
    excepted_items: int = 0
    open_exceptions: int = 0
    status: str = "no data"
    sources: list[str] = field(default_factory=list)


@dataclass
class Scorecard:
    organisation: str
    run_date: str
    generated_at: str
    rows: list[Row]
    exception_gaps: list[dict[str, Any]]
    summary_problems: list[dict[str, Any]]
    baseline: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)


def _load_summaries(directory: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    summaries, problems = [], []
    for path in sorted(directory.glob("*.summary.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            problems.append({"file": path.name, "problems": [str(exc)]})
            continue
        errors = validate_summary(data)
        if errors:
            problems.append({"file": path.name, "problems": errors, "zero": data.get("zero")})
        else:
            summaries.append(data)
    return summaries, problems


def _load_baseline(path: Path) -> dict[str, dict[str, Any]]:
    if path.exists():
        data: dict[str, dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return data
    return {}


def build(config: Config, run_date: date) -> Scorecard:
    directory = config.output_dir / run_date.isoformat()
    summaries, summary_problems = _load_summaries(directory) if directory.exists() else ([], [])
    exceptions = load_exceptions(
        config.registers_dir / "exceptions.csv",
        run_date,
        config.threshold("exception_max_days", 90),
    )
    valid: dict[int, list[ExceptionRecord]] = {}
    for record in exceptions:
        if record.valid and record.zero:
            valid.setdefault(record.zero, []).append(record)

    baseline = _load_baseline(config.output_dir / "baseline.json")
    rows = []
    for zero, target in TARGETS.items():
        row = Row(zero=zero, target=target, owner=config.owner(zero))
        mine = [s for s in summaries if s["zero"] == zero]
        broken = [p for p in summary_problems if p.get("zero") == zero]
        if mine:
            items = {i["id"] for s in mine for i in s["items"]}
            covered = {i for e in valid.get(zero, []) for i in e.items} & items
            row.today = len(items - covered)
            row.excepted_items = len(covered)
            row.sources = sorted(f"{s['source']}/{s['name']}" for s in mine)
            if broken or not all(s["complete"] for s in mine):
                row.status = "incomplete"
            else:
                row.status = "zero" if row.today == 0 else "open"
            if str(zero) not in baseline:
                baseline[str(zero)] = {"date": run_date.isoformat(), "count": row.today}
        elif broken:
            row.status = "incomplete"
        row.open_exceptions = len(valid.get(zero, []))
        if str(zero) in baseline:
            row.day_1 = int(baseline[str(zero)]["count"])
        rows.append(row)

    return Scorecard(
        organisation=config.organisation,
        run_date=run_date.isoformat(),
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        rows=rows,
        exception_gaps=[
            {"id": e.id, "zero": e.zero, "problems": e.problems} for e in exceptions if not e.valid
        ],
        summary_problems=summary_problems,
        baseline=baseline,
    )


def _csv_row(row: Row) -> dict[str, Any]:
    values = asdict(row)
    values["sources"] = ";".join(row.sources)
    return {k: values[k] for k in ROW_FIELDS}


def write(config: Config, card: Scorecard) -> list[Path]:
    directory = config.output_dir / card.run_date
    directory.mkdir(parents=True, exist_ok=True)
    csv_path = write_csv(directory / "scorecard.csv", [_csv_row(r) for r in card.rows], ROW_FIELDS)
    json_path = directory / "scorecard.json"
    data = asdict(card)
    del data["baseline"]
    json_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    baseline_path = config.output_dir / "baseline.json"
    baseline_path.write_text(
        json.dumps(card.baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # History: one row per target per run date; re-running a date replaces its rows.
    history_path = config.output_dir / "history.csv"
    history: list[dict[str, Any]] = []
    if history_path.exists():
        with history_path.open(newline="", encoding="utf-8") as handle:
            history = [r for r in csv.DictReader(handle) if r["run_date"] != card.run_date]
    history += [
        {"run_date": card.run_date, **{k: v for k, v in _csv_row(r).items() if k in HISTORY_FIELDS}}
        for r in card.rows
    ]
    history.sort(key=lambda r: (r["run_date"], int(r["zero"])))
    write_csv(history_path, history, HISTORY_FIELDS)
    return [csv_path, json_path, history_path, baseline_path]


def render_text(card: Scorecard) -> str:
    def show(value: int | None) -> str:
        return "-" if value is None else str(value)

    lines = [
        f"Target 0 scorecard - {card.organisation} - {card.run_date}",
        "",
        f"{'#':<2} {'Target':<64} {'Day 1':>5} {'Today':>5} {'Exc.':>4}  Status",
    ]
    for r in card.rows:
        lines.append(
            f"{r.zero:<2} {r.target:<64} {show(r.day_1):>5} {show(r.today):>5} "
            f"{r.open_exceptions:>4}  {r.status}"
        )
    if card.exception_gaps:
        lines += ["", "Exceptions that are gaps (not counted as exceptions):"]
        lines += [f"  {g['id']}: {'; '.join(g['problems'])}" for g in card.exception_gaps]
    if card.summary_problems:
        lines += ["", "Summaries that were rejected:"]
        lines += [f"  {p['file']}: {'; '.join(p['problems'])}" for p in card.summary_problems]
    return "\n".join(lines)
