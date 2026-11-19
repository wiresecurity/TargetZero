# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import csv
import json
from datetime import date

from targetzero.common.config import Config
from targetzero.common.output import run_dir, write_csv, write_summary
from targetzero.scorecard import scorecard

DAY1 = date(2026, 11, 19)
DAY8 = date(2026, 11, 26)
EXC_FIELDS = [
    "id",
    "zero",
    "items",
    "description",
    "compensating_control",
    "accepted_by",
    "signed_date",
    "expiry_date",
    "notes",
]


def summary(
    config: Config, run: date, zero: int, source: str, ids: list[str], complete: bool = True
) -> None:
    write_summary(
        run_dir(config.output_dir, run),
        zero=zero,
        source=source,
        name="check",
        tool="test",
        run_date=run,
        complete=complete,
        items=[{"id": i, "reason": "r"} for i in ids],
    )


def by_zero(card: scorecard.Scorecard) -> dict[int, scorecard.Row]:
    return {r.zero: r for r in card.rows}


def test_missing_data_is_not_zero(config: Config) -> None:
    rows = by_zero(scorecard.build(config, DAY1))
    assert all(r.status == "no data" and r.today is None for r in rows.values())


def test_counts_merge_sources_and_dedupe(config: Config) -> None:
    summary(config, DAY1, 1, "m365", ["m365:a", "m365:b"])
    summary(config, DAY1, 1, "gws", ["gws:c"])
    summary(config, DAY1, 2, "manual", ["manual:fw/admin", "manual:fw/admin2"])
    summary(config, DAY1, 2, "manual2", ["manual:fw/admin"])
    rows = by_zero(scorecard.build(config, DAY1))
    assert rows[1].today == 3 and rows[1].status == "open"
    assert rows[1].sources == ["gws/check", "m365/check"]
    assert rows[2].today == 2
    assert rows[1].owner == "Alice"


def test_incomplete_summary_flags_target(config: Config) -> None:
    summary(config, DAY1, 4, "external", [], complete=False)
    assert by_zero(scorecard.build(config, DAY1))[4].status == "incomplete"


def test_valid_exception_moves_items_out_of_today(config: Config) -> None:
    summary(config, DAY1, 4, "external", ["external:1.2.3.4/tcp-3389", "external:1.2.3.4/tcp-22"])
    write_csv(
        config.registers_dir / "exceptions.csv",
        [
            {
                "id": "EXC-1",
                "zero": "4",
                "items": "external:1.2.3.4/tcp-3389",
                "description": "d",
                "compensating_control": "c",
                "accepted_by": "CEO",
                "signed_date": "2026-11-19",
                "expiry_date": "2027-01-31",
                "notes": "",
            },
            {
                "id": "EXC-2",
                "zero": "4",
                "items": "external:1.2.3.4/tcp-22",
                "description": "d",
                "compensating_control": "c",
                "accepted_by": "",
                "signed_date": "2026-11-19",
                "expiry_date": "2027-01-31",
                "notes": "",
            },
        ],
        EXC_FIELDS,
    )
    card = scorecard.build(config, DAY1)
    row = by_zero(card)[4]
    assert (row.today, row.excepted_items, row.open_exceptions) == (1, 1, 1)
    assert [g["id"] for g in card.exception_gaps] == ["EXC-2"]


def test_baseline_and_history(config: Config) -> None:
    summary(config, DAY1, 1, "m365", ["m365:a", "m365:b", "m365:c"])
    scorecard.write(config, scorecard.build(config, DAY1))
    summary(config, DAY8, 1, "m365", [])
    card = scorecard.build(config, DAY8)
    scorecard.write(config, card)
    # Re-running the same date must not duplicate history rows.
    scorecard.write(config, scorecard.build(config, DAY8))

    row = by_zero(card)[1]
    assert (row.day_1, row.today, row.status) == (3, 0, "zero")
    with (config.output_dir / "history.csv").open() as handle:
        history = list(csv.DictReader(handle))
    assert len(history) == 14
    data = json.loads((config.output_dir / "2026-11-26" / "scorecard.json").read_text())
    assert "baseline" not in data


def test_invalid_summary_is_reported(config: Config) -> None:
    directory = run_dir(config.output_dir, DAY1)
    (directory / "1_bad_x.summary.json").write_text('{"zero": 1}')
    card = scorecard.build(config, DAY1)
    assert card.summary_problems[0]["file"] == "1_bad_x.summary.json"
    assert by_zero(card)[1].status == "incomplete"
