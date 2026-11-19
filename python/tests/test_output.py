# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from targetzero.common.output import read_csv, write_csv, write_summary
from targetzero.common.schema import validate_summary

RUN = date(2026, 11, 19)


def test_summary_round_trip(tmp_path: Path) -> None:
    path = write_summary(
        tmp_path,
        zero=1,
        source="m365",
        name="admins",
        tool="test",
        run_date=RUN,
        items=[{"id": "m365:a@x.com/global-administrator", "reason": "permanent"}],
    )
    assert path.name == "1_m365_admins.summary.json"
    data = json.loads(path.read_text())
    assert data["count"] == 1
    assert validate_summary(data) == []


def test_summary_rejects_duplicate_ids(tmp_path: Path) -> None:
    item = {"id": "m365:a@x.com", "reason": "r"}
    with pytest.raises(ValueError, match="duplicate"):
        write_summary(
            tmp_path,
            zero=1,
            source="m365",
            name="admins",
            tool="t",
            run_date=RUN,
            items=[item, item],
        )


def test_summary_rejects_ids_with_spaces(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        write_summary(
            tmp_path,
            zero=1,
            source="m365",
            name="admins",
            tool="t",
            run_date=RUN,
            items=[{"id": "m365:Global Administrator", "reason": "r"}],
        )


def test_count_must_match_items() -> None:
    summary = {
        "schema_version": "1.0",
        "zero": 2,
        "source": "gws",
        "name": "mfa",
        "tool": "t",
        "tool_version": "1",
        "run_date": "2026-11-19",
        "generated_at": "2026-11-19T10:00:00+00:00",
        "count": 3,
        "complete": True,
        "items": [],
    }
    assert any("count is 3" in p for p in validate_summary(summary))


def test_csv_round_trip_handles_excel_bom(tmp_path: Path) -> None:
    path = tmp_path / "x.csv"
    write_csv(path, [{"a": "1", "b": None}], ["a", "b"])
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    assert read_csv(path) == [{"a": "1", "b": ""}]
