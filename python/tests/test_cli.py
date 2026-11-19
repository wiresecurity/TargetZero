# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest

from targetzero.cli import main


def test_init_then_scorecard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                             capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert (tmp_path / "targetzero.yaml").exists()
    assert (tmp_path / "registers" / "exceptions.csv").exists()
    assert (tmp_path / "registers" / "recovery" / "_template.md").exists()
    # A second init keeps existing files.
    assert main(["init"]) == 0
    assert "kept" in capsys.readouterr().out

    assert main(["scorecard", "--date", "2026-11-19"]) == 0
    assert (tmp_path / "output" / "2026-11-19" / "scorecard.csv").exists()


def test_templates_validate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    main(["init"])
    files = [str(p) for p in (tmp_path / "registers").glob("*.csv")
             if p.stem != "approved_exposure"]
    assert main(["validate", *files]) == 0


def test_validate_reports_bad_rows(tmp_path: Path) -> None:
    path = tmp_path / "inventory.csv"
    path.write_text("id,asset,type,status\ninventory:x,x.example.com,host,reviewed\n")
    assert main(["validate", str(path)]) == 1


def test_missing_config_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TARGETZERO_CONFIG", raising=False)
    assert main(["scorecard"]) == 2
