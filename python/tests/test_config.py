# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest

from targetzero.common.config import Config, ConfigError, load_config
from targetzero.common.resources import example_config_dir


def test_example_config_is_valid() -> None:
    config = load_config(example_config_dir() / "targetzero.example.yaml")
    assert config.organisation == "Example Ltd"
    assert len(config.break_glass("m365")) == 2


def test_paths_resolve_against_config_folder(config: Config, tmp_path: Path) -> None:
    assert config.output_dir == (tmp_path / "output").resolve()
    assert config.registers_dir == (tmp_path / "registers").resolve()


def test_integer_owner_keys_are_accepted(config: Config) -> None:
    assert config.owner(1) == "Alice"
    assert config.owner(7) == ""


def test_break_glass_is_lowercased(config: Config) -> None:
    assert "bg1@test.onmicrosoft.com" in config.break_glass("m365")
    assert config.break_glass("gws") == []


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "targetzero.yaml"
    path.write_text("organisation: X\ntypo_key: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="typo_key"):
        load_config(path)


def test_exception_max_days_cannot_exceed_90(tmp_path: Path) -> None:
    path = tmp_path / "targetzero.yaml"
    path.write_text("organisation: X\nthresholds:\n  exception_max_days: 180\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yaml")
