# SPDX-License-Identifier: Apache-2.0
"""Load and validate targetzero.yaml."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from targetzero.common.schema import validate

ENV_VAR = "TARGETZERO_CONFIG"
DEFAULT_LOCATIONS = (Path("targetzero.yaml"), Path("config") / "targetzero.yaml")


class ConfigError(Exception):
    """The configuration file is missing or invalid."""


@dataclass(frozen=True)
class Config:
    path: Path
    data: dict[str, Any]

    @property
    def organisation(self) -> str:
        return str(self.data["organisation"])

    @property
    def output_dir(self) -> Path:
        return self._resolve(self.data.get("output_dir", "output"))

    @property
    def registers_dir(self) -> Path:
        return self._resolve(self.data.get("registers_dir", "registers"))

    def owner(self, zero: int) -> str:
        return str(self.data.get("owners", {}).get(str(zero), ""))

    def break_glass(self, source: str) -> list[str]:
        return [a.lower() for a in self.data.get("break_glass", {}).get(source, [])]

    def threshold(self, name: str, default: int) -> int:
        return int(self.data.get("thresholds", {}).get(name, default))

    def _resolve(self, value: str) -> Path:
        path = Path(value).expanduser()
        return path if path.is_absolute() else (self.path.parent / path).resolve()


def find_config(explicit: str | os.PathLike[str] | None = None) -> Path:
    if explicit:
        return Path(explicit)
    if os.environ.get(ENV_VAR):
        return Path(os.environ[ENV_VAR])
    for candidate in DEFAULT_LOCATIONS:
        if candidate.exists():
            return candidate
    raise ConfigError(
        f"No configuration found. Run 'targetzero init', pass --config, or set {ENV_VAR}."
    )


def load_config(explicit: str | os.PathLike[str] | None = None) -> Config:
    path = find_config(explicit).resolve()
    if not path.is_file():
        raise ConfigError(f"Configuration file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping at the top level")
    # YAML reads `1:` as an integer key; the schema expects strings.
    if isinstance(data.get("owners"), dict):
        data["owners"] = {str(k): v for k, v in data["owners"].items()}
    problems = validate(data, "config")
    if problems:
        raise ConfigError(f"{path} is invalid:\n  " + "\n  ".join(problems))
    return Config(path=path, data=data)
