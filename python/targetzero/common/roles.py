# SPDX-License-Identifier: Apache-2.0
"""Load privileged_roles.yaml: which roles count as full admin."""

from __future__ import annotations

from pathlib import Path

import yaml

from targetzero.common.config import Config
from targetzero.common.resources import example_config_dir

FILE_NAME = "privileged_roles.yaml"


def roles_file(config: Config) -> Path:
    """Prefer the copy next to targetzero.yaml, so users can change it."""
    local = config.path.parent / FILE_NAME
    return local if local.exists() else example_config_dir() / FILE_NAME


def privileged_roles(config: Config, key: str) -> set[str]:
    data = yaml.safe_load(roles_file(config).read_text(encoding="utf-8")) or {}
    return {str(r).casefold() for r in data.get(key, [])}
