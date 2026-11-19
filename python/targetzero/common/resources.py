# SPDX-License-Identifier: Apache-2.0
"""Locate files that ship with TargetZero (schemas, templates, example config).

In an installed wheel they live inside the package. In a source checkout they
live at the repository root, so both places are tried.
"""

from __future__ import annotations

from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _PACKAGE_DIR.parent.parent


def _find(packaged: str, in_repo: str) -> Path:
    for candidate in (_PACKAGE_DIR / packaged, _REPO_ROOT / in_repo):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"TargetZero resource not found: {in_repo}")


def schema_dir() -> Path:
    return _find("schemas", "schema")


def templates_dir() -> Path:
    return _find("templates", "templates")


def example_config_dir() -> Path:
    return _find("config", "config")
