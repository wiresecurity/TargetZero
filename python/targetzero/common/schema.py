# SPDX-License-Identifier: Apache-2.0
"""Validate data against the JSON schemas in schema/."""

from __future__ import annotations

import json
from functools import cache
from typing import Any

from jsonschema import Draft202012Validator

from targetzero.common.resources import schema_dir

SCHEMAS = ("summary", "admins", "inventory", "findings", "exceptions", "alert_tests", "config")


@cache
def _validator(name: str) -> Draft202012Validator:
    if name not in SCHEMAS:
        raise ValueError(f"Unknown schema '{name}'. Known: {', '.join(SCHEMAS)}")
    path = schema_dir() / f"{name}.schema.json"
    return Draft202012Validator(json.loads(path.read_text(encoding="utf-8")))


def validate(instance: Any, name: str) -> list[str]:
    """Return a readable list of problems; empty when the instance is valid."""
    problems = []
    for error in sorted(_validator(name).iter_errors(instance), key=lambda e: list(e.path)):
        location = "/".join(str(part) for part in error.path) or "(root)"
        problems.append(f"{location}: {error.message}")
    return problems


def validate_summary(summary: Any) -> list[str]:
    """Schema check plus the rules a schema cannot express."""
    problems = validate(summary, "summary")
    if problems or not isinstance(summary, dict):
        return problems
    ids = [item["id"] for item in summary["items"]]
    if summary["count"] != len(ids):
        problems.append(f"count is {summary['count']} but there are {len(ids)} items")
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        problems.append(f"duplicate item ids: {', '.join(duplicates)}")
    return problems
