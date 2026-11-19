# SPDX-License-Identifier: Apache-2.0
"""Stable item ids: <source>:<part>/<part>... without spaces or semicolons.

Exceptions refer to these ids, so the same thing must get the same id on every
run. Parts are lowercased and whitespace or semicolons become hyphens.
"""

from __future__ import annotations

import re

_UNSAFE = re.compile(r"[\s;]+")


def make_id(source: str, *parts: str) -> str:
    cleaned = [_UNSAFE.sub("-", p.strip().lower()).strip("-") for p in parts if p.strip()]
    return f"{source}:{'/'.join(cleaned)}"
