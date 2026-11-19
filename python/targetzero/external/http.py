# SPDX-License-Identifier: Apache-2.0
"""Minimal HTTPS JSON client for public reference data, with a one-day file cache."""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Any

from targetzero import __version__

USER_AGENT = f"TargetZero/{__version__} (+https://github.com/wiresecurity/TargetZero)"


def get_json(url: str, *, timeout: float = 30, headers: dict[str, str] | None = None) -> Any:
    if not url.startswith("https://"):
        raise ValueError(f"Only HTTPS URLs are allowed: {url}")
    request = urllib.request.Request(  # noqa: S310 (https only, checked above)
        url, headers={"User-Agent": USER_AGENT, **(headers or {})}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (https only)
        return json.loads(response.read().decode("utf-8"))


def cached_json(url: str, cache_file: Path, max_age_hours: float = 24, **kwargs: Any) -> Any:
    if cache_file.exists() and time.time() - cache_file.stat().st_mtime < max_age_hours * 3600:
        return json.loads(cache_file.read_text(encoding="utf-8"))
    data = get_json(url, **kwargs)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(data), encoding="utf-8")
    return data
