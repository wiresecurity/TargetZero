# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest

from targetzero.common.config import Config, load_config

CONFIG = """\
organisation: Test Org
owners:
  1: Alice
  2: Bob
break_glass:
  m365: [BG1@test.onmicrosoft.com, bg2@test.onmicrosoft.com]
thresholds:
  exception_max_days: 90
"""


@pytest.fixture
def config(tmp_path: Path) -> Config:
    path = tmp_path / "targetzero.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    return load_config(path)


FIXTURES = Path(__file__).parent / "fixtures"

SCOPED = """\
organisation: Test Org
break_glass:
  fortigate: [bg-fw]
  gws: [bg@example.com]
scope:
  domains: [example.com]
  ip_ranges: [203.0.113.0/29]
"""


@pytest.fixture
def scoped(tmp_path: Path) -> Config:
    path = tmp_path / "targetzero.yaml"
    path.write_text(SCOPED, encoding="utf-8")
    return load_config(path)
