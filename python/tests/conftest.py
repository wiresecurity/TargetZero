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
