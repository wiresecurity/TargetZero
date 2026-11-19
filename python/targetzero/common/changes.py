# SPDX-License-Identifier: Apache-2.0
"""Change log and rollback plan for change commands (same format as Save-T0ChangeLog).

changes_<name>_<timestamp>.json   every planned action with its status
rollback_<name>_<timestamp>.csv   a plan that the same command can apply to undo the run
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from targetzero.common.output import write_csv


def save_change_log(
    directory: Path,
    name: str,
    changes: Sequence[Mapping[str, Any]],
    rollback: Sequence[Mapping[str, str]],
    fields: Sequence[str],
    *,
    dry_run: bool,
) -> list[Path]:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log = directory / f"{'dryrun' if dry_run else 'changes'}_{name}_{stamp}.json"
    log.write_text(
        json.dumps(
            {
                "tool": name,
                "dry_run": dry_run,
                "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
                "changes": list(changes),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    paths = [log]
    if rollback and not dry_run:
        paths.append(write_csv(directory / f"rollback_{name}_{stamp}.csv", rollback, fields))
    return paths
