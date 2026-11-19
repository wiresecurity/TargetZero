# SPDX-License-Identifier: Apache-2.0
"""Shared output for vendor collectors.

Each collector returns, per config file, a Device: its admin records (unified
admin format), its management exposure findings (Zero 4) and a device record
(product and version, used by `targetzero external kev`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from targetzero.admins import write_admin_outputs
from targetzero.common.config import Config
from targetzero.common.output import run_dir, write_csv, write_summary

DEVICE_FIELDS = ("id", "vendor", "system", "product", "model", "version", "file")
EXPOSURE_FIELDS = ("id", "system", "interface", "zone_or_role", "services", "reason")


@dataclass
class Device:
    vendor: str
    system: str
    product: str
    model: str = ""
    version: str = ""
    file: str = ""
    admins: list[dict[str, str]] = field(default_factory=list)
    exposure: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # False for collectors that cannot see interface exposure (it is then left to the scan).
    checks_exposure: bool = True


def write_outputs(
    config: Config,
    run_date: date,
    source: str,
    devices: Sequence[Device],
    tool: str,
    notes: Sequence[str] = (),
) -> list[Path]:
    """All devices of one vendor go into one set of files: pass every config file in one run."""
    directory = run_dir(config.output_dir, run_date)
    all_notes = [*notes, *(f"{d.system}: {n}" for d in devices for n in d.notes)]
    records = [a for d in devices for a in d.admins]
    paths = write_admin_outputs(
        directory, source=source, records=records, tool=tool, run_date=run_date, notes=all_notes
    )
    exposure = [e for d in devices for e in d.exposure]
    record_file = f"4_{source}_mgmt-exposure.csv"
    if any(d.checks_exposure for d in devices):
        paths.append(write_csv(directory / record_file, exposure, EXPOSURE_FIELDS))
        paths.append(
            write_summary(
                directory,
                zero=4,
                source=source,
                name="mgmt-exposure",
                tool=tool,
                run_date=run_date,
                items=[{"id": e["id"], "reason": e["reason"]} for e in exposure],
                notes=all_notes,
                record_file=record_file,
            )
        )
    devices_rows = [
        {
            "id": f"device:{source}/{d.system.lower()}",
            "vendor": d.vendor,
            "system": d.system,
            "product": d.product,
            "model": d.model,
            "version": d.version,
            "file": d.file,
        }
        for d in devices
    ]
    paths.append(write_csv(directory / f"devices_{source}.csv", devices_rows, DEVICE_FIELDS))
    return paths
