# SPDX-License-Identifier: Apache-2.0
"""Google Workspace domains, as a seed for `targetzero external discover` (Zero 5)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from targetzero.common.config import Config
from targetzero.common.output import run_dir, write_csv
from targetzero.gws.client import Gws

FIELDS = ("domain", "verified", "primary", "kind")


def run(config: Config, run_date: date, gws: Gws) -> list[Path]:
    rows = []
    for d in gws.pages(gws.directory.domains().list, "domains", customer=gws.customer):
        rows.append(
            {
                "domain": d["domainName"].lower(),
                "verified": "Y" if d.get("verified") else "N",
                "primary": "Y" if d.get("isPrimary") else "N",
                "kind": "domain",
            }
        )
        for alias in d.get("domainAliases", []):
            rows.append(
                {
                    "domain": alias["domainAliasName"].lower(),
                    "verified": "Y" if alias.get("verified") else "N",
                    "primary": "N",
                    "kind": "alias",
                }
            )
    return [write_csv(run_dir(config.output_dir, run_date) / "5_gws_domains.csv", rows, FIELDS)]
