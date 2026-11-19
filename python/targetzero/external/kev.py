# SPDX-License-Identifier: Apache-2.0
"""Known exploited vulnerabilities (Zero 6): match the CISA KEV catalog against the inventory.

KEV entries name a vendor and product but no versions. When the inventory row
has a version, the NVD API gives the affected version ranges and entries that
do not apply are dropped. Without a version, only entries added recently are
reported, with a note to fill in the version.

Results are merged into registers/findings.csv; rows people already updated
are never changed.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from targetzero.common.config import Config
from targetzero.common.ids import make_id
from targetzero.common.output import read_csv
from targetzero.external.http import cached_json
from targetzero.registers import findings, inventory

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
GENERIC_PRODUCTS = {"multiple products", "multiple", "unknown"}


def norm(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text.lower()).split())


def product_matches(kev: Mapping[str, str], inventory_product: str) -> bool:
    product = norm(kev.get("product", ""))
    if not product or product in GENERIC_PRODUCTS:
        return False
    return f" {product} " in f" {norm(inventory_product)} "


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


def version_affected(nvd: Mapping[str, Any], product: str, version: str) -> bool | None:
    """True/False when NVD has ranges for this product, None when it cannot tell."""
    wanted = version_tuple(version)
    if not wanted:
        return None
    product_key = norm(product).replace(" ", "")
    seen_product = False
    for vuln in nvd.get("vulnerabilities", []):
        for config in vuln.get("cve", {}).get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable"):
                        continue
                    parts = match.get("criteria", "").split(":")
                    if len(parts) < 6 or norm(parts[4]).replace(" ", "") != product_key:
                        continue
                    seen_product = True
                    if _in_range(wanted, parts[5], match):
                        return True
    return False if seen_product else None


def _in_range(wanted: tuple[int, ...], exact: str, match: Mapping[str, str]) -> bool:
    bounds = {k: version_tuple(v) for k, v in match.items() if k.startswith("version")}
    if exact not in ("*", "-", ""):
        return version_tuple(exact) == wanted
    if not bounds:
        return True
    checks: tuple[tuple[str, Callable[[tuple[int, ...]], bool]], ...] = (
        ("versionStartIncluding", lambda b: wanted >= b),
        ("versionStartExcluding", lambda b: wanted > b),
        ("versionEndIncluding", lambda b: wanted <= b),
        ("versionEndExcluding", lambda b: wanted < b),
    )
    return all(check(bounds[key]) for key, check in checks if key in bounds)


class Nvd:
    """NVD API 2.0 with a disk cache and the public rate limit (5 requests / 30 s)."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.api_key = os.environ.get("NVD_API_KEY", "")
        self.delay = 0.7 if self.api_key else 6.5
        self._last = 0.0

    def cve(self, cve_id: str) -> Mapping[str, Any] | None:
        cache = self.cache_dir / f"{cve_id}.json"
        if cache.exists() and time.time() - cache.stat().st_mtime < 7 * 86400:
            data: Mapping[str, Any] = json.loads(cache.read_text(encoding="utf-8"))
            return data
        wait = self._last + self.delay - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            fetched: Mapping[str, Any] = cached_json(
                NVD_URL.format(cve_id), cache, max_age_hours=0, headers=headers
            )
            return fetched
        except (urllib.error.URLError, TimeoutError, ValueError):
            return None


def kev_deadline(date_added: str, hours: int) -> str:
    start = datetime.fromisoformat(date_added).replace(tzinfo=UTC)
    return (start + timedelta(hours=hours)).isoformat()


def match(
    catalog: Iterable[Mapping[str, str]],
    rows: Iterable[Mapping[str, str]],
    *,
    run_date: date,
    deadline_hours: int,
    recent_days: int,
    nvd: Nvd | None,
    internetdb: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[list[dict[str, str]], list[str]]:
    catalog = list(catalog)
    by_cve = {v["cveID"]: v for v in catalog}
    recent = (run_date - timedelta(days=recent_days)).isoformat()
    found: dict[str, dict[str, str]] = {}
    notes: list[str] = []

    def add(row: Mapping[str, str], kev: Mapping[str, str], basis: str) -> None:
        asset = row["id"].split(":", 1)[-1]
        finding_id = make_id("kev", asset, kev["cveID"])
        ransomware = kev.get("knownRansomwareCampaignUse") == "Known"
        found.setdefault(
            finding_id,
            {
                "id": finding_id,
                "asset_id": row["id"],
                "vulnerability": kev["cveID"],
                "title": kev.get("vulnerabilityName", ""),
                "severity": "kev",
                "published": kev["dateAdded"],
                "deadline": kev_deadline(kev["dateAdded"], deadline_hours),
                "status": "open",
                "owner": row.get("owner", ""),
                "notes": basis + ("; used in ransomware campaigns" if ransomware else ""),
            },
        )

    for row in rows:
        if row.get("status") == "retired" or not row.get("product"):
            continue
        version = row.get("version", "")
        for kev in catalog:
            if not product_matches(kev, row["product"]):
                continue
            affected = nvd.cve(kev["cveID"]) if nvd and version else None
            verdict = version_affected(affected, kev["product"], version) if affected else None
            if verdict is True:
                add(row, kev, f"version {version} is in the affected range (NVD)")
            elif verdict is None and kev["dateAdded"] >= recent:
                add(row, kev, "product match; version could not be checked - confirm")
        if internetdb:
            for ip in filter(None, row.get("ip", "").split(";")):
                for cve in internetdb.get(ip, {}).get("vulns", []):
                    if cve in by_cve:
                        add(row, by_cve[cve], f"reported for {ip} by Shodan InternetDB - confirm")
    if nvd is None:
        notes.append(
            f"NVD lookups off: only KEV entries from the last {recent_days} days are matched"
        )
    return sorted(found.values(), key=lambda f: f["id"]), notes


def run(
    config: Config, run_date: date, *, use_nvd: bool = True, recent_days: int = 30
) -> list[Path]:
    cache = config.output_dir / "cache"
    notes: list[str] = []
    complete = True
    try:
        catalog = cached_json(KEV_URL, cache / "kev.json", max_age_hours=6, timeout=60)
        entries = catalog.get("vulnerabilities", [])
        notes.append(
            f"CISA KEV catalog {catalog.get('catalogVersion', '?')}, {len(entries)} entries"
        )
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        entries, complete = [], False
        notes.append(f"Could not download the CISA KEV catalog: {exc}")

    idb_file = config.output_dir / run_date.isoformat() / "external_internetdb.json"
    idb = json.loads(idb_file.read_text(encoding="utf-8")) if idb_file.exists() else None
    rows = inventory.load(config)
    # Firewalls and VPNs found by the vendor collectors today, with exact firmware versions.
    for devices_file in sorted((config.output_dir / run_date.isoformat()).glob("devices_*.csv")):
        rows += read_csv(devices_file)
    if not any(r.get("product") for r in rows):
        notes.append("No inventory row has a product filled in: nothing to match")
        complete = False
    new, match_notes = match(
        entries,
        rows,
        run_date=run_date,
        deadline_hours=int(
            config.data.get("thresholds", {}).get("deadline_hours", {}).get("kev", 8)
        ),
        recent_days=recent_days,
        nvd=Nvd(cache / "nvd") if use_nvd else None,
        internetdb=idb,
    )
    merged, added = findings.merge(findings.load(config), new)
    notes += [*match_notes, f"{len(new)} KEV match(es), {added} new in registers/findings.csv"]
    paths = [findings.save(config, merged)]
    paths += findings.count(config, run_date, notes=notes, complete=complete)
    return paths
