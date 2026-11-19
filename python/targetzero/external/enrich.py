# SPDX-License-Identifier: Apache-2.0
"""Inventory enrichment (Zero 5): suggest product, version and support status per asset.

Reads the inventory, probes each in-scope web asset once, and writes suggestions to
5_external_enrich.csv. The register itself is not changed: the owner decides.

Sources: HTTP Server / X-Powered-By headers, TLS certificate and version, CPEs from Shodan
InternetDB (when `external scan --internetdb` ran today), and support dates from endoflife.date.
"""

from __future__ import annotations

import json
import re
import urllib.error
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

from targetzero.common.config import Config
from targetzero.common.output import run_dir, write_csv
from targetzero.external import web
from targetzero.external.http import cached_json
from targetzero.external.scope import Scope
from targetzero.registers import inventory

FIELDS = (
    "id",
    "asset",
    "https",
    "tls_version",
    "certificate_valid",
    "certificate_issuer",
    "certificate_expiry",
    "server",
    "powered_by",
    "suggested_product",
    "suggested_version",
    "suggested_vendor_supported",
    "eol_date",
    "evidence",
)
# Header product name -> endoflife.date product id.
EOL_PRODUCTS = {
    "nginx": "nginx",
    "apache": "apache-http-server",
    "php": "php",
    "tomcat": "tomcat",
    "openssl": "openssl",
    "node.js": "nodejs",
}
PRODUCT_PATTERN = re.compile(r"(?P<product>[A-Za-z][A-Za-z.\-]*)/(?P<version>\d+(?:\.\d+)*)")


def products_from_headers(headers: Mapping[str, str]) -> list[tuple[str, str]]:
    found = []
    for key in ("server", "x-powered-by"):
        for match in PRODUCT_PATTERN.finditer(headers.get(key, "")):
            found.append((match["product"].lower(), match["version"]))
    return found


def products_from_cpes(cpes: list[str]) -> list[tuple[str, str]]:
    found = []
    for cpe in cpes:
        parts = cpe.split(":")  # cpe:/a:vendor:product:version
        if len(parts) >= 5 and parts[4]:
            found.append((parts[3].lower(), parts[4]))
    return found


def support_status(product: str, version: str, cache: Path) -> tuple[str, str]:
    """('Y'|'N'|'?', eol date) from endoflife.date."""
    slug = EOL_PRODUCTS.get(product)
    if not slug:
        return "?", ""
    try:
        cycles = cached_json(
            f"https://endoflife.date/api/{slug}.json", cache / f"eol-{slug}.json", max_age_hours=24
        )
    except (urllib.error.URLError, TimeoutError, ValueError):
        return "?", ""
    for cycle in sorted(cycles, key=lambda c: -len(str(c.get("cycle", "")))):
        name = str(cycle.get("cycle", ""))
        if version == name or version.startswith(name + "."):
            eol: Any = cycle.get("eol")
            if isinstance(eol, bool):
                return ("N" if eol else "Y"), ""
            return ("N" if str(eol) <= date.today().isoformat() else "Y"), str(eol)
    return "?", ""


def run(config: Config, run_date: date) -> list[Path]:
    scope = Scope.from_config(config)
    cache = config.output_dir / "cache"
    idb_file = config.output_dir / run_date.isoformat() / "external_internetdb.json"
    idb: dict[str, Any] = json.loads(idb_file.read_text()) if idb_file.exists() else {}
    records = []
    for row in inventory.load(config):
        asset = row["asset"]
        in_scope = (
            scope.contains_ip(asset) if row.get("type") == "ip" else scope.contains_name(asset)
        )
        if row.get("status") == "retired" or not in_scope:
            continue
        record = {f: "" for f in FIELDS} | {"id": row["id"], "asset": asset}
        response = web.get(asset, port=443, use_tls=True)
        if not response.status:
            response = web.get(asset, port=80, use_tls=False)
        else:
            record["https"] = "Y"
        if response.tls and record["https"]:
            record["tls_version"] = response.tls.version
            record["certificate_valid"] = "Y" if response.tls.verified else "N"
            record["certificate_issuer"] = response.tls.issuer
            record["certificate_expiry"] = response.tls.not_after
            if response.tls.error:
                record["evidence"] = f"certificate: {response.tls.error}"
        record["server"] = response.headers.get("server", "")
        record["powered_by"] = response.headers.get("x-powered-by", "")
        cpes = [
            str(c) for ip in row.get("ip", "").split(";") for c in idb.get(ip, {}).get("cpes", [])
        ]
        candidates = products_from_headers(response.headers) + products_from_cpes(cpes)
        if candidates:
            product, version = candidates[0]
            supported, eol = support_status(product, version, cache)
            record |= {
                "suggested_product": product,
                "suggested_version": version,
                "suggested_vendor_supported": supported,
                "eol_date": eol,
            }
        records.append(record)
    directory = run_dir(config.output_dir, run_date)
    return [write_csv(directory / "5_external_enrich.csv", records, FIELDS)]
