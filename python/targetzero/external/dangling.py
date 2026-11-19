# SPDX-License-Identifier: Apache-2.0
"""Dangling DNS (Zero 5): names that point to things you no longer use.

A name counts when its CNAME target does not exist, or when the service it points to says
the site is gone (an unclaimed bucket, app or page that someone else could take over).
A records pointing to released cloud addresses cannot be detected this way.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from targetzero.common.config import Config
from targetzero.common.ids import make_id
from targetzero.common.output import read_csv, run_dir, write_csv, write_summary
from targetzero.external import dnsinfo, web
from targetzero.external.scope import Scope
from targetzero.registers import inventory

FIELDS = ("name", "cname", "target_exists", "service", "evidence", "result")

# (service, CNAME suffixes, text in the response that shows the resource is unclaimed)
FINGERPRINTS = (
    ("Amazon S3", ("s3.amazonaws.com", "amazonaws.com"), "NoSuchBucket"),
    ("GitHub Pages", ("github.io",), "There isn't a GitHub Pages site here"),
    ("Heroku", ("herokuapp.com", "herokudns.com"), "no-such-app"),
    ("Azure App Service", ("azurewebsites.net",), "404 Web Site not found"),
    ("Shopify", ("myshopify.com",), "Sorry, this shop is currently unavailable"),
    ("Zendesk", ("zendesk.com",), "Help Center Closed"),
    ("Fastly", ("fastly.net",), "Fastly error: unknown domain"),
    ("Surge", ("surge.sh",), "project not found"),
)


def candidate_names(config: Config, scope: Scope, run_date: date) -> list[str]:
    names = {
        r["asset"].lower()
        for r in inventory.load(config)
        if r.get("type") in ("domain", "subdomain")
    }
    discovery = config.output_dir / run_date.isoformat() / "5_external_discovery.csv"
    if discovery.exists():
        names |= {r["name"].lower() for r in read_csv(discovery)}
    return sorted(n for n in names if scope.contains_name(n))


def check_name(name: str, res: object) -> dict[str, str] | None:
    target = dnsinfo.cname_target(name, res)  # type: ignore[arg-type]
    if not target:
        return None
    record = {
        "name": name,
        "cname": target,
        "target_exists": "",
        "service": "",
        "evidence": "",
        "result": "",
    }
    found = dnsinfo.lookup(target, res)  # type: ignore[arg-type]
    record["target_exists"] = "N" if found.nxdomain or not found.ips else "Y"
    if record["target_exists"] == "N":
        record["result"] = "dangling"
        record["evidence"] = "CNAME target does not resolve"
        return record
    for service, suffixes, text in FINGERPRINTS:
        if any(target == s or target.endswith("." + s) for s in suffixes):
            record["service"] = service
            for use_tls, port in ((True, 443), (False, 80)):
                response = web.get(name, port=port, use_tls=use_tls, timeout=8)
                if text in response.body:
                    record["result"] = "dangling"
                    record["evidence"] = f"{service} answers '{text}'"
                    return record
    record["result"] = "ok"
    return record


def run(config: Config, run_date: date) -> list[Path]:
    scope = Scope.from_config(config)
    res = dnsinfo.resolver()
    records = [r for n in candidate_names(config, scope, run_date) if (r := check_name(n, res))]
    items = [
        {
            "id": make_id("external", r["name"], "dangling"),
            "reason": f"{r['name']} -> {r['cname']}: {r['evidence']}; delete the record",
        }
        for r in records
        if r["result"] == "dangling"
    ]
    directory = run_dir(config.output_dir, run_date)
    record_file = "5_external_dangling-dns.csv"
    return [
        write_csv(directory / record_file, records, FIELDS),
        write_summary(
            directory,
            zero=5,
            source="external",
            name="dangling-dns",
            items=items,
            tool="targetzero external dangling-dns",
            run_date=run_date,
            notes=["Only CNAME records are checked"],
            record_file=record_file,
        ),
    ]
