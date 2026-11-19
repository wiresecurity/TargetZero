# SPDX-License-Identifier: Apache-2.0
"""WAF / CDN check (Zero 4): are your public websites behind a WAF or CDN, and does the origin
server refuse direct traffic?

A web name counts when it does not resolve into a known CDN/WAF (by IP range or CNAME), or
when its origin, listed in registers/origins.csv, answers directly. Names whose inventory row
has behind_waf = n/a (a VPN portal, a mail server) are skipped.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.error
from collections.abc import Iterable, Mapping
from datetime import date
from pathlib import Path
from typing import Any

from targetzero.common.config import Config
from targetzero.common.ids import make_id
from targetzero.common.output import read_csv, run_dir, write_csv, write_summary
from targetzero.external import dnsinfo, web
from targetzero.external.http import cached_json
from targetzero.external.scope import Scope
from targetzero.registers import inventory

FIELDS = ("name", "ips", "cnames", "web", "provider", "origin_ip", "origin_reachable", "result")
CNAME_PROVIDERS = {
    "Akamai": ("edgekey.net", "edgesuite.net", "akamaiedge.net", "akamai.net", "akamaized.net"),
    "Azure Front Door / CDN": ("azurefd.net", "azureedge.net", "t-msedge.net"),
    "Cloudflare": ("cdn.cloudflare.net",),
    "CloudFront": ("cloudfront.net",),
    "Fastly": ("fastly.net", "fastlylb.net"),
    "Imperva": ("incapdns.net", "impervadns.net"),
    "Sucuri": ("sucuri.net",),
}

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def provider_ranges(cache: Path) -> tuple[dict[str, list[Network]], list[str]]:
    """Published IP ranges of the large CDNs, refreshed daily."""
    sources: dict[str, tuple[str, Any]] = {
        "Cloudflare": (
            "https://api.cloudflare.com/client/v4/ips",
            lambda d: d["result"]["ipv4_cidrs"] + d["result"]["ipv6_cidrs"],
        ),
        "CloudFront": (
            "https://ip-ranges.amazonaws.com/ip-ranges.json",
            lambda d: (
                [p["ip_prefix"] for p in d["prefixes"] if p["service"] == "CLOUDFRONT"]
                + [p["ipv6_prefix"] for p in d["ipv6_prefixes"] if p["service"] == "CLOUDFRONT"]
            ),
        ),
        "Fastly": (
            "https://api.fastly.com/public-ip-list",
            lambda d: d["addresses"] + d.get("ipv6_addresses", []),
        ),
    }
    ranges: dict[str, list[Network]] = {}
    notes = []
    for name, (url, extract) in sources.items():
        try:
            data = cached_json(url, cache / f"ranges-{name.lower()}.json", max_age_hours=24)
            ranges[name] = [ipaddress.ip_network(c, strict=False) for c in extract(data)]
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
            notes.append(f"Could not load {name} IP ranges: {exc}")
    return ranges, notes


def provider_for(found: dnsinfo.Lookup, ranges: Mapping[str, list[Network]]) -> str:
    for name, suffixes in CNAME_PROVIDERS.items():
        if any(c == s or c.endswith("." + s) for c in found.cnames for s in suffixes):
            return name
    for ip in found.ips:
        address = ipaddress.ip_address(ip)
        for name, networks in ranges.items():
            if any(address in n for n in networks):
                return name
    return ""


def is_web(name: str, timeout: float = 4) -> bool:
    for port in (443, 80):
        try:
            with socket.create_connection((name, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def web_names(config: Config, scope: Scope) -> list[str]:
    skip = {r["asset"].lower() for r in inventory.load(config) if r.get("behind_waf") == "n/a"}
    names = set(scope.domains) | {
        r["asset"].lower()
        for r in inventory.load(config)
        if r.get("type") in ("domain", "subdomain") and r.get("status") != "retired"
    }
    return sorted(n for n in names if scope.contains_name(n) and n not in skip)


def origin_reachable(name: str, origin_ip: str) -> bool:
    for use_tls, port in ((True, 443), (False, 80)):
        if web.get(name, port=port, use_tls=use_tls, connect_to=origin_ip, timeout=6).status:
            return True
    return False


def check(
    names: Iterable[str],
    ranges: Mapping[str, list[Network]],
    origins: Mapping[str, str],
    scope: Scope,
    *,
    test_origins: bool,
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    res = dnsinfo.resolver()
    records, items, notes = [], [], []
    for name in names:
        found = dnsinfo.lookup(name, res)
        record = {
            "name": name,
            "ips": ";".join(found.ips),
            "cnames": ";".join(found.cnames),
            "web": "",
            "provider": "",
            "origin_ip": origins.get(name, ""),
            "origin_reachable": "",
            "result": "",
        }
        if not found.ips:
            records.append(record | {"result": "does not resolve"})
            continue
        if not is_web(name):
            records.append(record | {"web": "N", "result": "no web service"})
            continue
        record["web"] = "Y"
        record["provider"] = provider_for(found, ranges)
        if not record["provider"]:
            record["result"] = "not behind a known WAF/CDN"
            items.append(
                {
                    "id": make_id("external", name, "no-waf"),
                    "reason": f"{name} serves web traffic directly ({record['ips']})",
                }
            )
        else:
            record["result"] = f"behind {record['provider']}"
        origin = record["origin_ip"]
        if origin and record["provider"]:
            if not test_origins:
                record["origin_reachable"] = "not tested"
            elif not scope.contains_ip(origin):
                record["origin_reachable"] = "not tested"
                notes.append(f"{name}: origin {origin} is outside scope.ip_ranges, not tested")
            elif origin_reachable(name, origin):
                record["origin_reachable"] = "Y"
                items.append(
                    {
                        "id": make_id("external", name, "origin-reachable"),
                        "reason": f"origin {origin} of {name} answers without the CDN",
                    }
                )
            else:
                record["origin_reachable"] = "N"
        records.append(record)
    return records, items, notes


def run(config: Config, run_date: date, *, test_origins: bool = False) -> list[Path]:
    scope = Scope.from_config(config)
    ranges, notes = provider_ranges(config.output_dir / "cache")
    origins_file = config.registers_dir / "origins.csv"
    origins = (
        {r["host"].lower(): r["origin_ip"] for r in read_csv(origins_file)}
        if origins_file.exists()
        else {}
    )
    if origins and not test_origins:
        notes.append("Origins not tested: pass --authorised to test registers/origins.csv")
    records, items, check_notes = check(
        web_names(config, scope), ranges, origins, scope, test_origins=test_origins
    )
    directory = run_dir(config.output_dir, run_date)
    record_file = "4_external_waf.csv"
    return [
        write_csv(directory / record_file, records, FIELDS),
        write_summary(
            directory,
            zero=4,
            source="external",
            name="waf",
            items=items,
            tool="targetzero external waf",
            run_date=run_date,
            complete=len(ranges) == 3 and not (origins and not test_origins),
            notes=notes + check_notes,
            record_file=record_file,
        ),
    ]
