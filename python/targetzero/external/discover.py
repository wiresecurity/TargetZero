# SPDX-License-Identifier: Apache-2.0
"""Asset discovery (Zero 5): find your public names and addresses and merge them into
registers/inventory.csv.

Sources: scope.domains, domain lists written today by the M365 and Google
Workspace scripts (5_*_domains.csv), DNS zone files, and certificate
transparency logs (crt.sh). Names that no longer resolve are listed but not added.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import dns.exception
import dns.rdatatype
import dns.resolver
import dns.zone

from targetzero.common.config import Config
from targetzero.common.ids import make_id
from targetzero.common.output import read_csv, run_dir, write_csv
from targetzero.external.http import get_json
from targetzero.external.scope import Scope
from targetzero.registers import inventory

FIELDS = ("name", "resolves", "ips", "cname", "in_scope", "sources")


@dataclass
class Name:
    name: str
    sources: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    cname: str = ""


def crtsh_names(domain: str, timeout: float = 90) -> set[str]:
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    try:
        entries = get_json(url, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code < 500:
            raise
        time.sleep(10)  # crt.sh often answers 502/503 under load; one retry
        entries = get_json(url, timeout=timeout)
    names = set()
    for entry in entries:
        for value in str(entry.get("name_value", "")).splitlines():
            value = value.strip().lower().removeprefix("*.")
            if value and " " not in value and "@" not in value:
                names.add(value)
    return names


def zone_names(path: Path, origin: str | None) -> set[str]:
    zone = dns.zone.from_file(str(path), origin=origin, relativize=False, check_origin=False)
    wanted = {dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.CNAME}
    return {
        str(name).rstrip(".").lower()
        for name, node in zone.nodes.items()
        if any(rdataset.rdtype in wanted for rdataset in node.rdatasets)
        and not str(name).startswith("*")
    }


def platform_domains(directory: Path) -> dict[str, str]:
    """Domains written today by Get-T0M365Domain or `targetzero gws domains`."""
    found = {}
    for path in sorted(directory.glob("5_*_domains.csv")):
        source = path.stem.split("_")[1]
        for row in read_csv(path):
            if row.get("domain"):
                found[row["domain"].lower()] = source
    return found


def resolve(name: Name, resolver: dns.resolver.Resolver) -> None:
    for rdtype in ("A", "AAAA"):
        try:
            answer = resolver.resolve(name.name, rdtype)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
        name.ips |= {r.to_text() for r in answer}
        if answer.canonical_name.to_text().rstrip(".").lower() != name.name:
            name.cname = answer.canonical_name.to_text().rstrip(".").lower()


def discovered_rows(names: Iterable[Name], apexes: set[str], scope: Scope) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    ips: set[str] = set()
    for n in names:
        if not n.ips:
            continue
        rows.append(
            {
                "id": make_id("inventory", n.name),
                "asset": n.name,
                "type": "domain" if n.name in apexes else "subdomain",
                "ip": ";".join(sorted(n.ips)),
            }
        )
        ips |= {ip for ip in n.ips if scope.contains_ip(ip)}
    rows += [
        {"id": make_id("inventory", ip), "asset": ip, "type": "ip", "ip": ip} for ip in sorted(ips)
    ]
    return rows


def run(
    config: Config,
    run_date: date,
    *,
    use_crtsh: bool = True,
    zone_files: Iterable[tuple[Path, str | None]] = (),
) -> list[Path]:
    scope = Scope.from_config(config)
    directory = run_dir(config.output_dir, run_date)
    notes: list[str] = []
    complete = True
    names: dict[str, Name] = {}

    def add(name: str, source: str) -> None:
        name = name.lower().strip(".")
        names.setdefault(name, Name(name)).sources.add(source)

    for domain in scope.domains:
        add(domain, "config")
    for domain, source in platform_domains(directory).items():
        add(domain, source)
        if not scope.contains_name(domain):
            notes.append(f"{domain} ({source}) is not in scope.domains: add it if you own it")
    for path, origin in zone_files:
        for name in zone_names(path, origin):
            add(name, "zone")
    apexes = set(names)
    if use_crtsh:
        for domain in sorted(apexes):
            try:
                for name in crtsh_names(domain):
                    if name == domain or name.endswith("." + domain):
                        add(name, "crt.sh")
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                notes.append(f"crt.sh failed for {domain}: {exc}")
                complete = False

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    for entry in names.values():
        resolve(entry, resolver)

    rows, added, updated = inventory.merge(
        inventory.load(config), discovered_rows(names.values(), apexes, scope)
    )
    paths = [inventory.save(config, rows)]
    notes.append(f"Inventory: {added} new row(s) marked unreviewed, {updated} address update(s)")
    records = [
        {
            "name": n.name,
            "resolves": "Y" if n.ips else "N",
            "ips": ";".join(sorted(n.ips)),
            "cname": n.cname,
            "in_scope": "Y" if scope.contains_name(n.name) else "N",
            "sources": ";".join(sorted(n.sources)),
        }
        for n in sorted(names.values(), key=lambda n: n.name)
    ]
    paths.append(write_csv(directory / "5_external_discovery.csv", records, FIELDS))
    paths += inventory.count(config, run_date, notes=notes, complete=complete)
    return paths
