# SPDX-License-Identifier: Apache-2.0
"""Exposure scan (Zero 4): open TCP ports on your public IPs, compared with the approved list.

Run it from outside your network (a cloud VM, a home line), never from inside:
from inside you see your own LAN, not what the internet sees.

Only addresses inside scope.ip_ranges are scanned. Hostnames are resolved and
their addresses scanned only when those addresses are inside the ranges too:
a website on a CDN is not yours to scan.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
import subprocess
import urllib.error
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from defusedxml import ElementTree

from targetzero.common.config import Config
from targetzero.common.ids import make_id
from targetzero.common.output import read_csv, run_dir, write_csv, write_summary
from targetzero.external.http import get_json
from targetzero.external.ports import PORTS, describe
from targetzero.external.scope import Scope
from targetzero.registers import inventory

FIELDS = (
    "ip",
    "hostnames",
    "port",
    "protocol",
    "category",
    "service",
    "seen_by",
    "approved",
    "justification",
)
INTERNETDB_FILE = "external_internetdb.json"


@dataclass
class Target:
    ip: str
    hostnames: set[str] = field(default_factory=set)


def collect_targets(
    config: Config, scope: Scope, max_hosts: int, resolve: bool = True
) -> tuple[dict[str, Target], list[str]]:
    """Addresses in scope, plus in-scope addresses of known hostnames."""
    targets = {ip: Target(ip) for ip in scope.addresses(max_hosts)}
    notes: list[str] = []
    if not resolve:
        return targets, notes
    names = set(scope.domains)
    names |= {
        r["asset"] for r in inventory.load(config) if r.get("type") in ("domain", "subdomain")
    }
    for name in sorted(names):
        try:
            addresses = {
                info[4][0] for info in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
            }
        except socket.gaierror:
            continue
        for ip in addresses:
            if scope.contains_ip(str(ip)):
                targets.setdefault(str(ip), Target(str(ip))).hostnames.add(name)
            else:
                notes.append(f"{name} -> {ip}: outside scope.ip_ranges, not scanned")
    return targets, notes


def scan_nmap(ips: Iterable[str], ports: Iterable[int], nmap: str) -> dict[str, set[int]]:
    command = [
        nmap,
        "-Pn",
        "-n",
        "-sT",
        "--open",
        "-T4",
        "-p",
        ",".join(str(p) for p in sorted(ports)),
        "-oX",
        "-",
        *sorted(ips),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=3600)  # noqa: S603
    return parse_nmap_xml(result.stdout)


def parse_nmap_xml(xml: str) -> dict[str, set[int]]:
    found: dict[str, set[int]] = {}
    root = ElementTree.fromstring(xml)
    for host in root.iter("host"):
        address = host.find("address")
        if address is None:
            continue
        ip = address.get("addr", "")
        for port in host.iter("port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open" and port.get("protocol") == "tcp":
                found.setdefault(ip, set()).add(int(port.get("portid", "0")))
    return found


async def _probe(ip: str, port: int, timeout: float, limit: asyncio.Semaphore) -> bool:
    async with limit:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except (TimeoutError, OSError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True


async def _scan_connect(
    ips: list[str], ports: list[int], timeout: float, concurrency: int
) -> dict[str, set[int]]:
    limit = asyncio.Semaphore(concurrency)
    pairs = [(ip, port) for ip in ips for port in ports]
    results = await asyncio.gather(*(_probe(ip, port, timeout, limit) for ip, port in pairs))
    found: dict[str, set[int]] = {}
    for (ip, port), is_open in zip(pairs, results, strict=True):
        if is_open:
            found.setdefault(ip, set()).add(port)
    return found


def scan_connect(
    ips: Iterable[str], ports: Iterable[int], timeout: float = 1.5, concurrency: int = 200
) -> dict[str, set[int]]:
    return asyncio.run(_scan_connect(sorted(ips), sorted(ports), timeout, concurrency))


def internetdb(ips: Iterable[str]) -> tuple[dict[str, dict[str, list[object]]], list[str]]:
    """Shodan InternetDB: free, no key. Data can be up to a week old."""
    data, notes = {}, []
    for ip in sorted(ips):
        try:
            data[ip] = get_json(f"https://internetdb.shodan.io/{ip}", timeout=15)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:  # 404: InternetDB has nothing on this address
                notes.append(f"InternetDB {ip}: HTTP {exc.code}")
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            notes.append(f"InternetDB {ip}: {exc}")
    return data, notes


def load_approved(config: Config) -> dict[tuple[str, int], str]:
    path = config.registers_dir / "approved_exposure.csv"
    if not path.exists():
        return {}
    approved = {}
    for row in read_csv(path):
        if row.get("protocol", "tcp").lower() == "tcp" and row.get("port", "").isdigit():
            approved[(row["host"].lower(), int(row["port"]))] = row.get("justification", "")
    return approved


def run(
    config: Config,
    run_date: date,
    *,
    use_nmap: bool = True,
    use_internetdb: bool = False,
    max_hosts: int = 1024,
    timeout: float = 1.5,
) -> list[Path]:
    scope = Scope.from_config(config)
    targets, notes = collect_targets(config, scope, max_hosts)
    complete = True
    if not targets:
        notes.append("Nothing to scan: scope.ip_ranges is empty and no hostname resolves inside it")
        complete = False

    ports = list(PORTS)
    nmap = shutil.which("nmap") if use_nmap else None
    try:
        if nmap:
            open_ports = scan_nmap(targets, ports, nmap)
            notes.append("Scanned with nmap (TCP connect)")
        else:
            open_ports = scan_connect(targets, ports, timeout=timeout)
            notes.append("Scanned with the built-in TCP connect scanner")
    except (subprocess.SubprocessError, OSError) as exc:
        notes.append(f"Scan failed: {exc}")
        open_ports, complete = {}, False

    directory = run_dir(config.output_dir, run_date)
    seen_by: dict[tuple[str, int], set[str]] = {}
    for ip, found in open_ports.items():
        for port in found:
            seen_by.setdefault((ip, port), set()).add("scan")
    if use_internetdb and targets:
        idb, idb_notes = internetdb(targets)
        notes += idb_notes
        (directory / INTERNETDB_FILE).write_text(json.dumps(idb, indent=2), encoding="utf-8")
        for ip, entry in idb.items():
            for reported in entry.get("ports", []):
                if isinstance(reported, int):
                    seen_by.setdefault((ip, reported), set()).add("internetdb")

    approved = load_approved(config)
    records, items = [], []
    for (ip, port), sources in sorted(seen_by.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        target = targets.get(ip, Target(ip))
        keys = [ip, *sorted(target.hostnames)]
        justification = next((approved[(k, port)] for k in keys if (k, port) in approved), None)
        category, service = describe(port)
        records.append(
            {
                "ip": ip,
                "hostnames": ";".join(sorted(target.hostnames)),
                "port": port,
                "protocol": "tcp",
                "category": category,
                "service": service,
                "seen_by": ";".join(sorted(sources)),
                "approved": "Y" if justification is not None else "N",
                "justification": justification or "",
            }
        )
        # Count only what our own scan confirmed; InternetDB alone may be stale.
        if justification is None and "scan" in sources:
            items.append(
                {
                    "id": make_id("external", ip, f"tcp-{port}"),
                    "reason": f"{service or f'port {port}'} ({category}) open, "
                    "not on the approved list",
                }
            )
    record_file = "4_external_exposure.csv"
    return [
        write_csv(directory / record_file, records, FIELDS),
        write_summary(
            directory,
            zero=4,
            source="external",
            name="exposure",
            items=items,
            tool="targetzero external scan",
            run_date=run_date,
            complete=complete,
            notes=notes,
            record_file=record_file,
        ),
    ]
