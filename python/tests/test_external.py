# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from conftest import FIXTURES

from targetzero.common.config import Config
from targetzero.common.output import read_csv, write_csv
from targetzero.external import discover, kev, scan
from targetzero.external.scope import Scope

RUN = date(2026, 11, 19)


def summary(config: Config, name: str) -> dict[str, Any]:
    return json.loads((config.output_dir / RUN.isoformat() / name).read_text())  # type: ignore[no-any-return]


# --- scope -----------------------------------------------------------------


def test_scope(scoped: Config) -> None:
    scope = Scope.from_config(scoped)
    assert scope.contains_ip("203.0.113.5") and not scope.contains_ip("198.51.100.1")
    assert scope.contains_name("vpn.EXAMPLE.com.") and not scope.contains_name("example.com.evil")
    assert len(scope.addresses(1024)) == 6
    with pytest.raises(ValueError, match="max-hosts"):
        scope.addresses(4)


# --- scan ------------------------------------------------------------------


def test_parse_nmap_xml() -> None:
    assert scan.parse_nmap_xml((FIXTURES / "nmap.xml").read_text()) == {"203.0.113.2": {443, 3389}}


def test_scan_counts_unapproved_confirmed_ports(
    scoped: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        scan,
        "collect_targets",
        lambda c, s, m: ({"203.0.113.2": scan.Target("203.0.113.2", {"vpn.example.com"})}, []),
    )
    monkeypatch.setattr(
        scan, "scan_connect", lambda ips, ports, timeout: {"203.0.113.2": {443, 3389}}
    )
    monkeypatch.setattr(
        scan,
        "internetdb",
        lambda ips: ({"203.0.113.2": {"ports": [443, 8443], "vulns": ["CVE-2099-0001"]}}, []),
    )
    write_csv(
        scoped.registers_dir / "approved_exposure.csv",
        [{"host": "vpn.example.com", "port": "443", "protocol": "tcp", "justification": "VPN"}],
        ["host", "port", "protocol", "justification"],
    )
    scan.run(scoped, RUN, use_nmap=False, use_internetdb=True)
    data = summary(scoped, "4_external_exposure.summary.json")
    assert [i["id"] for i in data["items"]] == ["external:203.0.113.2/tcp-3389"]
    rows = {
        r["port"]: r
        for r in read_csv(scoped.output_dir / RUN.isoformat() / "4_external_exposure.csv")
    }
    assert rows["443"]["approved"] == "Y"
    assert rows["8443"]["seen_by"] == "internetdb"


def test_scan_connect_finds_local_listener() -> None:
    import socket

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    try:
        assert scan.scan_connect(["127.0.0.1"], [port], timeout=1) == {"127.0.0.1": {port}}
    finally:
        server.close()


# --- discover --------------------------------------------------------------


def test_zone_names() -> None:
    names = discover.zone_names(FIXTURES / "example.com.zone", None)
    assert names == {"example.com", "www.example.com", "vpn.example.com", "old.example.com"}


def test_discover_merges_inventory(scoped: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_resolve(name: discover.Name, resolver: object) -> None:
        name.ips = {
            "example.com": {"203.0.113.5"},
            "vpn.example.com": {"203.0.113.2"},
            "shop.example.com": {"192.0.2.50"},
        }.get(name.name, set())

    monkeypatch.setattr(discover, "resolve", fake_resolve)
    monkeypatch.setattr(
        discover,
        "crtsh_names",
        lambda d: {"vpn.example.com", "shop.example.com", "gone.example.com", "example.org"},
    )
    discover.run(scoped, RUN)
    assets = {r["asset"]: r for r in read_csv(scoped.registers_dir / "inventory.csv")}
    assert set(assets) == {
        "example.com",
        "vpn.example.com",
        "shop.example.com",
        "203.0.113.5",
        "203.0.113.2",
    }
    assert assets["example.com"]["type"] == "domain"
    assert all(r["status"] == "unreviewed" for r in assets.values())
    assert summary(scoped, "5_inventory_rows.summary.json")["count"] == 5
    found = {
        r["name"]: r
        for r in read_csv(scoped.output_dir / RUN.isoformat() / "5_external_discovery.csv")
    }
    assert found["gone.example.com"]["resolves"] == "N"


# --- kev -------------------------------------------------------------------

CATALOG = [
    {
        "cveID": "CVE-2099-0001",
        "vendorProject": "Fortinet",
        "product": "FortiOS",
        "vulnerabilityName": "FortiOS SSL-VPN overflow",
        "dateAdded": "2026-01-10",
        "knownRansomwareCampaignUse": "Known",
    },
    {
        "cveID": "CVE-2099-0002",
        "vendorProject": "Fortinet",
        "product": "FortiOS",
        "vulnerabilityName": "Recent FortiOS bug",
        "dateAdded": "2026-11-10",
    },
    {
        "cveID": "CVE-2099-0003",
        "vendorProject": "Many",
        "product": "Multiple Products",
        "vulnerabilityName": "Generic",
        "dateAdded": "2026-11-15",
    },
]


class FakeNvd:
    def __init__(self) -> None:
        self.data = json.loads((FIXTURES / "nvd-cve.json").read_text())

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        return self.data if cve_id == "CVE-2099-0001" else None


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("7.2.5", True),
        ("7.2.7", False),
        ("7.4.2", True),
        ("7.0.1", False),
        ("", None),
    ],
)
def test_version_affected(version: str, expected: bool | None) -> None:
    nvd = json.loads((FIXTURES / "nvd-cve.json").read_text())
    assert kev.version_affected(nvd, "FortiOS", version) is expected


def test_product_match_is_word_based() -> None:
    assert kev.product_matches({"product": "FortiOS"}, "Fortinet FortiOS 7.2")
    assert not kev.product_matches({"product": "OS"}, "FortiOS")
    assert not kev.product_matches({"product": "Multiple Products"}, "Multiple Products")


def test_match_with_and_without_version() -> None:
    rows = [
        {
            "id": "inventory:vpn.example.com",
            "product": "FortiOS",
            "version": "7.2.5",
            "owner": "Jane",
        },
        {"id": "inventory:old.example.com", "product": "FortiOS", "version": "7.0.1"},
        {"id": "inventory:unknown.example.com", "product": "FortiOS", "version": ""},
    ]
    found, _ = kev.match(
        CATALOG, rows, run_date=RUN, deadline_hours=8, recent_days=30, nvd=FakeNvd()
    )  # type: ignore[arg-type]
    by_id = {f["id"]: f for f in found}
    assert set(by_id) == {
        "kev:vpn.example.com/cve-2099-0001",  # version in range
        "kev:vpn.example.com/cve-2099-0002",  # no NVD data, recent
        "kev:old.example.com/cve-2099-0002",  # no NVD data, recent
        "kev:unknown.example.com/cve-2099-0002",  # no version, recent
    }
    first = by_id["kev:vpn.example.com/cve-2099-0001"]
    assert first["deadline"] == "2026-01-10T08:00:00+00:00"
    assert "ransomware" in first["notes"] and first["owner"] == "Jane"


def test_match_internetdb() -> None:
    rows = [{"id": "inventory:203.0.113.2", "product": "Some appliance", "ip": "203.0.113.2"}]
    found, _ = kev.match(
        CATALOG,
        rows,
        run_date=RUN,
        deadline_hours=8,
        recent_days=0,
        nvd=None,
        internetdb={"203.0.113.2": {"vulns": ["CVE-2099-0001", "CVE-1999-9999"]}},
    )
    assert [f["id"] for f in found] == ["kev:203.0.113.2/cve-2099-0001"]


def test_kev_run_includes_devices(
    scoped: Config, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        kev, "cached_json", lambda *a, **k: {"catalogVersion": "test", "vulnerabilities": CATALOG}
    )
    directory = scoped.output_dir / RUN.isoformat()
    write_csv(
        directory / "devices_fortigate.csv",
        [{"id": "device:fortigate/fgt-hq", "product": "FortiOS", "version": ""}],
        ["id", "product", "version"],
    )
    kev.run(scoped, RUN, use_nvd=False)
    rows = read_csv(scoped.registers_dir / "findings.csv")
    assert [r["id"] for r in rows] == ["kev:fortigate/fgt-hq/cve-2099-0002"]
    assert summary(scoped, "6_findings_overdue.summary.json")["count"] == 1
