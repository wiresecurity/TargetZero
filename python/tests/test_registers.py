# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from datetime import UTC, date, datetime

from targetzero.common.config import Config
from targetzero.common.output import read_csv, write_csv
from targetzero.registers import findings, inventory, manual_admins

RUN = date(2026, 11, 19)


def summary(config: Config, name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((config.output_dir / RUN.isoformat() / name).read_text())


def test_manual_admins(config: Config) -> None:
    from targetzero.admins import FIELDS

    rows = [
        {
            "system": "Main firewall",
            "account": "admin",
            "role": "super_admin",
            "account_type": "user",
            "privileged": "Y",
            "permanent": "Y",
            "mfa_class": "none",
            "mfa_enforced": "N",
            "break_glass": "N",
        },
        {
            "system": "Backup",
            "account": "veeam",
            "role": "Backup Administrator",
            "privileged": "Y",
            "permanent": "maybe",
            "mfa_class": "mfa",
            "mfa_enforced": "Y",
            "break_glass": "N",
        },
    ]
    write_csv(config.registers_dir / "manual_admins.csv", rows, FIELDS)
    manual_admins.run(config, RUN)
    zero1 = summary(config, "1_manual_admins.summary.json")
    assert [i["id"] for i in zero1["items"]] == ["manual:main-firewall/admin"]
    assert zero1["complete"] is False
    assert any("row 3 skipped" in n for n in zero1["notes"])
    assert summary(config, "2_manual_mfa.summary.json")["count"] == 1


def test_manual_admins_missing_file_is_incomplete(config: Config) -> None:
    manual_admins.run(config, RUN)
    assert summary(config, "1_manual_admins.summary.json")["complete"] is False


def test_inventory_merge_keeps_hand_columns() -> None:
    rows = [
        {
            "id": "inventory:www.example.com",
            "asset": "www.example.com",
            "type": "subdomain",
            "ip": "203.0.113.9",
            "owner": "Jane",
            "status": "reviewed",
        }
    ]
    discovered = [
        {
            "id": "inventory:www.example.com",
            "asset": "WWW.example.com",
            "type": "subdomain",
            "ip": "203.0.113.10",
            "owner": "should not win",
        },
        {
            "id": "inventory:new.example.com",
            "asset": "new.example.com",
            "type": "subdomain",
            "ip": "203.0.113.11",
        },
    ]
    merged, added, updated = inventory.merge(rows, discovered)
    assert (added, updated) == (1, 1)
    assert merged[0]["owner"] == "Jane" and merged[0]["ip"] == "203.0.113.10"
    assert merged[1]["status"] == "unreviewed"


def test_inventory_count(config: Config) -> None:
    complete = {
        "owner": "Jane",
        "purpose": "web",
        "product": "nginx",
        "version": "1.26",
        "vendor_supported": "Y",
        "status": "reviewed",
        "last_reviewed": "2026-11-01",
    }
    rows = [
        {"id": "inventory:ok", "asset": "ok", "type": "subdomain", **complete},
        {
            "id": "inventory:old",
            "asset": "old",
            "type": "subdomain",
            **(complete | {"last_reviewed": "2026-01-01"}),
        },
        {"id": "inventory:new", "asset": "new", "type": "subdomain", "status": "unreviewed"},
        {"id": "inventory:gone", "asset": "gone", "type": "subdomain", "status": "retired"},
    ]
    write_csv(config.registers_dir / "inventory.csv", rows, inventory.FIELDS)
    inventory.count(config, RUN)
    data = summary(config, "5_inventory_rows.summary.json")
    assert [i["id"] for i in data["items"]] == ["inventory:old", "inventory:new"]
    assert "last reviewed 322 days ago" in data["items"][0]["reason"]


def test_findings_count_only_overdue_open(config: Config) -> None:
    base = {
        "asset_id": "inventory:vpn",
        "vulnerability": "CVE-2099-0001",
        "severity": "kev",
        "published": "2026-11-18",
    }
    rows = [
        base | {"id": "kev:vpn/a", "deadline": "2026-11-18T08:00:00+00:00", "status": "open"},
        base | {"id": "kev:vpn/b", "deadline": "2026-11-20T08:00:00+00:00", "status": "open"},
        base | {"id": "kev:vpn/c", "deadline": "2026-11-18T08:00:00+00:00", "status": "patched"},
        base | {"id": "kev:vpn/d", "deadline": "2026-11-18T08:00:00+00:00", "status": "exception"},
        base | {"id": "kev:vpn/e", "deadline": "not a date", "status": "open"},
    ]
    write_csv(config.registers_dir / "findings.csv", rows, findings.FIELDS)
    findings.count(config, RUN, now=datetime(2026, 11, 19, 12, tzinfo=UTC))
    data = summary(config, "6_findings_overdue.summary.json")
    assert [i["id"] for i in data["items"]] == ["kev:vpn/a", "kev:vpn/d", "kev:vpn/e"]


def test_findings_merge_never_overwrites() -> None:
    rows = [{"id": "kev:x/cve-1", "status": "patched"}]
    merged, added = findings.merge(
        rows, [{"id": "kev:x/cve-1", "status": "open"}, {"id": "kev:x/cve-2", "status": "open"}]
    )
    assert added == 1 and merged[0]["status"] == "patched"


def test_saving_keeps_a_backup(config: Config) -> None:
    inventory.save(config, [])
    inventory.save(config, [])
    assert len(list(config.registers_dir.glob("inventory.csv.*.bak"))) == 1
    assert read_csv(config.registers_dir / "inventory.csv") == []
