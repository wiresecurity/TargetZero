# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from datetime import date

from conftest import FIXTURES

from targetzero.common.config import Config
from targetzero.common.output import read_csv
from targetzero.vendors import common, fortigate, panos

RUN = date(2026, 11, 19)


def by_account(device: common.Device) -> dict[str, dict[str, str]]:
    return {a["account"]: a for a in device.admins}


def test_fortigate() -> None:
    device = fortigate.collect(FIXTURES / "fortigate.conf", {"bg-fw"})
    assert (device.system, device.model, device.version) == ("FGT-HQ", "FGT60F", "7.2.5")
    admins = by_account(device)
    assert admins["admin"]["mfa_class"] == "none"
    assert "no trusted hosts" in admins["admin"]["notes"]
    assert admins["jane.admin"]["mfa_class"] == "mfa"
    assert "198.51.100.0" in admins["jane.admin"]["notes"]
    assert admins["helpdesk"]["mfa_class"] == "does-not-count"
    assert admins["helpdesk"]["privileged"] == "N"
    assert admins["radius-admins"]["mfa_class"] == "unknown"
    assert admins["bg-fw"]["break_glass"] == "Y"
    assert [e["id"] for e in device.exposure] == ["fortigate:fgt-hq/wan1"]
    assert device.exposure[0]["services"] == "https;ssh"


def test_fortigate_vdom_mode() -> None:
    text = """config vdom
edit root
config system admin
    edit "vdomadmin"
        set accprofile "prof_admin"
    next
end
next
end
"""
    root = fortigate.parse(text)
    assert list(fortigate.find(root, "system admin")[0].edits) == ["vdomadmin"]


def test_panos() -> None:
    device = panos.collect(FIXTURES / "panos-running-config.xml", set())
    assert (device.system, device.version) == ("PA-EDGE", "10.2.4")
    admins = by_account(device)
    assert (admins["admin"]["mfa_class"], admins["admin"]["role"]) == ("none", "superuser")
    assert admins["jane"]["mfa_class"] == "mfa"
    assert admins["auditor"]["privileged"] == "N"
    assert admins["certadmin"]["mfa_class"] == "phishing-resistant"
    assert admins["certadmin"]["role"] == "deviceadmin"
    assert admins["sso"]["mfa_class"] == "unknown"
    assert [e["id"] for e in device.exposure] == ["panos:pa-edge/ethernet1/1"]


def test_write_outputs(config: Config) -> None:
    devices = [fortigate.collect(FIXTURES / "fortigate.conf", {"bg-fw"})]
    common.write_outputs(config, RUN, "fortigate", devices, tool="test")
    directory = config.output_dir / RUN.isoformat()
    zero1 = json.loads((directory / "1_fortigate_admins.summary.json").read_text())
    # admin, jane.admin, radius-admins are permanent super_admin; bg-fw is break-glass.
    assert zero1["count"] == 3
    zero2 = json.loads((directory / "2_fortigate_mfa.summary.json").read_text())
    assert {i["id"] for i in zero2["items"]} == {
        "fortigate:fgt-hq/admin",
        "fortigate:fgt-hq/helpdesk",
        "fortigate:fgt-hq/radius-admins",
        "fortigate:fgt-hq/bg-fw",
    }
    zero4 = json.loads((directory / "4_fortigate_mgmt-exposure.summary.json").read_text())
    assert zero4["count"] == 1
    assert read_csv(directory / "devices_fortigate.csv")[0]["version"] == "7.2.5"
