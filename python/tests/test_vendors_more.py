# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from conftest import FIXTURES

from targetzero.vendors import cisco_asa, redfish, vsphere


def test_cisco_asa() -> None:
    device = cisco_asa.collect(FIXTURES / "asa-running-config.txt", set())
    assert (device.system, device.version) == ("FW-EDGE", "9.16(4)")
    admins = {a["account"]: a for a in device.admins}
    assert set(admins) == {"admin", "netops", "helpdesk", "ISE (remote admins)"}  # vpnuser skipped
    assert admins["admin"]["privileged"] == "Y" and admins["helpdesk"]["privileged"] == "N"
    assert admins["admin"]["mfa_class"] == "unknown"  # ISE in use, LOCAL is the fallback
    assert {e["id"] for e in device.exposure} == {
        "asa:fw-edge/outside/http",
        "asa:fw-edge/outside/ssh",
    }
    reasons = {e["services"]: e["reason"] for e in device.exposure}
    assert "from anywhere" in reasons["https (ASDM)"]
    assert "198.51.100.0/255.255.255.0" in reasons["ssh"]


class FakeRedfish:
    def __init__(self, pages: dict[str, dict[str, Any]]) -> None:
        self.pages = pages

    def get(self, path: str) -> dict[str, Any]:
        return self.pages[path]

    def members(self, path: str) -> list[dict[str, Any]]:
        return [self.pages[m["@odata.id"]] for m in self.pages[path]["Members"]]


def test_redfish() -> None:
    pages = {
        "/redfish/v1/": {
            "Vendor": "Dell",
            "Managers": {"@odata.id": "/m"},
            "AccountService": {"@odata.id": "/as"},
        },
        "/m": {"Members": [{"@odata.id": "/m/1"}]},
        "/m/1": {"Model": "iDRAC9", "FirmwareVersion": "7.00.00.00"},
        "/as": {
            "Accounts": {"@odata.id": "/as/a"},
            "MultiFactorAuth": {"GoogleAuthenticator": {"Enabled": False}},
        },
        "/as/a": {
            "Members": [
                {"@odata.id": "/as/a/1"},
                {"@odata.id": "/as/a/2"},
                {"@odata.id": "/as/a/3"},
            ]
        },
        "/as/a/1": {"UserName": "", "RoleId": "None"},
        "/as/a/2": {"UserName": "root", "RoleId": "Administrator", "Enabled": True},
        "/as/a/3": {"UserName": "monitor", "RoleId": "ReadOnly", "Enabled": False},
    }
    device = redfish.collect(FakeRedfish(pages), "idrac-01.example.com", set())  # type: ignore[arg-type]
    assert (device.product, device.version) == ("Dell iDRAC9", "7.00.00.00")
    assert [(a["account"], a["privileged"], a["mfa_class"]) for a in device.admins] == [
        ("root", "Y", "none"),
        ("monitor", "N", "none"),
    ]
    assert "disabled" in device.admins[1]["notes"]
    assert device.checks_exposure is False


def test_redfish_mfa_settings() -> None:
    assert redfish.mfa_settings({"MultiFactorAuth": {"SecurID": {"Enabled": True}}})[0] == "mfa"
    assert redfish.mfa_settings({"LDAP": {"ServiceEnabled": True}})[0] == "unknown"


def test_vsphere() -> None:
    perms = [
        SimpleNamespace(
            principal="VSPHERE.LOCAL\\Administrators",
            group=True,
            roleId=-1,
            propagate=True,
            entity=SimpleNamespace(name="Datacenters"),
        ),
        SimpleNamespace(
            principal="EXAMPLE\\jane",
            group=False,
            roleId=-2,
            propagate=False,
            entity=SimpleNamespace(name="Cluster1"),
        ),
    ]
    manager = SimpleNamespace(
        roleList=[
            SimpleNamespace(roleId=-1, name="Admin"),
            SimpleNamespace(roleId=-2, name="ReadOnly"),
        ],
        RetrieveAllPermissions=lambda: perms,
    )
    content = SimpleNamespace(
        about=SimpleNamespace(name="VMware vCenter Server", fullName="x", version="8.0.2"),
        authorizationManager=manager,
    )
    device = vsphere.collect(content, "vc.example.com", set())
    assert device.product == "VMware vCenter Server" and device.version == "8.0.2"
    first, second = device.admins
    assert (first["privileged"], first["mfa_class"]) == ("Y", "unknown")
    assert "group" in first["notes"] and "Datacenters and below" in first["notes"]
    assert second["privileged"] == "N"
    declared = vsphere.collect(content, "vc.example.com", set(), mfa_via_idp=True)
    assert declared.admins[0]["mfa_enforced"] == "Y"
