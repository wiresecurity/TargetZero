# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from targetzero.common.config import Config
from targetzero.gws import admins
from targetzero.gws.client import Gws


class Call:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result

    def execute(self) -> dict[str, Any]:
        return self.result


class Resource:
    """Fake googleapiclient resource: method(**params) -> Call."""

    def __init__(self, **methods: Callable[..., dict[str, Any]]) -> None:
        for name, fn in methods.items():
            setattr(self, name, lambda _fn=fn, **params: Call(_fn(**params)))


USERS = [
    {
        "id": "1",
        "primaryEmail": "Jane@example.com",
        "isAdmin": True,
        "isEnrolledIn2Sv": True,
        "isEnforcedIn2Sv": True,
        "orgUnitPath": "/Admins",
    },
    {
        "id": "2",
        "primaryEmail": "bob@example.com",
        "isAdmin": False,
        "isDelegatedAdmin": True,
        "isEnrolledIn2Sv": True,
        "isEnforcedIn2Sv": False,
    },
    {"id": "3", "primaryEmail": "bg@example.com", "isAdmin": True, "isEnrolledIn2Sv": False},
    {
        "id": "4",
        "primaryEmail": "eve@example.com",
        "isAdmin": True,
        "isEnrolledIn2Sv": True,
        "isEnforcedIn2Sv": True,
    },
]
LOGINS = {
    "jane@example.com": ["security_key"],
    "bob@example.com": ["google_prompt", "idv_preregistered_phone"],
}


def list_users(query: str, **_: Any) -> dict[str, Any]:
    if query == "isAdmin=true":
        return {"users": [u for u in USERS if u["isAdmin"]]}
    return {"users": [u for u in USERS if u.get("isDelegatedAdmin")]}


def activities(userKey: str, **_: Any) -> dict[str, Any]:
    methods = LOGINS.get(userKey, [])
    return {
        "items": [
            {"events": [{"parameters": [{"name": "login_challenge_method", "multiValue": [m]}]}]}
            for m in methods
        ]
    }


def usage(**_: Any) -> dict[str, Any]:
    return {
        "usageReports": [
            {
                "entity": {"userEmail": "bob@example.com"},
                "parameters": [{"name": "gmail:num_emails_sent", "intValue": "12"}],
            }
        ]
    }


def fake_gws() -> Gws:
    directory = Resource()
    directory.users = lambda: Resource(list=list_users)  # type: ignore[attr-defined]
    directory.roles = lambda: Resource(
        list=lambda **_: {
            "items": [  # type: ignore[attr-defined]
                {"roleId": "r1", "roleName": "_SEED_ADMIN_ROLE", "isSuperAdminRole": True},
                {"roleId": "r2", "roleName": "_GROUPS_ADMIN_ROLE"},
                {"roleId": "r3", "roleName": "Help Desk Admin"},
            ]
        }
    )
    directory.roleAssignments = lambda: Resource(
        list=lambda **_: {
            "items": [  # type: ignore[attr-defined]
                {"roleId": "r1", "assignedTo": "1", "assigneeType": "user"},
                {"roleId": "r3", "assignedTo": "2", "assigneeType": "user"},
                {
                    "roleId": "r2",
                    "assignedTo": "2",
                    "assigneeType": "user",
                    "condition": "request.time < timestamp('2026-12-01T00:00:00Z')",
                },
                {"roleId": "r2", "assignedTo": "g1", "assigneeType": "group"},
            ]
        }
    )
    reports = Resource()
    reports.activities = lambda: Resource(list=activities)  # type: ignore[attr-defined]
    reports.userUsageReport = lambda: Resource(get=usage)  # type: ignore[attr-defined]
    return Gws(directory, reports, "my_customer")


@pytest.mark.parametrize(
    ("enrolled", "methods", "expected"),
    [
        (False, ["security_key"], "none"),
        (True, [], "unknown"),
        (True, ["security_key", "passkey"], "phishing-resistant"),
        (True, ["security_key", "idv_any_phone"], "does-not-count"),
        (True, ["password", "google_authenticator"], "mfa"),
    ],
)
def test_classify(enrolled: bool, methods: list[str], expected: str) -> None:
    assert admins.classify(enrolled, methods)[0] == expected


def test_collect(scoped: Config) -> None:
    records, notes = admins.collect(fake_gws(), scoped, days=30)
    by_key = {(r["account"], r["role"]): r for r in records}
    jane = by_key[("jane@example.com", "Super Admin")]
    assert (jane["mfa_class"], jane["privileged"], jane["separate_admin_account"]) == (
        "phishing-resistant",
        "Y",
        "Y",
    )
    helpdesk = by_key[("bob@example.com", "Help Desk Admin")]
    assert (helpdesk["privileged"], helpdesk["mfa_class"], helpdesk["mfa_enforced"]) == (
        "N",
        "does-not-count",
        "N",
    )
    assert helpdesk["separate_admin_account"] == "N"
    groups = by_key[("bob@example.com", " GROUPS ADMIN ROLE")]
    assert groups["permanent"] == "N"
    # Super admins without an explicit assignment come from isAdmin.
    assert by_key[("bg@example.com", "Super Admin")]["break_glass"] == "Y"
    assert by_key[("eve@example.com", "Super Admin")]["mfa_class"] == "unknown"
    assert any("assigned to a group" in n for n in notes)
