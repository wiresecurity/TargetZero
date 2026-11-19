# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import date

from targetzero.admins import count_items, write_admin_outputs


def rec(account: str, role: str = "Global Administrator", **kw: str) -> dict[str, str]:
    base = {
        "source": "m365",
        "system": "contoso",
        "account": account,
        "role": role,
        "account_type": "user",
        "privileged": "Y",
        "permanent": "Y",
        "mfa_class": "mfa",
        "mfa_enforced": "Y",
        "break_glass": "N",
    }
    return base | kw


def ids(items: list[dict[str, str]]) -> list[str]:
    return [i["id"] for i in items]


def test_permanent_privileged_counts_once_per_account() -> None:
    zero1, _ = count_items([rec("a@x.com"), rec("A@x.com", "Exchange Administrator")])
    assert ids(zero1) == ["m365:contoso/a@x.com"]
    assert zero1[0]["reason"] == "Permanent Exchange Administrator, Global Administrator"


def test_eligible_or_unprivileged_or_break_glass_not_in_zero1() -> None:
    zero1, _ = count_items(
        [
            rec("eligible@x.com", permanent="N"),
            rec("reader@x.com", "Global Reader", privileged="N"),
            rec("bg@x.com", break_glass="Y"),
        ]
    )
    assert zero1 == []


def test_zero2_weakest_record_wins() -> None:
    _, zero2 = count_items(
        [
            rec("ok@x.com", mfa_class="phishing-resistant"),
            rec("sms@x.com", mfa_class="does-not-count"),
            rec("unknown@x.com", mfa_class="unknown"),
            rec("notenforced@x.com", mfa_enforced="N"),
            rec("mixed@x.com", mfa_enforced="Y"),
            rec("mixed@x.com", "Exchange Administrator", mfa_enforced="unknown"),
        ]
    )
    assert ids(zero2) == [
        "m365:contoso/mixed@x.com",
        "m365:contoso/notenforced@x.com",
        "m365:contoso/sms@x.com",
        "m365:contoso/unknown@x.com",
    ]


def test_service_accounts_count_for_zero1_not_zero2() -> None:
    zero1, zero2 = count_items([rec("backup-app", account_type="service", mfa_class="none")])
    assert ids(zero1) == ["m365:contoso/backup-app"]
    assert zero2 == []


def test_break_glass_still_needs_mfa() -> None:
    _, zero2 = count_items([rec("bg@x.com", break_glass="Y", mfa_class="none", mfa_enforced="N")])
    assert ids(zero2) == ["m365:contoso/bg@x.com"]


def test_write_admin_outputs(tmp_path) -> None:  # type: ignore[no-untyped-def]
    paths = write_admin_outputs(
        tmp_path,
        source="m365",
        records=[rec("a@x.com", id="m365:x")],
        tool="t",
        run_date=date(2026, 11, 19),
    )
    assert [p.name for p in paths] == [
        "1_m365_admins.csv",
        "1_m365_admins.summary.json",
        "2_m365_mfa.summary.json",
    ]


def test_shared_cases_match_powershell() -> None:
    import json
    from pathlib import Path

    cases = json.loads(
        (Path(__file__).parents[2] / "tests" / "shared" / "admin-count-cases.json").read_text()
    )
    zero1, zero2 = count_items(cases["records"])
    assert sorted(ids(zero1)) == cases["expected_zero1"]
    assert sorted(ids(zero2)) == cases["expected_zero2"]
