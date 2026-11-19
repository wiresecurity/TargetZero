# SPDX-License-Identifier: Apache-2.0
"""Google Workspace admins (Zero 1 and Zero 2).

Records one row per admin and role, in the unified admin format:

- Roles come from role assignments; super admins without an explicit
  assignment are added from the user list (isAdmin).
- Google Workspace has no general expiry on role assignments. An assignment
  is treated as time-bound only when it carries a condition on request.time.
- MFA class comes from the second factors the admin actually used to sign in
  during the last --days days (Reports API, login events). Not enrolled in
  2-Step Verification means none. Enrolled but no sign-in seen means unknown.
- MFA is enforced when 2-Step Verification is enforced for the admin.
- Separate admin account: N when the admin sent mail in the sample days.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from targetzero.admins import record_id, write_admin_outputs
from targetzero.common.config import Config
from targetzero.common.output import run_dir
from targetzero.common.roles import privileged_roles
from targetzero.gws.client import Gws

SOURCE = "gws"

# login_challenge_method values from the Reports API login audit.
CHALLENGE_CLASS = {
    "security_key": "phishing-resistant",
    "passkey": "phishing-resistant",
    "google_authenticator": "mfa",
    "google_prompt": "mfa",
    "totp": "mfa",
    "offline_otp": "mfa",
    "backup_code": "mfa",
    "internal_two_factor": "mfa",
    "idv_preregistered_phone": "does-not-count",
    "idv_any_phone": "does-not-count",
}
RANK = {"does-not-count": 1, "mfa": 3, "phishing-resistant": 4}


def classify(enrolled: bool, methods: Iterable[str]) -> tuple[str, list[str]]:
    """Weakest second factor used counts: one SMS sign-in shows SMS still works."""
    if not enrolled:
        return "none", []
    classes = [CHALLENGE_CLASS[m] for m in methods if m in CHALLENGE_CLASS]
    unknown = sorted(
        {m for m in methods if m not in CHALLENGE_CLASS and m not in ("password", "none")}
    )
    if not classes:
        return "unknown", unknown
    return min(classes, key=RANK.__getitem__), unknown


def login_methods(gws: Gws, emails: Iterable[str], days: int) -> dict[str, set[str]]:
    start = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    found: dict[str, set[str]] = {}
    for email in emails:
        events = gws.pages(
            gws.reports.activities().list,
            "items",
            userKey=email,
            applicationName="login",
            eventName="login_success",
            startTime=start,
        )
        for activity in events:
            for event in activity.get("events", []):
                for parameter in event.get("parameters", []):
                    if parameter.get("name") == "login_challenge_method":
                        values = parameter.get("multiValue") or [parameter.get("value", "")]
                        found.setdefault(email, set()).update(v for v in values if v)
    return found


def mail_senders(gws: Gws, sample_days: int = 7) -> tuple[set[str], bool]:
    """Users who sent mail on recent days. Usage reports lag about three days."""
    senders: set[str] = set()
    ok = False
    for offset in range(3, 3 + sample_days):
        day = (date.today() - timedelta(days=offset)).isoformat()
        try:
            reports = gws.pages(
                gws.reports.userUsageReport().get,
                "usageReports",
                userKey="all",
                date=day,
                parameters="gmail:num_emails_sent",
            )
        except Exception:  # noqa: S112 - the report for a day may not exist yet
            continue
        ok = True
        for report in reports:
            for parameter in report.get("parameters", []):
                if (
                    parameter.get("name") == "gmail:num_emails_sent"
                    and int(parameter.get("intValue", 0)) > 0
                ):
                    senders.add(report.get("entity", {}).get("userEmail", "").lower())
    return senders, ok


def is_time_bound(assignment: Mapping[str, Any]) -> bool:
    return "request.time" in str(assignment.get("condition", ""))


def collect(gws: Gws, config: Config, days: int) -> tuple[list[dict[str, str]], list[str]]:
    notes: list[str] = []
    privileged = privileged_roles(config, "gws")
    break_glass = set(config.break_glass(SOURCE))
    roles = {
        r["roleId"]: r
        for r in gws.pages(gws.directory.roles().list, "items", customer=gws.customer)
    }
    users = {
        u["id"]: u
        for u in gws.pages(
            gws.directory.users().list, "users", customer=gws.customer, query="isAdmin=true"
        )
    }
    delegated = gws.pages(
        gws.directory.users().list, "users", customer=gws.customer, query="isDelegatedAdmin=true"
    )
    users |= {u["id"]: u for u in delegated}
    assignments = gws.pages(gws.directory.roleAssignments().list, "items", customer=gws.customer)

    pairs: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]] = []
    covered: set[str] = set()
    for assignment in assignments:
        assignee = users.get(assignment.get("assignedTo", ""))
        if assignee is None:
            if assignment.get("assigneeType", "user") != "user":
                notes.append(
                    f"Role {assignment.get('roleId')} assigned to a group: list its members "
                    "in manual_admins.csv"
                )
            continue
        role = roles.get(assignment["roleId"], {"roleName": assignment["roleId"]})
        pairs.append((assignee, role, assignment))
        if role.get("isSuperAdminRole"):
            covered.add(assignee["id"])
    for candidate in users.values():
        if candidate.get("isAdmin") and candidate["id"] not in covered:
            pairs.append((candidate, {"roleName": "Super Admin", "isSuperAdminRole": True}, None))

    emails = sorted({u["primaryEmail"].lower() for u, _, _ in pairs})
    methods = login_methods(gws, emails, days)
    senders, usage_ok = mail_senders(gws)
    if not usage_ok:
        notes.append("Gmail usage reports unavailable: separate_admin_account left empty")

    records = []
    for user, role, grant in pairs:
        email = user["primaryEmail"].lower()
        name = str(role.get("roleName", "")).replace("_", " ")
        if role.get("isSuperAdminRole"):
            name = "Super Admin"
        mfa_class, unmapped = classify(bool(user.get("isEnrolledIn2Sv")), methods.get(email, set()))
        extra = [f"org unit {user.get('orgUnitPath', '/')}"]
        if user.get("suspended"):
            extra.append("suspended")
        if unmapped:
            extra.append("unmapped sign-in methods: " + ", ".join(unmapped))
        if mfa_class == "unknown":
            extra.append(f"no sign-in in the last {days} days")
        if grant and grant.get("scopeType") == "ORG_UNIT":
            extra.append("role limited to an org unit")
        records.append(
            {
                "id": record_id(SOURCE, gws.customer, email, name),
                "source": SOURCE,
                "system": gws.customer,
                "account": email,
                "role": name,
                "account_type": "user",
                "privileged": "Y"
                if role.get("isSuperAdminRole") or name.casefold() in privileged
                else "N",
                "permanent": "N" if grant and is_time_bound(grant) else "Y",
                "mfa_class": mfa_class,
                "mfa_enforced": "Y" if user.get("isEnforcedIn2Sv") else "N",
                "separate_admin_account": ("N" if email in senders else "Y") if usage_ok else "",
                "break_glass": "Y" if email in break_glass else "N",
                "last_logon": user.get("lastLoginTime", ""),
                "notes": "; ".join(extra),
            }
        )
    return records, notes


def run(config: Config, run_date: date, gws: Gws, days: int = 30) -> list[Path]:
    records, notes = collect(gws, config, days)
    return write_admin_outputs(
        run_dir(config.output_dir, run_date),
        source=SOURCE,
        records=records,
        tool="targetzero gws admins",
        run_date=run_date,
        notes=notes,
    )
