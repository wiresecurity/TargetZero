# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed Google Workspace role plan (1_gws_role-plan.csv). Dry run unless applied.

Actions in the plan's action column:

  revoke               remove the role (super admins without an explicit assignment: remove
                       super admin status)
  move-ou              move the admin into target_org_unit, e.g. /Admins
  restore-role         assign the role again (used by rollback)
  restore-super-admin  make the user super admin again (used by rollback)

Safety: break-glass accounts are never changed, and it refuses to leave fewer than two super
admins. Every applied change is logged with a rollback plan next to it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import date
from pathlib import Path
from typing import Any

from targetzero.common.changes import save_change_log
from targetzero.common.config import Config
from targetzero.common.output import read_csv, run_dir
from targetzero.gws.client import Gws

PLAN_FIELDS = (
    "plan_id",
    "account",
    "user_id",
    "role",
    "role_id",
    "role_assignment_id",
    "scope_type",
    "super_admin",
    "org_unit",
    "break_glass",
    "mfa_class",
    "action",
    "target_org_unit",
    "justification",
)
ACTIONS = ("revoke", "move-ou", "restore-role", "restore-super-admin")
UNDO = {
    "revoke": "restore-role",
    "restore-role": "revoke",
    "restore-super-admin": "revoke",
    "move-ou": "move-ou",
}
MIN_SUPER_ADMINS = 2


def calls_for(gws: Gws, row: Mapping[str, str]) -> list[tuple[str, Callable[[], Any]]]:
    """(description, call) pairs for one plan row."""
    directory = gws.directory
    user = row["user_id"] or row["account"]
    action = row["action"]
    if action == "revoke" and row["role_assignment_id"]:
        assignment = row["role_assignment_id"]
        return [
            (
                f"delete role assignment {assignment}",
                lambda: (
                    directory.roleAssignments()
                    .delete(customer=gws.customer, roleAssignmentId=assignment)
                    .execute()
                ),
            )
        ]
    if action in ("revoke", "restore-super-admin") and row["super_admin"] == "Y":
        status = action == "restore-super-admin"
        return [
            (
                f"set super admin {status} for {row['account']}",
                lambda: (
                    directory.users().makeAdmin(userKey=user, body={"status": status}).execute()
                ),
            )
        ]
    if action == "restore-role":
        body = {"roleId": row["role_id"], "assignedTo": row["user_id"], "scopeType": "CUSTOMER"}
        return [
            (
                f"assign role {row['role']}",
                lambda: (
                    directory.roleAssignments().insert(customer=gws.customer, body=body).execute()
                ),
            )
        ]
    if action == "move-ou":
        target = row["target_org_unit"]
        return [
            (
                f"move to {target}",
                lambda: (
                    directory.users().update(userKey=user, body={"orgUnitPath": target}).execute()
                ),
            )
        ]
    raise ValueError(f"cannot {action} this row")


def apply_plan(
    config: Config, gws: Gws, plan: Path, run_date: date, *, apply: bool = False
) -> tuple[list[dict[str, str]], list[Path]]:
    rows = [r for r in read_csv(plan) if r.get("action")]
    break_glass = set(config.break_glass("gws"))
    super_admins = len(
        gws.pages(gws.directory.users().list, "users", customer=gws.customer, query="isAdmin=true")
    )
    losing = {
        r["account"].lower()
        for r in rows
        if r["action"] == "revoke"
        and r.get("super_admin") == "Y"
        and r.get("break_glass") != "Y"
        and r["account"].lower() not in break_glass
    }

    results: list[dict[str, str]] = []
    rollback: list[dict[str, str]] = []
    for row in rows:
        result = {
            "plan_id": row.get("plan_id", ""),
            "account": row["account"],
            "role": row.get("role", ""),
            "action": row["action"],
            "status": "",
            "detail": "",
        }
        account = row["account"].lower()
        refuse = ""
        if row["action"] not in ACTIONS:
            refuse = f"unknown action '{row['action']}'"
        elif row.get("break_glass") == "Y" or account in break_glass:
            refuse = "break-glass account: never changed"
        elif row["action"] == "move-ou" and not row.get("target_org_unit", "").startswith("/"):
            refuse = "move-ou needs target_org_unit, e.g. /Admins"
        elif account in losing and super_admins - len(losing) < MIN_SUPER_ADMINS:
            refuse = (
                f"would leave fewer than {MIN_SUPER_ADMINS} super admins "
                f"({super_admins} now, {len(losing)} planned to go)"
            )
        if refuse:
            results.append(result | {"status": "refused", "detail": refuse})
            continue
        try:
            calls = calls_for(gws, row)
        except ValueError as exc:
            results.append(result | {"status": "refused", "detail": str(exc)})
            continue
        description = " + ".join(d for d, _ in calls)
        if not apply:
            results.append(result | {"status": "dry-run", "detail": f"would {description}"})
            continue
        try:
            for _, call in calls:
                response = call()
                if row["action"] == "restore-role" and isinstance(response, dict):
                    row["role_assignment_id"] = str(response.get("roleAssignmentId", ""))
        except Exception as exc:
            results.append(result | {"status": "failed", "detail": str(exc)})
            continue
        results.append(result | {"status": "applied", "detail": description})
        back = {f: row.get(f, "") for f in PLAN_FIELDS}
        back["action"] = UNDO[row["action"]]
        if row["action"] == "move-ou":
            back["target_org_unit"], back["org_unit"] = (
                row.get("org_unit", "/"),
                row["target_org_unit"],
            )
        if (
            row["action"] == "revoke"
            and row.get("super_admin") == "Y"
            and not row["role_assignment_id"]
        ):
            back["action"] = "restore-super-admin"
        back["justification"] = f"Rollback of {row['action']} {date.today().isoformat()}"
        rollback.append(back)

    paths = save_change_log(
        run_dir(config.output_dir, run_date),
        "gws_roles",
        results,
        rollback,
        PLAN_FIELDS,
        dry_run=not apply,
    )
    return results, paths
