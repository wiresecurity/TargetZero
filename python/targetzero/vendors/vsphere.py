# SPDX-License-Identifier: Apache-2.0
"""VMware vSphere (vCenter or ESXi) collector, live and read-only. Install with [vsphere].

Lists every permission (principal, role, object) and the product version. MFA for vCenter
depends on its identity source (SSO, AD, or identity federation with an IdP), which the API
does not show: pass --mfa-via-idp when your identity source enforces MFA for these admins.

Credentials come from TARGETZERO_VSPHERE_USER and TARGETZERO_VSPHERE_PASSWORD (read-only role).
"""

from __future__ import annotations

import os
import ssl
from typing import Any

from targetzero.common.config import ConfigError
from targetzero.common.ids import make_id
from targetzero.vendors.common import Device

SOURCE = "vsphere"
ADMIN_ROLE_IDS = {-1}  # Admin
PRIVILEGED_NAMES = {"Admin", "NoCryptoAdmin", "Administrator"}


def credentials() -> tuple[str, str]:
    user = os.environ.get("TARGETZERO_VSPHERE_USER", "")
    password = os.environ.get("TARGETZERO_VSPHERE_PASSWORD", "")
    if not user or not password:
        raise ConfigError("Set TARGETZERO_VSPHERE_USER and TARGETZERO_VSPHERE_PASSWORD")
    return user, password


def connect(host: str, context: ssl.SSLContext) -> Any:
    try:
        from pyVim.connect import SmartConnect
    except ImportError as exc:
        raise ConfigError(
            "vSphere support is not installed: pip install 'targetzero[vsphere]'"
        ) from exc
    user, password = credentials()
    return SmartConnect(host=host, user=user, pwd=password, sslContext=context)


def entity_name(entity: Any) -> str:
    try:
        return str(entity.name)
    except Exception:
        return "?"


def collect(content: Any, host: str, break_glass: set[str], *, mfa_via_idp: bool = False) -> Device:
    about = content.about
    device = Device(
        vendor="VMware",
        system=host,
        product=str(about.name),
        model=str(about.fullName),
        version=str(about.version),
        file=host,
        checks_exposure=False,
    )
    manager = content.authorizationManager
    roles = {r.roleId: r.name for r in manager.roleList}
    if mfa_via_idp:
        mfa_class, enforced, note = (
            "mfa",
            "Y",
            "MFA enforced by the identity source (declared with --mfa-via-idp)",
        )
    else:
        mfa_class, enforced, note = (
            "unknown",
            "unknown",
            "MFA depends on the identity source: check it",
        )
    for permission in manager.RetrieveAllPermissions():
        role = roles.get(permission.roleId, str(permission.roleId))
        principal = str(permission.principal)
        where = entity_name(permission.entity)
        notes = [note, f"on {where}{' and below' if permission.propagate else ''}"]
        if permission.group:
            notes.append("group: list its members in the identity source")
        device.admins.append(
            {
                "id": make_id(SOURCE, host, principal, role, where),
                "source": SOURCE,
                "system": host,
                "account": principal,
                "role": role,
                "account_type": "user",
                "privileged": "Y"
                if permission.roleId in ADMIN_ROLE_IDS or role in PRIVILEGED_NAMES
                else "N",
                "permanent": "Y",
                "mfa_class": mfa_class,
                "mfa_enforced": enforced,
                "break_glass": "Y" if principal.lower() in break_glass else "N",
                "notes": "; ".join(notes),
            }
        )
    return device
