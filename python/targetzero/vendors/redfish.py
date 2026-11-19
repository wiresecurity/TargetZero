# SPDX-License-Identifier: Apache-2.0
"""Server management cards (Dell iDRAC, HPE iLO and other Redfish BMCs), live and read-only.

Credentials come from TARGETZERO_REDFISH_USER and TARGETZERO_REDFISH_PASSWORD. Use a
read-only account. Management cards often have self-signed certificates: pass the CA with
--ca-bundle, or --insecure if you accept that risk on your own network.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.request
from typing import Any

from targetzero.admins import record_id
from targetzero.common.config import ConfigError
from targetzero.vendors.common import Device

SOURCE = "redfish"
PRIVILEGED_ROLES = {"Administrator"}
MFA_KEYS = ("SecurID", "GoogleAuthenticator", "MicrosoftAuthenticator")


class Redfish:
    def __init__(self, host: str, user: str, password: str, context: ssl.SSLContext) -> None:
        self.base = f"https://{host}"
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        self.context = context

    def get(self, path: str) -> dict[str, Any]:
        url = path if path.startswith("https://") else self.base + path
        request = urllib.request.Request(url, headers=self.headers)  # noqa: S310 (https only)
        with urllib.request.urlopen(request, timeout=20, context=self.context) as response:  # noqa: S310
            data: dict[str, Any] = json.loads(response.read().decode("utf-8"))
            return data

    def members(self, path: str) -> list[dict[str, Any]]:
        return [self.get(m["@odata.id"]) for m in self.get(path).get("Members", [])]


def ssl_context(ca_bundle: str | None, insecure: bool) -> ssl.SSLContext:
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=ca_bundle)


def credentials() -> tuple[str, str]:
    user = os.environ.get("TARGETZERO_REDFISH_USER", "")
    password = os.environ.get("TARGETZERO_REDFISH_PASSWORD", "")
    if not user or not password:
        raise ConfigError("Set TARGETZERO_REDFISH_USER and TARGETZERO_REDFISH_PASSWORD")
    return user, password


def mfa_settings(account_service: dict[str, Any]) -> tuple[str, str, str]:
    mfa = account_service.get("MultiFactorAuth") or {}
    enabled = [k for k in MFA_KEYS if (mfa.get(k) or {}).get("Enabled")]
    if (mfa.get("ClientCertificate") or {}).get("Enabled"):
        return "phishing-resistant", "unknown", "client certificate authentication enabled"
    if enabled:
        return "mfa", "unknown", f"multi-factor enabled: {', '.join(enabled)}"
    directory = [
        k
        for k in ("LDAP", "ActiveDirectory")
        if (account_service.get(k) or {}).get("ServiceEnabled")
    ]
    if directory:
        return "unknown", "unknown", f"{'/'.join(directory)} login enabled: check MFA there"
    return "none", "N", "no multi-factor authentication configured"


def collect(client: Redfish, host: str, break_glass: set[str]) -> Device:
    root = client.get("/redfish/v1/")
    managers = client.members(root.get("Managers", {}).get("@odata.id", "/redfish/v1/Managers"))
    manager = managers[0] if managers else {}
    vendor = str(root.get("Vendor") or manager.get("Manufacturer") or "")
    model = str(manager.get("Model") or manager.get("Name") or "")
    device = Device(
        vendor=vendor,
        system=host,
        product=f"{vendor} {model}".strip(),
        model=model,
        version=str(manager.get("FirmwareVersion", "")),
        file=host,
        checks_exposure=False,
    )
    account_service = client.get(
        root.get("AccountService", {}).get("@odata.id", "/redfish/v1/AccountService")
    )
    mfa_class, enforced, note = mfa_settings(account_service)
    accounts = client.members(
        account_service.get("Accounts", {}).get("@odata.id", "/redfish/v1/AccountService/Accounts")
    )
    for account in accounts:
        name = str(account.get("UserName") or "")
        if not name:
            continue  # empty slot (iDRAC has 16)
        role = str(account.get("RoleId") or "?")
        notes = [note] + ([] if account.get("Enabled", True) else ["disabled"])
        device.admins.append(
            {
                "id": record_id(SOURCE, host, name, role),
                "source": SOURCE,
                "system": host,
                "account": name,
                "role": role,
                "account_type": "user",
                "privileged": "Y" if role in PRIVILEGED_ROLES else "N",
                "permanent": "Y",
                "mfa_class": mfa_class,
                "mfa_enforced": enforced,
                "break_glass": "Y" if name.lower() in break_glass else "N",
                "notes": "; ".join(notes),
            }
        )
    device.notes.append("internet exposure of the card is checked by `external scan` (443, 623)")
    return device
