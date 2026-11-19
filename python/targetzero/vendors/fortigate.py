# SPDX-License-Identifier: Apache-2.0
"""Fortinet FortiGate (FortiOS) collector, offline: parses a configuration backup (.conf).

Get the file from System > Configuration > Backup, or `execute backup config`.
Encrypted backups cannot be read; make an unencrypted one and keep it safe.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from targetzero.admins import record_id
from targetzero.common.ids import make_id
from targetzero.vendors.common import Device

SOURCE = "fortigate"
PRIVILEGED_PROFILES = {"super_admin", "prof_admin"}
ADMIN_SERVICES = {"http", "https", "ssh", "telnet", "snmp", "fgfm", "radius-acct", "ftm"}
MANAGEMENT = {"http", "https", "ssh", "telnet", "snmp", "fgfm"}
VERSION_LINE = re.compile(r"#config-version=([A-Za-z0-9]+)-(\d+(?:\.\d+)+)-FW-build(\d+)")


@dataclass
class Node:
    settings: dict[str, list[str]] = field(default_factory=dict)
    configs: dict[str, Node] = field(default_factory=dict)
    edits: dict[str, Node] = field(default_factory=dict)


def parse(text: str) -> Node:
    root = Node()
    stack = [root]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            words = shlex.split(line, posix=True)
        except ValueError:
            words = line.split()
        keyword, args = words[0], words[1:]
        if keyword == "config":
            node = stack[-1].configs.setdefault(" ".join(args), Node())
            stack.append(node)
        elif keyword == "edit":
            node = stack[-1].edits.setdefault(" ".join(args), Node())
            stack.append(node)
        elif keyword in ("end", "next"):
            if len(stack) > 1:
                stack.pop()
        elif keyword == "set" and args:
            stack[-1].settings[args[0]] = args[1:]
    return root


def find(node: Node, path: str) -> list[Node]:
    """Every config block with this path, at any depth (covers VDOM mode)."""
    found = [child for name, child in node.configs.items() if name == path]
    for child in [*node.configs.values(), *node.edits.values()]:
        found += find(child, path)
    return found


def value(node: Node, key: str) -> str:
    return " ".join(node.settings.get(key, []))


def mfa(admin: Node) -> tuple[str, str, str]:
    """(mfa_class, mfa_enforced, note)."""
    method = value(admin, "two-factor") or "disable"
    if method in ("fortitoken", "fortitoken-cloud"):
        return "mfa", "Y", f"two-factor {method}"
    if method in ("email", "sms"):
        return "does-not-count", "Y", f"two-factor {method}"
    if value(admin, "remote-auth") == "enable":
        return (
            "unknown",
            "unknown",
            f"remote authentication ({value(admin, 'remote-group')}): "
            "check MFA on the RADIUS/LDAP/TACACS+ server",
        )
    return "none", "N", "password only"


def trusted_hosts(admin: Node) -> list[str]:
    hosts = []
    for key, values in admin.settings.items():
        if key.startswith("trusthost") or key.startswith("ip6-trusthost"):
            joined = " ".join(values)
            if joined not in ("0.0.0.0 0.0.0.0", "::/0", ""):
                hosts.append(joined)
    return hosts


def collect(path: Path, break_glass: set[str]) -> Device:
    text = path.read_text(encoding="utf-8", errors="replace")
    root = parse(text)
    hostname = next(
        (value(g, "hostname") for g in find(root, "system global") if value(g, "hostname")),
        path.stem,
    )
    device = Device(vendor="Fortinet", system=hostname, product="FortiOS", file=path.name)
    match = VERSION_LINE.search(text)
    if match:
        device.model, device.version = match.group(1), match.group(2)
    else:
        device.notes.append("firmware version not found in the file header")
    if text.lstrip().startswith("#FGBK") or "config system admin" not in text:
        device.notes.append("no 'config system admin' block: encrypted or partial backup?")

    for block in find(root, "system admin"):
        for name, admin in block.edits.items():
            profile = value(admin, "accprofile")
            mfa_class, enforced, note = mfa(admin)
            hosts = trusted_hosts(admin)
            notes = [
                note,
                f"trusted hosts: {', '.join(hosts)}" if hosts else "no trusted hosts set",
            ]
            device.admins.append(
                {
                    "id": record_id(SOURCE, hostname, name, profile),
                    "source": SOURCE,
                    "system": hostname,
                    "account": name,
                    "role": profile or "?",
                    "account_type": "user",
                    "privileged": "Y" if profile in PRIVILEGED_PROFILES else "N",
                    "permanent": "Y",
                    "mfa_class": mfa_class,
                    "mfa_enforced": enforced,
                    "break_glass": "Y" if name.lower() in break_glass else "N",
                    "notes": "; ".join(notes),
                }
            )
    for block in find(root, "system sso-admin"):
        for name, admin in block.edits.items():
            profile = value(admin, "accprofile")
            device.admins.append(
                {
                    "id": record_id(SOURCE, hostname, name, profile),
                    "source": SOURCE,
                    "system": hostname,
                    "account": name,
                    "role": profile or "?",
                    "account_type": "user",
                    "privileged": "Y" if profile in PRIVILEGED_PROFILES else "N",
                    "permanent": "Y",
                    "mfa_class": "unknown",
                    "mfa_enforced": "unknown",
                    "break_glass": "Y" if name.lower() in break_glass else "N",
                    "notes": "SAML single sign-on admin: check MFA at the identity provider",
                }
            )

    for block in find(root, "system interface"):
        for name, interface in block.edits.items():
            role = value(interface, "role")
            if role != "wan" and not name.lower().startswith("wan"):
                continue
            services = sorted(set(interface.settings.get("allowaccess", [])) & MANAGEMENT)
            if services:
                device.exposure.append(
                    {
                        "id": make_id(SOURCE, hostname, name),
                        "system": hostname,
                        "interface": name,
                        "zone_or_role": role or "wan (by name)",
                        "services": ";".join(services),
                        "reason": f"admin access ({', '.join(services)}) on WAN interface {name}",
                    }
                )
    return device
