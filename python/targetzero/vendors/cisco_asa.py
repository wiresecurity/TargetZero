# SPDX-License-Identifier: Apache-2.0
"""Cisco ASA collector, offline: parses `show running-config` saved as text.

Save it with `more system:running-config` or `show running-config` in a terminal session that
logs to a file, or copy it from ASDM (File > Show Running Configuration in New Window).
"""

from __future__ import annotations

import re
from pathlib import Path

from targetzero.admins import record_id
from targetzero.common.ids import make_id
from targetzero.vendors.common import Device

SOURCE = "asa"
UNTRUSTED = re.compile(r"outside|internet|wan|untrust|external|public", re.IGNORECASE)
USER = re.compile(r"^username (\S+) (?:password|nopassword)\b.*?(?:privilege (\d+))?\s*$")
ACCESS = re.compile(r"^(ssh|http|telnet) (\S+) (\S+) (\S+)\s*$")


def parse_interfaces(lines: list[str]) -> dict[str, int]:
    """nameif -> security-level."""
    levels: dict[str, int] = {}
    nameif = ""
    for line in lines:
        if line.startswith("interface "):
            nameif = ""
        elif line.startswith(" nameif "):
            nameif = line.split()[1]
            levels.setdefault(nameif, 100)
        elif line.startswith(" security-level ") and nameif:
            levels[nameif] = int(line.split()[1])
    return levels


def console_auth(lines: list[str]) -> dict[str, list[str]]:
    """'ssh' / 'http' -> server groups used for console login, e.g. ['ISE', 'LOCAL']."""
    auth: dict[str, list[str]] = {}
    for line in lines:
        words = line.split()
        if words[:2] == ["aaa", "authentication"] and len(words) >= 5 and words[3] == "console":
            auth[words[2]] = words[4:]
    return auth


def collect(path: Path, break_glass: set[str]) -> Device:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    hostname = next((ln.split()[1] for ln in lines if ln.startswith("hostname ")), path.stem)
    version = next((m.group(1) for ln in lines if (m := re.match(r"^ASA Version (\S+)", ln))), "")
    device = Device(
        vendor="Cisco",
        system=hostname,
        product="Adaptive Security Appliance (ASA)",
        version=version,
        file=path.name,
    )
    if not version:
        device.notes.append("'ASA Version' line not found: is this a running-config?")

    vpn_only: set[str] = set()
    current = ""
    for line in lines:
        if line.startswith("username ") and line.endswith(" attributes"):
            current = line.split()[1]
        elif line.startswith(" service-type remote-access") and current:
            vpn_only.add(current)
        elif not line.startswith(" "):
            current = ""

    auth = console_auth(lines)
    groups = sorted({g for methods in auth.values() for g in methods if g != "LOCAL"})
    if groups:
        local_class, local_enforced = "unknown", "unknown"
        local_note = (
            f"console login through {', '.join(groups)}; local account is the fallback; "
            "check MFA on that server"
        )
    else:
        local_class, local_enforced, local_note = "none", "N", "local password only"

    for line in lines:
        match = USER.match(line)
        if not match or match.group(1) in vpn_only:
            continue
        name, level = match.group(1), int(match.group(2) or 2)
        role = f"privilege {level}"
        device.admins.append(
            {
                "id": record_id(SOURCE, hostname, name, role),
                "source": SOURCE,
                "system": hostname,
                "account": name,
                "role": role,
                "account_type": "user",
                "privileged": "Y" if level == 15 else "N",
                "permanent": "Y",
                "mfa_class": local_class,
                "mfa_enforced": local_enforced,
                "break_glass": "Y" if name.lower() in break_glass else "N",
                "notes": local_note,
            }
        )
    for group in groups:
        account = f"{group} (remote admins)"
        device.admins.append(
            {
                "id": record_id(SOURCE, hostname, account, "remote"),
                "source": SOURCE,
                "system": hostname,
                "account": account,
                "role": "remote",
                "account_type": "user",
                "privileged": "Y",
                "permanent": "Y",
                "mfa_class": "unknown",
                "mfa_enforced": "unknown",
                "break_glass": "N",
                "notes": f"admins who log in through AAA server group {group}: "
                "list them and check MFA",
            }
        )

    levels = parse_interfaces(lines)
    http_server = any(ln.strip() == "http server enable" for ln in lines)
    allowed: dict[tuple[str, str], list[str]] = {}
    for line in lines:
        match = ACCESS.match(line)
        if not match:
            continue
        service, network, mask, nameif = match.groups()
        if service == "http" and not http_server:
            continue
        if nameif in levels and (levels[nameif] == 0 or UNTRUSTED.search(nameif)):
            anywhere = network == mask == "0.0.0.0"  # noqa: S104 (config text, not a bind)
            source = "anywhere" if anywhere else f"{network}/{mask}"
            allowed.setdefault((nameif, service), []).append(source)
    for (nameif, service), sources in sorted(allowed.items()):
        label = {"http": "https (ASDM)"}.get(service, service)
        device.exposure.append(
            {
                "id": make_id(SOURCE, hostname, nameif, service),
                "system": hostname,
                "interface": nameif,
                "zone_or_role": f"security-level {levels[nameif]}",
                "services": label,
                "reason": f"{label} management on {nameif} from {', '.join(sources)}",
            }
        )
    return device
