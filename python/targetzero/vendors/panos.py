# SPDX-License-Identifier: Apache-2.0
"""Palo Alto Networks PAN-OS collector, offline: parses running-config.xml.

Get the file from Device > Setup > Operations > Export named configuration
snapshot (running-config.xml).
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import ElementTree

from targetzero.admins import record_id
from targetzero.common.ids import make_id
from targetzero.vendors.common import Device

SOURCE = "panos"
PRIVILEGED = {"superuser", "deviceadmin", "vsysadmin"}
MANAGEMENT = ("https", "http", "ssh", "telnet", "snmp")
UNTRUST = re.compile(r"untrust|outside|internet|wan|external|public", re.IGNORECASE)


def text(element: Element | None, path: str, default: str = "") -> str:
    if element is None:
        return default
    found = element.find(path)
    return (found.text or "").strip() if found is not None and found.text else default


def role_of(user: Element) -> str:
    role_based = user.find("permissions/role-based")
    if role_based is None or len(role_based) == 0:
        return "?"
    first = role_based[0]
    if first.tag == "custom":
        return f"custom:{text(first, 'profile', '?')}"
    return first.tag


def auth_profiles(root: Element) -> dict[str, Element]:
    """Authentication profiles from every scope (shared, device, vsys)."""
    return {
        entry.get("name", ""): entry
        for container in root.iter("authentication-profile")
        for entry in container.findall("entry")
    }


def mfa(user: Element, profiles: dict[str, Element]) -> tuple[str, str, str]:
    if text(user, "client-certificate-only") == "yes":
        return "phishing-resistant", "Y", "client certificate only"
    profile_name = text(user, "authentication-profile")
    if not profile_name:
        return "none", "N", "local password only"
    profile = profiles.get(profile_name)
    if profile is None:
        return "unknown", "unknown", f"authentication profile {profile_name} not found in this file"
    if text(profile, "multi-factor-auth/mfa-enable") == "yes":
        return "mfa", "Y", f"profile {profile_name} with multi-factor authentication"
    method = profile.find("method")
    kind = method[0].tag if method is not None and len(method) else "?"
    if kind == "local-database":
        return "none", "N", f"profile {profile_name}: local database, no MFA"
    return "unknown", "unknown", f"profile {profile_name} uses {kind}: check MFA on that server"


def collect(path: Path, break_glass: set[str]) -> Device:
    root = ElementTree.parse(path).getroot()
    if root is None:
        raise ValueError(f"{path} is empty")
    hostname = text(root, "devices/entry/deviceconfig/system/hostname") or path.stem
    version = root.get("detail-version") or root.get("version") or ""
    device = Device(
        vendor="Palo Alto Networks",
        system=hostname,
        product="PAN-OS",
        version=version,
        file=path.name,
    )
    profiles = auth_profiles(root)

    users = root.findall("mgt-config/users/entry")
    if not users:
        device.notes.append("no mgt-config users: admins may be managed by Panorama")
    for user in users:
        name = user.get("name", "?")
        role = role_of(user)
        mfa_class, enforced, note = mfa(user, profiles)
        device.admins.append(
            {
                "id": record_id(SOURCE, hostname, name, role),
                "source": SOURCE,
                "system": hostname,
                "account": name,
                "role": role,
                "account_type": "user",
                "privileged": "Y" if role in PRIVILEGED else "N",
                "permanent": "Y",
                "mfa_class": mfa_class,
                "mfa_enforced": enforced,
                "break_glass": "Y" if name.lower() in break_glass else "N",
                "notes": note,
            }
        )

    mgmt_profiles = {
        entry.get("name", ""): [s for s in MANAGEMENT if text(entry, s) == "yes"]
        for container in root.iter("interface-management-profile")
        for entry in container.findall("entry")
    }
    zones: dict[str, str] = {}
    for zone_entry in root.findall("devices/entry/vsys/entry/zone/entry"):
        for member in zone_entry.findall("network/layer3/member"):
            zones[(member.text or "").strip()] = zone_entry.get("name", "")
    for interface in root.iter("entry"):
        profile = text(interface, "layer3/interface-management-profile") or text(
            interface, "interface-management-profile"
        )
        name = interface.get("name", "")
        services = mgmt_profiles.get(profile, [])
        if not services or not name:
            continue
        zone = zones.get(name, "")
        if UNTRUST.search(zone):
            device.exposure.append(
                {
                    "id": make_id(SOURCE, hostname, name),
                    "system": hostname,
                    "interface": name,
                    "zone_or_role": zone,
                    "services": ";".join(services),
                    "reason": f"management profile {profile} ({', '.join(services)}) on "
                    f"{name} in zone {zone}",
                }
            )
        elif not zone:
            device.notes.append(f"{name} has management profile {profile} but no zone: check it")
    return device
