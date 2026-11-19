# SPDX-License-Identifier: Apache-2.0
"""Ports checked by the exposure scan, grouped by why they matter."""

from __future__ import annotations

PORTS: dict[int, tuple[str, str]] = {
    # port: (category, service)
    21: ("file", "ftp"),
    22: ("management", "ssh"),
    23: ("management", "telnet"),
    25: ("mail", "smtp"),
    53: ("other", "dns"),
    80: ("web", "http"),
    110: ("mail", "pop3"),
    111: ("other", "rpcbind"),
    135: ("management", "msrpc"),
    139: ("file", "netbios"),
    143: ("mail", "imap"),
    161: ("management", "snmp"),
    389: ("directory", "ldap"),
    443: ("web", "https"),
    445: ("file", "smb"),
    465: ("mail", "smtps"),
    514: ("management", "syslog/rsh"),
    587: ("mail", "submission"),
    623: ("management", "ipmi"),
    636: ("directory", "ldaps"),
    873: ("file", "rsync"),
    993: ("mail", "imaps"),
    995: ("mail", "pop3s"),
    1194: ("vpn", "openvpn"),
    1433: ("database", "mssql"),
    1521: ("database", "oracle"),
    1723: ("vpn", "pptp"),
    2049: ("file", "nfs"),
    2375: ("management", "docker"),
    2376: ("management", "docker-tls"),
    3268: ("directory", "ldap-gc"),
    3306: ("database", "mysql"),
    3389: ("management", "rdp"),
    4443: ("management", "admin-https"),
    5432: ("database", "postgresql"),
    5900: ("management", "vnc"),
    5985: ("management", "winrm"),
    5986: ("management", "winrm-https"),
    6379: ("database", "redis"),
    6443: ("management", "kubernetes-api"),
    8000: ("web", "http-alt"),
    8006: ("management", "proxmox"),
    8080: ("web", "http-alt"),
    8443: ("management", "admin-https"),
    9000: ("management", "admin-web"),
    9200: ("database", "elasticsearch"),
    9443: ("management", "admin-https"),
    10000: ("management", "webmin/backup"),
    10443: ("vpn", "ssl-vpn/admin"),
    11211: ("database", "memcached"),
    27017: ("database", "mongodb"),
}


def describe(port: int) -> tuple[str, str]:
    return PORTS.get(port, ("other", ""))
