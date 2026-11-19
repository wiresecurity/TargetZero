# SPDX-License-Identifier: Apache-2.0
"""The scan scope from targetzero.yaml. Nothing outside it is ever scanned."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from targetzero.common.config import Config

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class Scope:
    domains: tuple[str, ...]
    networks: tuple[IPNetwork, ...]

    @classmethod
    def from_config(cls, config: Config) -> Scope:
        scope = config.data.get("scope", {})
        return cls(
            domains=tuple(d.lower().strip(".") for d in scope.get("domains", [])),
            networks=tuple(
                ipaddress.ip_network(r, strict=False) for r in scope.get("ip_ranges", [])
            ),
        )

    def contains_ip(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in n for n in self.networks)

    def contains_name(self, name: str) -> bool:
        name = name.lower().strip(".")
        return any(name == d or name.endswith("." + d) for d in self.domains)

    def addresses(self, max_hosts: int) -> list[str]:
        total = sum(n.num_addresses for n in self.networks)
        if total > max_hosts:
            raise ValueError(
                f"Scope has {total} addresses, more than --max-hosts {max_hosts}. "
                "Split the ranges or raise the limit."
            )
        found: list[str] = []
        for network in self.networks:
            hosts = (
                [network.network_address] if network.num_addresses == 1 else list(network.hosts())
            )
            found += [str(h) for h in hosts]
        return found
