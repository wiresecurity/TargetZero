# SPDX-License-Identifier: Apache-2.0
"""DNS lookups shared by the external checks: addresses plus the CNAME chain."""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.exception
import dns.rdatatype
import dns.resolver

NOT_FOUND = (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout)


@dataclass
class Lookup:
    name: str
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    nxdomain: bool = False


def resolver(timeout: float = 5) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    return r


def lookup(name: str, res: dns.resolver.Resolver) -> Lookup:
    result = Lookup(name.lower().rstrip("."))
    for rdtype in ("A", "AAAA"):
        try:
            answer = res.resolve(result.name, rdtype)
        except dns.resolver.NXDOMAIN:
            result.nxdomain = True
            break
        except NOT_FOUND:
            continue
        result.ips += [r.to_text() for r in answer]
        if answer.response is not None:
            for rrset in answer.response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    result.cnames += [r.target.to_text().rstrip(".").lower() for r in rrset]
    result.cnames = list(dict.fromkeys(result.cnames))
    return result


def cname_target(name: str, res: dns.resolver.Resolver) -> str:
    """The direct CNAME target of a name, or '' when it has none."""
    try:
        answer = res.resolve(name, "CNAME")
    except (dns.resolver.NXDOMAIN, *NOT_FOUND):
        return ""
    return str(answer[0].target.to_text()).rstrip(".").lower()
