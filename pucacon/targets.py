"""Classify a mixed target list into domains / wildcards / IPs / CIDRs."""
from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)
_MAX_CIDR_HOSTS = 65536  # safety cap on /16-ish expansion

def classify(line: str) -> str:
    s = line.strip()
    if not s:
        return "invalid"
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=False); return "cidr"
        except ValueError:
            return "invalid"
    try:
        ipaddress.ip_address(s); return "ip"
    except ValueError:
        pass
    if s.startswith("*."):
        return "wildcard" if _DOMAIN_RE.match(s[2:]) else "invalid"
    return "domain" if _DOMAIN_RE.match(s) else "invalid"

@dataclass
class Scope:
    domains: set[str] = field(default_factory=set)
    wildcards: set[str] = field(default_factory=set)   # bare root, no "*."
    ips: set[str] = field(default_factory=set)
    cidrs: set[str] = field(default_factory=set)

    def enum_roots(self) -> set[str]:
        return set(self.domains) | set(self.wildcards)

    def expand_cidrs(self) -> set[str]:
        out: set[str] = set()
        for c in self.cidrs:
            net = ipaddress.ip_network(c, strict=False)
            hosts = net.hosts() if net.num_addresses > 2 else net
            for i, ip in enumerate(hosts):
                if i >= _MAX_CIDR_HOSTS:
                    break
                out.add(str(ip))
        return out

def parse_targets(lines: Iterable[str]) -> Scope:
    scope = Scope()
    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        kind = classify(s)
        if kind == "domain":   scope.domains.add(s)
        elif kind == "wildcard": scope.wildcards.add(s[2:])
        elif kind == "ip":     scope.ips.add(s)
        elif kind == "cidr":   scope.cidrs.add(s)
        # invalid silently dropped
    return scope
