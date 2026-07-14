"""Domain model: Host / Service / Finding + filename slugifiers."""
from __future__ import annotations
import re
from dataclasses import dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

def slugify_host(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s.strip())

def slugify_finding(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s[:60].rstrip("-") or "finding"

@dataclass
class Service:
    url: str
    port: int
    scheme: str = ""
    status_code: int | None = None
    title: str = ""
    webserver: str = ""
    tech: list[str] = field(default_factory=list)

@dataclass
class Finding:
    title: str
    severity: str = "info"
    source: str = ""
    target: str = ""
    description: str = ""
    evidence: str = ""
    references: list[str] = field(default_factory=list)
    @property
    def slug(self) -> str:
        return slugify_finding(self.title)

@dataclass
class Host:
    name: str
    is_ip: bool = False
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    asn: dict = field(default_factory=dict)
    cdn: dict = field(default_factory=dict)
    open_ports: list[int] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    shodan: dict = field(default_factory=dict)
    endpoints: int = 0
    findings: list[Finding] = field(default_factory=list)
