"""Fold _raw/*.jsonl artifacts into per-host Host objects with Findings."""
from __future__ import annotations
import json
from .runner import iter_jsonl
from .model import Host, Service, Finding

def _hostkey(row: dict) -> str | None:
    return (row.get("input") or row.get("host") or "").lower() or None

# notable non-HTTP ports -> (service label, severity). Exposure of these is a
# finding in its own right even when no nuclei template fired.
NOTABLE_PORTS = {
    21: ("FTP", "low"), 22: ("SSH", "info"), 23: ("Telnet", "high"),
    25: ("SMTP", "info"), 135: ("MSRPC", "medium"), 139: ("NetBIOS", "medium"),
    445: ("SMB", "high"), 1433: ("MSSQL", "high"), 1521: ("Oracle DB", "high"),
    2375: ("Docker API", "critical"), 3306: ("MySQL", "high"), 3389: ("RDP", "high"),
    5432: ("PostgreSQL", "high"), 5900: ("VNC", "high"), 6379: ("Redis", "high"),
    9200: ("Elasticsearch", "high"), 11211: ("Memcached", "high"),
    27017: ("MongoDB", "high"),
}
# HTTP ports that are "expected" web surface; anything not here + not in NOTABLE
# is reported generically.
_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

def build_hosts(ws) -> list[Host]:
    hosts: dict[str, Host] = {}

    def get(name: str, is_ip: bool = False) -> Host:
        h = hosts.get(name)
        if not h:
            h = Host(name=name, is_ip=is_ip)
            hosts[name] = h
        return h

    # 1) httpx = alive hosts (source of truth)
    for row in iter_jsonl(ws.artifact("http.jsonl")):
        key = _hostkey(row)
        if not key:
            continue
        h = get(key)
        for ip in (row.get("a") or []):
            if ip not in h.ips:
                h.ips.append(ip)
        for cn in (row.get("cname") or []):
            if cn not in h.cnames:
                h.cnames.append(cn)
        if row.get("cdn"):
            h.cdn = {"is_cdn": True, "provider": row.get("cdn_name", "")}
        try:
            port = int(row.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        h.services.append(Service(
            url=row.get("url", ""), port=port, scheme=row.get("scheme", ""),
            status_code=row.get("status_code"), title=row.get("title", ""),
            webserver=row.get("webserver", ""), tech=list(row.get("tech") or []),
        ))

    # 2) dnsx (ips/cnames for hosts even if httpx missed some fields)
    for row in iter_jsonl(ws.artifact("dns.jsonl")):
        name = (row.get("host") or "").lower()
        if name in hosts:
            h = hosts[name]
            for ip in (row.get("a") or []) + (row.get("aaaa") or []):
                if ip not in h.ips:
                    h.ips.append(ip)
            for cn in (row.get("cname") or []):
                if cn not in h.cnames:
                    h.cnames.append(cn)

    # index host-by-ip for port/cdn/asn back-mapping
    ip_index: dict[str, list[Host]] = {}
    for h in hosts.values():
        for ip in h.ips:
            ip_index.setdefault(ip, []).append(h)

    # 3) naabu ports
    for row in iter_jsonl(ws.artifact("ports.jsonl")):
        ip = row.get("ip"); port = row.get("port")
        name = (row.get("host") or "").lower()
        targets = hosts.get(name) and [hosts[name]] or ip_index.get(ip, [])
        for h in targets:
            if isinstance(port, int) and port not in h.open_ports:
                h.open_ports.append(port)
    for h in hosts.values():
        h.open_ports.sort()

    # 4) cdncheck / 5) asnmap (by ip)
    for row in iter_jsonl(ws.artifact("cdncheck.jsonl")):
        ip = row.get("input") or row.get("ip")
        for h in ip_index.get(ip, []):
            if row.get("cdn"):
                h.cdn = {"is_cdn": True, "provider": row.get("cdn_name", ""),
                         "type": row.get("itemtype") or row.get("cdn_type", "")}
    for row in iter_jsonl(ws.artifact("asnmap.jsonl")):
        ip = row.get("input") or row.get("ip")
        for h in ip_index.get(ip, []):
            h.asn = {"asn": row.get("as_number", ""), "org": row.get("as_name", ""),
                     "country": row.get("as_country", "")}

    # 6) tlsx -> tls dict + expired/self-signed finding
    for row in iter_jsonl(ws.artifact("tls.jsonl")):
        name = (row.get("host") or "").lower()
        if name not in hosts:
            continue
        h = hosts[name]
        h.tls = {"cn": row.get("subject_cn", ""), "sans": row.get("subject_an") or [],
                 "expired": bool(row.get("expired")), "self_signed": bool(row.get("self_signed")),
                 "not_after": row.get("not_after", "")}
        if row.get("expired"):
            h.findings.append(Finding(title="TLS certificate expired", severity="low",
                source="tlsx", target=f"{name}:{row.get('port','443')}",
                description=f"Certificate expired at {row.get('not_after','')}."))
        if row.get("self_signed"):
            h.findings.append(Finding(title="TLS certificate self-signed", severity="info",
                source="tlsx", target=f"{name}:{row.get('port','443')}",
                description="Certificate is self-signed."))

    # 7) katana endpoint counts
    counts: dict[str, int] = {}
    for row in iter_jsonl(ws.artifact("crawl.jsonl")):
        ep = ((row.get("request") or {}).get("endpoint")) or row.get("endpoint") or ""
        for name in hosts:
            if name in ep:
                counts[name] = counts.get(name, 0) + 1
                break
    for name, c in counts.items():
        hosts[name].endpoints = c

    # 8) nuclei findings
    for row in iter_jsonl(ws.artifact("nuclei.jsonl")):
        info = row.get("info") or {}
        target = row.get("matched-at") or row.get("host") or ""
        # attach to the host whose name appears in the matched target
        owner = next((hosts[n] for n in hosts if n in target), None)
        if not owner:
            continue
        owner.findings.append(Finding(
            title=info.get("name") or row.get("template-id", "nuclei finding"),
            severity=(info.get("severity") or "info").lower(),
            source="nuclei", target=target,
            description=info.get("description", ""),
            evidence="\n".join(row.get("extracted-results") or []),
            references=list(info.get("reference") or []),
        ))

    # 9) subdomain-takeover heuristic: alive host, CNAME set, but no resolved A record
    for h in hosts.values():
        if h.cnames and not h.ips:
            h.findings.append(Finding(
                title="Possible subdomain takeover (dangling CNAME)",
                severity="high", source="pucacon", target=h.name,
                description=f"{h.name} points to {', '.join(h.cnames)} but has no A record — verify the target is claimed.",
            ))

    # 10) bare-IP hosts: IPs with open ports but no hostname get their own folder
    for row in iter_jsonl(ws.artifact("ports.jsonl")):
        ip = row.get("ip"); port = row.get("port")
        if not ip or ip in ip_index:
            continue  # already covered by a named host
        h = get(ip, is_ip=True)
        if isinstance(port, int) and port not in h.open_ports:
            h.open_ports.append(port)
            h.open_ports.sort()
        if ip not in h.ips:
            h.ips.append(ip)

    # 11) exposed non-web ports -> findings (source: naabu)
    for h in hosts.values():
        web = {s.port for s in h.services}
        for p in h.open_ports:
            if p in web or p in _WEB_PORTS:
                continue
            label, sev = NOTABLE_PORTS.get(p, (None, None))
            if label:
                h.findings.append(Finding(
                    title=f"Exposed {label} service (port {p})", severity=sev,
                    source="naabu", target=f"{h.name}:{p}",
                    description=f"{label} is reachable on {h.name}:{p}. Confirm it should be internet-exposed."))

    # 12) Shodan-reported CVEs (per-IP JSON written by netintel to _raw/shodan/<ip>.json)
    sdir = ws.raw / "shodan"
    if sdir.is_dir():
        for jf in sorted(sdir.glob("*.json")):
            try:
                data = json.loads(jf.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            ip = jf.stem
            vulns = data.get("vulns") or {}
            # shodan emits vulns as a dict {cve: {cvss,summary}} or a bare list [cve,...]
            items = vulns.items() if isinstance(vulns, dict) else [(c, {}) for c in vulns]
            for h in ip_index.get(ip, []) or ([hosts[ip]] if ip in hosts else []):
                h.shodan = {"ports": data.get("ports", []), "org": data.get("org", "")}
                for cve, meta in items:
                    meta = meta if isinstance(meta, dict) else {}
                    sev = "critical" if float(meta.get("cvss") or 0) >= 9 else "high"
                    h.findings.append(Finding(
                        title=f"Shodan-reported {cve}", severity=sev, source="shodan",
                        target=ip, description=meta.get("summary", ""),
                        references=[f"https://nvd.nist.gov/vuln/detail/{cve}"]))

    # 13) risky HTTP: auth-gated panels (401/403) surfaced as findings (source: httpx)
    for row in iter_jsonl(ws.artifact("http.jsonl")):
        key = _hostkey(row)
        if key in hosts and row.get("status_code") in (401, 403):
            hosts[key].findings.append(Finding(
                title=f"Auth-gated endpoint ({row.get('status_code')})", severity="info",
                source="httpx", target=row.get("url", key),
                description=f"{row.get('url','')} returned {row.get('status_code')} — a protected panel worth investigating."))

    # 14) exposed sensitive files found while crawling (source: katana known-files)
    _SENSITIVE = (".git/", ".env", ".svn/", "/.DS_Store", "wp-config", "/backup")
    for row in iter_jsonl(ws.artifact("crawl.jsonl")):
        ep = ((row.get("request") or {}).get("endpoint")) or row.get("endpoint") or ""
        if not any(s in ep for s in _SENSITIVE):
            continue
        owner = next((hosts[n] for n in hosts if n in ep), None)
        if owner:
            owner.findings.append(Finding(
                title="Exposed sensitive path", severity="medium", source="katana",
                target=ep, description=f"Crawler reached a sensitive path: {ep}"))

    return list(hosts.values())
