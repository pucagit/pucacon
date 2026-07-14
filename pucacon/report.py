"""Render Host objects into the per-host folder tree + summary index."""
from __future__ import annotations
from pathlib import Path
from .model import Host, Finding, slugify_host, SEVERITY_ORDER

def _sorted_findings(h: Host) -> list[Finding]:
    return sorted(h.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

def render_finding(f: Finding) -> str:
    lines = [f"# {f.title}", "",
             f"- **Severity:** {f.severity}",
             f"- **Source:** {f.source}",
             f"- **Target:** `{f.target}`", ""]
    if f.description:
        lines += ["## Description", "", f.description, ""]
    if f.evidence:
        lines += ["## Evidence", "", "```", f.evidence, "```", ""]
    if f.references:
        lines += ["## References", ""] + [f"- {r}" for r in f.references] + [""]
    return "\n".join(lines)

def render_readme(h: Host) -> str:
    L = [f"# {h.name}", ""]
    L += ["## Overview", "",
          f"- **Type:** {'IP' if h.is_ip else 'hostname'}",
          f"- **Resolved IPs:** {', '.join(h.ips) or '—'}",
          f"- **CNAMEs:** {', '.join(h.cnames) or '—'}"]
    if h.asn:
        L.append(f"- **ASN:** {h.asn.get('asn','')} {h.asn.get('org','')} ({h.asn.get('country','')})")
    if h.cdn:
        L.append(f"- **CDN/WAF:** {h.cdn.get('provider','') or 'yes'} ({h.cdn.get('type','')})")
    L.append(f"- **Open ports:** {', '.join(map(str, h.open_ports)) or '—'}")
    L.append(f"- **Crawled endpoints:** {h.endpoints}")
    L.append("")
    if h.services:
        L += ["## HTTP Services", "", "| URL | Status | Title | Server | Tech |", "|---|---|---|---|---|"]
        for s in h.services:
            L.append(f"| {s.url} | {s.status_code or ''} | {s.title} | {s.webserver} | {', '.join(s.tech)} |")
        L.append("")
    if h.tls:
        L += ["## TLS", "",
              f"- CN: {h.tls.get('cn','')}",
              f"- SANs: {', '.join(h.tls.get('sans', []))}",
              f"- Expired: {h.tls.get('expired')} · Self-signed: {h.tls.get('self_signed')}", ""]
    if h.shodan:
        L += ["## Shodan", "", "```json", str(h.shodan)[:1500], "```", ""]
    fs = _sorted_findings(h)
    L += [f"## Findings ({len(fs)})", ""]
    if fs:
        for f in fs:
            L.append(f"- **[{f.severity}]** [{f.title}](findings/{f.slug}.md)")
    else:
        L.append("_No findings._")
    L.append("")
    return "\n".join(L)

def render_summary(hosts: list[Host]) -> str:
    L = ["# Recon Summary", "",
         f"Alive hosts: **{len(hosts)}**", "",
         "| Host | IPs | Ports | Services | Findings |", "|---|---|---|---|---|"]
    for h in sorted(hosts, key=lambda x: x.name):
        crit = sum(1 for f in h.findings if f.severity in ("critical", "high"))
        flag = f" ⚠️{crit}" if crit else ""
        L.append(f"| [{h.name}](hosts/{slugify_host(h.name)}/README.md) "
                 f"| {len(h.ips)} | {len(h.open_ports)} | {len(h.services)} | {len(h.findings)}{flag} |")
    return "\n".join(L) + "\n"

def write_report(ws, hosts: list[Host]) -> None:
    for h in hosts:
        hdir = ws.hosts / slugify_host(h.name)
        (hdir / "findings").mkdir(parents=True, exist_ok=True)
        (hdir / "README.md").write_text(render_readme(h))
        seen: dict[str, int] = {}
        for f in _sorted_findings(h):
            slug = f.slug
            if slug in seen:
                seen[slug] += 1
                slug = f"{slug}-{seen[slug]}"
            else:
                seen[slug] = 0
            (hdir / "findings" / f"{slug}.md").write_text(render_finding(f))
    (ws.run / "summary.md").write_text(render_summary(hosts))
