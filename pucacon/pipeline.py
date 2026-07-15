"""Ordered execution of recon stages -> aggregated hosts."""
from __future__ import annotations
import json
from .stages import subs, dns, cdn, ports, http, netintel, tls, crawl, vulns
from .aggregate import build_hosts
from .runner import log, iter_jsonl
from . import guard

def _http_candidate_count(ws) -> int:
    f = ws.scope / "http-candidates.txt"
    if not f.exists():
        return 0
    return sum(1 for l in f.read_text().splitlines() if l.strip())

def _write_inventory(ws, hosts) -> None:
    """Cross-run inventory for a future --since diff. One-shot MVP only writes it."""
    inv = {
        "run_id": ws.run_id,
        "subdomains": sorted({l.strip() for l in
            (ws.raw / "subs.txt").read_text().splitlines() if l.strip()}
            if (ws.raw / "subs.txt").exists() else []),
        "hosts": sorted(h.name for h in hosts),
        "open_ports": {h.name: h.open_ports for h in hosts if h.open_ports},
        "finding_keys": sorted(f"{h.name}:{f.slug}" for h in hosts for f in h.findings),
    }
    (ws.state / "assets.json").write_text(json.dumps(inv, indent=2))

def run_pipeline(scope, ws, opts):
    """Run the recon stages. Returns (hosts, stop_signal). stop_signal is a
    guard.StopSignal if the run was aborted early (WAF/rate-limit), else None."""
    # persist input IPs (bare + expanded CIDR) for IP-centric stages
    ip_pool = set(scope.ips) | scope.expand_cidrs()
    (ws.scope / "ips.txt").write_text("\n".join(sorted(ip_pool)) + "\n")

    log("[*] stage: subdomain enumeration"); subs.run(scope, ws, opts)
    log("[*] stage: dns resolution");        dns.run(ws, opts)
    log("[*] stage: cdn detection");          cdn.run(ws, opts)
    log("[*] stage: port scan");             ports.run(ws, opts)
    log("[*] stage: http probe");            http.run(ws, opts)

    # WAF / rate-limit guard: abort before the aggressive crawl/nuclei stages
    # if httpx shows we are being blocked or throttled.
    stop = None
    if opts.get("guard", True):
        stop = guard.assess_http(_http_candidate_count(ws),
                                 list(iter_jsonl(ws.artifact("http.jsonl"))))
    if stop:
        log(f"[STOP] {stop.title}: {stop.detail}")
        hosts = build_hosts(ws)          # keep whatever was gathered pre-stop
        _write_inventory(ws, hosts)
        return hosts, stop

    log("[*] stage: network intel");         netintel.run(ws, opts)
    log("[*] stage: tls");                   tls.run(ws, opts)
    log("[*] stage: crawl");                 crawl.run(ws, opts)
    log("[*] stage: vulnerability scan");    vulns.run(ws, opts)
    log("[*] aggregating results")
    hosts = build_hosts(ws)
    _write_inventory(ws, hosts)
    return hosts, None
