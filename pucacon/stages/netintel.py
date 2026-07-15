"""IP intel: ASN (asnmap), Shodan + uncover (best-effort).

CDN/WAF/cloud detection lives in the earlier `cdn` stage (it must run before
naabu so we can skip shared edges); this stage reuses its cdncheck.jsonl."""
from __future__ import annotations
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from .. import runner

def build_asnmap_cmd(ip: str) -> list[str]:
    return ["-i", ip, "-json", "-silent"]

def shodan_host(ip: str, key: str, timeout: int | None = None) -> str:
    """Fetch Shodan host JSON via the REST API. The `shodan host` CLI cannot
    emit JSON (only pretty/tsv), so we call the API directly. Returns "" on
    any error (404 = no data, 401 = bad key, network issues)."""
    url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
    try:
        with urllib.request.urlopen(url, timeout=timeout or 30) as r:
            return r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return ""

def _all_ips(ws) -> list[str]:
    ips: set[str] = set()
    for name in ("resolved_ips.txt",):
        p = ws.raw / name
        if p.exists():
            ips |= {l.strip() for l in p.read_text().splitlines() if l.strip()}
    sp = ws.scope / "ips.txt"
    if sp.exists():
        ips |= {l.strip() for l in sp.read_text().splitlines() if l.strip()}
    return sorted(ips)

def run(ws, opts) -> dict:
    ips = _all_ips(ws)
    if not ips:
        return {}
    ip_file = ws.scope / "intel-ips.txt"
    ip_file.write_text("\n".join(ips) + "\n")

    # asnmap per-ip -> concatenated jsonl
    asn_out = ws.artifact("asnmap.jsonl")
    with open(asn_out, "w") as fh:
        for ip in ips:
            fh.write(runner.capture("asnmap", build_asnmap_cmd(ip), timeout=opts.get("timeout")))
    # shodan host enrichment via REST API (JSON); needs SHODAN_API_KEY in env
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if key and opts.get("shodan", True):
        sdir = ws.raw / "shodan"; sdir.mkdir(exist_ok=True)
        for ip in ips:
            if ":" in ip:
                continue  # Shodan host endpoint is IPv4-only
            txt = shodan_host(ip, key, opts.get("timeout"))
            if txt.strip().startswith("{"):
                (sdir / f"{ip}.json").write_text(txt)
    # uncover (best-effort; needs engine keys) — query by resolved IPs
    if runner.tool_available("uncover") and opts.get("uncover", True):
        q = "\n".join(f"ip:{ip}" for ip in ips[:50])
        txt = runner.capture("uncover", ["-e", "shodan,censys,fofa", "-json", "-silent"],
                             stdin=q, timeout=opts.get("timeout"))
        if txt.strip():
            ws.artifact("uncover.jsonl").write_text(txt)
    return {"ips": ips}
