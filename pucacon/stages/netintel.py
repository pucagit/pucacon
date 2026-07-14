"""IP intel: ASN (asnmap), CDN/WAF/cloud (cdncheck), Shodan + uncover (best-effort)."""
from __future__ import annotations
import json
from pathlib import Path
from .. import runner

def build_asnmap_cmd(ip: str) -> list[str]:
    return ["-i", ip, "-json", "-silent"]

def build_cdncheck_cmd(in_file: str, out: str) -> list[str]:
    # this cdncheck version uses -jsonl (not -json) for JSON output
    return ["-i", in_file, "-resp", "-jsonl", "-silent", "-o", out]

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

    # cdncheck (key-free)
    runner.run_tool("cdncheck", build_cdncheck_cmd(str(ip_file), str(ws.artifact("cdncheck.jsonl"))),
                    timeout=opts.get("timeout"))
    # asnmap per-ip -> concatenated jsonl
    asn_out = ws.artifact("asnmap.jsonl")
    with open(asn_out, "w") as fh:
        for ip in ips:
            fh.write(runner.capture("asnmap", build_asnmap_cmd(ip), timeout=opts.get("timeout")))
    # shodan host (best-effort; needs `shodan init`)
    if runner.tool_available("shodan") and opts.get("shodan", True):
        sdir = ws.raw / "shodan"; sdir.mkdir(exist_ok=True)
        for ip in ips:
            txt = runner.capture("shodan", ["host", "--format", "json", ip],
                                 timeout=opts.get("timeout"))
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
