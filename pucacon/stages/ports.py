"""Port discovery with naabu (SYN, CDN-aware)."""
from __future__ import annotations
from pathlib import Path
from .. import runner
from ..config import DEFAULTS

def build_naabu_cmd(in_file: str, out: str, top_ports: str, rate: str) -> list[str]:
    return ["-list", in_file, "-exclude-cdn", "-top-ports", top_ports,
            "-rate", rate, "-json", "-silent", "-o", out]

def run(ws, opts) -> Path:
    out = ws.artifact("ports.jsonl")
    if opts.get("passive"):
        out.write_text(""); return out
    targets: set[str] = set()
    rip = ws.raw / "resolved_ips.txt"
    if rip.exists():
        targets |= {l.strip() for l in rip.read_text().splitlines() if l.strip()}
    scope_ips = ws.scope / "ips.txt"
    if scope_ips.exists():
        targets |= {l.strip() for l in scope_ips.read_text().splitlines() if l.strip()}
    # drop CDN/WAF/cloud edge IPs (detected by the cdn stage) — scanning shared
    # provider infrastructure is pointless and out of the target's control.
    cdn_f = ws.raw / "cdn_ips.txt"
    if cdn_f.exists():
        cdn = {l.strip() for l in cdn_f.read_text().splitlines() if l.strip()}
        targets -= cdn
    if not targets:
        out.write_text(""); return out
    in_file = ws.scope / "scan-ips.txt"
    in_file.write_text("\n".join(sorted(targets)) + "\n")
    runner.run_tool("naabu",
                    build_naabu_cmd(str(in_file), str(out),
                                    DEFAULTS["top_ports"], DEFAULTS["naabu_rate"]),
                    timeout=opts.get("timeout"))
    return out
