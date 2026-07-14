"""Resolve the enumerated subdomains; emit live hosts + unique IP set."""
from __future__ import annotations
from pathlib import Path
from .. import runner
from ..config import DEFAULTS

def build_dnsx_cmd(in_file: str, out: str, resolvers: str) -> list[str]:
    cmd = ["-l", in_file, "-a", "-aaaa", "-cname", "-resp",
           "-json", "-silent", "-o", out]
    if resolvers and Path(resolvers).exists():
        cmd += ["-r", resolvers]
    return cmd

def run(ws, opts) -> Path:
    subs = ws.raw / "subs.txt"
    out = ws.artifact("dns.jsonl")
    if not subs.exists() or not subs.read_text().strip():
        out.write_text(""); (ws.raw / "resolved_ips.txt").write_text("")
        return out
    runner.run_tool("dnsx", build_dnsx_cmd(str(subs), str(out), DEFAULTS["resolvers"]),
                    timeout=opts.get("timeout"))
    ips: set[str] = set()
    for row in runner.iter_jsonl(out):
        for ip in (row.get("a") or []) + (row.get("aaaa") or []):
            ips.add(ip)
    (ws.raw / "resolved_ips.txt").write_text("\n".join(sorted(ips)) + "\n")
    return out
