"""Resolve the enumerated subdomains; emit live hosts + unique IP set."""
from __future__ import annotations
from pathlib import Path
from .. import runner

def build_dnsx_cmd(in_file: str, out: str) -> list[str]:
    # Use dnsx's built-in trusted resolvers (reliable) plus retries. Do NOT use
    # the big brute-force resolvers list here: it round-robins through ~12k
    # flaky public resolvers and intermittently drops valid records (a single
    # host can resolve to nothing on a bad pick). That list is for shuffledns
    # brute-force only (subs stage).
    return ["-l", in_file, "-a", "-aaaa", "-cname", "-resp",
            "-json", "-silent", "-retry", "2", "-o", out]

def run(ws, opts) -> Path:
    subs = ws.raw / "subs.txt"
    out = ws.artifact("dns.jsonl")
    if not subs.exists() or not subs.read_text().strip():
        out.write_text(""); (ws.raw / "resolved_ips.txt").write_text("")
        return out
    runner.run_tool("dnsx", build_dnsx_cmd(str(subs), str(out)),
                    timeout=opts.get("timeout"))
    ips: set[str] = set()
    for row in runner.iter_jsonl(out):
        for ip in (row.get("a") or []) + (row.get("aaaa") or []):
            ips.add(ip)
    (ws.raw / "resolved_ips.txt").write_text("\n".join(sorted(ips)) + "\n")
    return out
