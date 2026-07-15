"""Probe every candidate host:port with httpx -> canonical alive-host list."""
from __future__ import annotations
from pathlib import Path
from .. import runner
from ..config import DEFAULTS

def build_httpx_cmd(in_file: str, out: str) -> list[str]:
    # WAF-safe defaults: 50 threads / no rate-limit trips Cloudflare bot
    # protection and every connection gets dropped (whole scope -> empty).
    # Lower concurrency + rate cap + retries + random UA survive the WAF.
    return [
        "-l", in_file, "-json", "-silent",
        "-status-code", "-title", "-tech-detect", "-web-server",
        "-ip", "-cname", "-cdn", "-follow-redirects",
        "-threads", "30", "-rate-limit", "150", "-retries", "1",
        "-timeout", "6", "-random-agent", "-o", out,
    ]

def _candidates(ws) -> list[str]:
    cand: set[str] = set()
    subs = ws.raw / "subs.txt"
    if subs.exists():
        cand |= {l.strip() for l in subs.read_text().splitlines() if l.strip()}
    # host:port pairs from naabu, if the port scan ran
    for row in runner.iter_jsonl(ws.artifact("ports.jsonl")):
        host = row.get("host") or row.get("ip")
        port = row.get("port")
        if host and port:
            cand.add(f"{host}:{port}")
    # bare input IPs
    scope_ips = ws.scope / "ips.txt"
    if scope_ips.exists():
        cand |= {l.strip() for l in scope_ips.read_text().splitlines() if l.strip()}
    return sorted(cand)

def run(ws, opts) -> Path:
    cand = _candidates(ws)
    out = ws.artifact("http.jsonl")
    if not cand:
        out.write_text(""); return out
    in_file = ws.scope / "http-candidates.txt"
    in_file.write_text("\n".join(cand) + "\n")
    runner.run_tool("httpx", build_httpx_cmd(str(in_file), str(out)),
                    timeout=opts.get("timeout"))
    return out
