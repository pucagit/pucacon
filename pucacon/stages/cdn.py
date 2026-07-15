"""Early CDN/WAF/cloud detection (cdncheck) so we don't port-scan shared edges."""
from __future__ import annotations
from .. import runner

def build_cdncheck_cmd(in_file: str, out: str) -> list[str]:
    # this cdncheck version uses -jsonl (not -json) for JSON output
    return ["-i", in_file, "-resp", "-jsonl", "-silent", "-o", out]

def is_edge(row: dict) -> bool:
    """cdncheck classifies an IP as cdn / waf / cloud. Any of them is shared
    edge infrastructure we should not port-scan or turn into a bare-IP host."""
    return bool(row.get("cdn") or row.get("waf") or row.get("cloud"))

def _target_ips(ws) -> list[str]:
    ips: set[str] = set()
    p = ws.raw / "resolved_ips.txt"
    if p.exists():
        ips |= {l.strip() for l in p.read_text().splitlines() if l.strip()}
    sp = ws.scope / "ips.txt"
    if sp.exists():
        ips |= {l.strip() for l in sp.read_text().splitlines() if l.strip()}
    return sorted(ips)

def run(ws, opts) -> set[str]:
    out = ws.artifact("cdncheck.jsonl")
    ips = _target_ips(ws)
    cdn: set[str] = set()
    if not ips:
        out.write_text(""); (ws.raw / "cdn_ips.txt").write_text(""); return cdn
    in_file = ws.scope / "cdn-in.txt"
    in_file.write_text("\n".join(ips) + "\n")
    runner.run_tool("cdncheck", build_cdncheck_cmd(str(in_file), str(out)),
                    timeout=opts.get("timeout"))
    for row in runner.iter_jsonl(out):
        if is_edge(row):
            ip = row.get("input") or row.get("ip")
            if ip:
                cdn.add(ip)
    (ws.raw / "cdn_ips.txt").write_text("\n".join(sorted(cdn)) + "\n")
    return cdn
