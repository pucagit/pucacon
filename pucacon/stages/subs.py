"""Subdomain enumeration: subfinder (backbone) + chaos + shuffledns brute + alterx."""
from __future__ import annotations
from pathlib import Path
from .. import runner
from ..config import DEFAULTS

def build_subfinder_cmd(roots_file: str, out: str) -> list[str]:
    # -max-time caps total enumeration (minutes) so a hanging provider can't
    # keep the process alive indefinitely. Do NOT override the per-source
    # -timeout: a low value drops the slow-but-productive sources (cut a
    # 53-sub result down to 7). Default per-source timeout keeps coverage.
    return ["-dL", roots_file, "-all", "-silent", "-oJ",
            "-max-time", "5", "-o", out]

def build_shuffledns_cmd(domain: str, wordlist: str, resolvers: str, out: str) -> list[str]:
    return ["-d", domain, "-w", wordlist, "-r", resolvers,
            "-mode", "bruteforce", "-silent", "-o", out]

def build_alterx_cmd(in_file: str) -> list[str]:
    return ["-l", in_file, "-silent"]

def _hosts_from_subfinder(path: Path) -> set[str]:
    out = set()
    for row in runner.iter_jsonl(path):
        h = row.get("host")
        if h:
            out.add(h.lower())
    return out

def run(scope, ws, opts) -> Path:
    roots = sorted(scope.enum_roots())
    found: set[str] = set(roots)
    if not roots:
        (ws.raw / "subs.txt").write_text("")
        return ws.raw / "subs.txt"

    roots_file = ws.scope / "roots.txt"
    roots_file.write_text("\n".join(roots) + "\n")

    # 1) subfinder passive (always)
    sf_out = ws.artifact("subfinder.jsonl")
    runner.run_tool("subfinder", build_subfinder_cmd(str(roots_file), str(sf_out)),
                    timeout=opts.get("timeout"))
    found |= _hosts_from_subfinder(sf_out)

    # 2) chaos (best-effort, key-gated) — one call per root
    if runner.tool_available("chaos") and opts.get("chaos", True):
        for d in roots:
            txt = runner.capture("chaos", ["-d", d, "-silent"], timeout=opts.get("timeout"))
            found |= {l.strip().lower() for l in txt.splitlines() if l.strip()}

    # 3) shuffledns bruteforce (needs massdns + wordlist + resolvers)
    wl, rs = DEFAULTS["wordlist"], DEFAULTS["resolvers"]
    if (opts.get("brute") and runner.tool_available("shuffledns")
            and runner.tool_available("massdns")
            and Path(wl).exists() and Path(rs).exists()):
        for d in roots:
            b_out = ws.artifact(f"brute-{d}.txt")
            runner.run_tool("shuffledns",
                            build_shuffledns_cmd(d, wl, rs, str(b_out)),
                            timeout=opts.get("timeout"))
            if b_out.exists():
                found |= {l.strip().lower() for l in b_out.read_text().splitlines() if l.strip()}

    # 4) alterx permutations (optional, resolved later by dnsx)
    if opts.get("permute") and runner.tool_available("alterx"):
        base = ws.scope / "alterx-in.txt"
        base.write_text("\n".join(sorted(found)) + "\n")
        txt = runner.capture("alterx", build_alterx_cmd(str(base)), timeout=opts.get("timeout"))
        found |= {l.strip().lower() for l in txt.splitlines() if l.strip()}

    out = ws.raw / "subs.txt"
    out.write_text("\n".join(sorted(found)) + "\n")
    return out
