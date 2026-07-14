"""Vulnerability scanning with nuclei (interactsh OOB, severity-filtered)."""
from __future__ import annotations
from pathlib import Path
from .. import runner
from ..config import DEFAULTS

def build_nuclei_cmd(in_file: str, out: str, severities: str, rate: str) -> list[str]:
    return ["-l", in_file, "-jsonl", "-o", out, "-severity", severities,
            "-rate-limit", rate, "-stats", "-silent", "-etags", "fuzz,dos"]

def run(ws, opts) -> Path:
    out = ws.artifact("nuclei.jsonl")
    if opts.get("passive"):
        out.write_text(""); return out
    urls = sorted({r["url"] for r in runner.iter_jsonl(ws.artifact("http.jsonl")) if r.get("url")})
    if not urls:
        out.write_text(""); return out
    in_file = ws.scope / "nuclei-targets.txt"
    in_file.write_text("\n".join(urls) + "\n")
    runner.run_tool("nuclei",
                    build_nuclei_cmd(str(in_file), str(out),
                                     DEFAULTS["severities"], DEFAULTS["nuclei_rate"]),
                    timeout=opts.get("timeout"))
    return out
