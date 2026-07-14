"""Attack-surface discovery: katana (active, JS-aware) + urlfinder (passive)."""
from __future__ import annotations
from pathlib import Path
from .. import runner

def build_katana_cmd(in_file: str, out: str, depth: str) -> list[str]:
    return ["-list", in_file, "-jsonl", "-silent", "-jc", "-kf", "all",
            "-d", depth, "-o", out]

def build_urlfinder_cmd(in_file: str, out: str) -> list[str]:
    # urlfinder takes domains via -list (string[]); -dL is not a valid flag.
    return ["-list", in_file, "-silent", "-o", out]

def _alive_urls(ws) -> list[str]:
    urls: set[str] = set()
    for row in runner.iter_jsonl(ws.artifact("http.jsonl")):
        if row.get("url"):
            urls.add(row["url"])
    return sorted(urls)

def run(ws, opts) -> Path:
    out = ws.artifact("crawl.jsonl")
    urls = _alive_urls(ws)
    if not urls:
        out.write_text(""); return out
    in_file = ws.scope / "crawl-urls.txt"
    in_file.write_text("\n".join(urls) + "\n")
    if not opts.get("passive"):
        runner.run_tool("katana",
                        build_katana_cmd(str(in_file), str(out), opts.get("depth", "3")),
                        timeout=opts.get("timeout"))
    # urlfinder passive (always safe) — feed it domains (subs), not full URLs
    subs = ws.raw / "subs.txt"
    uf_in = subs if subs.exists() and subs.read_text().strip() else in_file
    if runner.tool_available("urlfinder"):
        runner.run_tool("urlfinder",
                        build_urlfinder_cmd(str(uf_in), str(ws.raw / "urls.txt")),
                        timeout=opts.get("timeout"))
    return out
