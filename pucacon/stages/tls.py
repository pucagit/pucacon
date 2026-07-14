"""TLS/cert inspection with tlsx; harvest SAN hostnames for feedback."""
from __future__ import annotations
from pathlib import Path
from .. import runner

def build_tlsx_cmd(in_file: str, out: str) -> list[str]:
    # tlsx forbids the -san/-cn extraction probes together with the -expired/
    # -self-signed misconfig probes; the default JSON already carries
    # subject_cn / subject_an, so we keep the misconfig probes only.
    return ["-l", in_file, "-json", "-silent",
            "-expired", "-self-signed", "-o", out]

def _https_targets(ws) -> list[str]:
    tgt: set[str] = set()
    for row in runner.iter_jsonl(ws.artifact("http.jsonl")):
        if (row.get("scheme") == "https") and row.get("host"):
            port = row.get("port") or "443"
            tgt.add(f"{row['host']}:{port}")
    return sorted(tgt)

def run(ws, opts) -> Path:
    out = ws.artifact("tls.jsonl")
    tgt = _https_targets(ws)
    if not tgt:
        out.write_text(""); return out
    in_file = ws.scope / "tls-targets.txt"
    in_file.write_text("\n".join(tgt) + "\n")
    runner.run_tool("tlsx", build_tlsx_cmd(str(in_file), str(out)), timeout=opts.get("timeout"))
    sans: set[str] = set()
    for row in runner.iter_jsonl(out):
        for name in (row.get("subject_an") or []):
            if name and not name.startswith("*"):
                sans.add(name.lower())
    (ws.raw / "tls_sans.txt").write_text("\n".join(sorted(sans)) + "\n")
    return out
