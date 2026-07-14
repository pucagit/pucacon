"""Thin, defensive wrappers around subprocess for the PD tools."""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterator, Sequence
from .config import resolve

def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)

def tool_available(name: str) -> bool:
    return resolve(name) is not None

def run_tool(name: str, args: Sequence[str], stdin: str | None = None,
             out_file: Path | None = None, timeout: int | None = None) -> int:
    binary = resolve(name)
    if not binary:
        log(f"[warn] skipping {name}: binary not found on PATH")
        return 127
    cmd = [binary, *args]
    log(f"[run] {' '.join(cmd)}")
    try:
        with (open(out_file, "w") if out_file else _null()) as fh:
            proc = subprocess.run(
                cmd, input=stdin, text=True,
                stdout=(fh if out_file else None),
                timeout=timeout, check=False,
            )
        return proc.returncode
    except subprocess.TimeoutExpired:
        log(f"[warn] {name} timed out after {timeout}s")
        return 124
    except Exception as e:  # noqa: BLE001 - never let a tool crash the pipeline
        log(f"[warn] {name} failed: {e}")
        return 1

def capture(name: str, args: Sequence[str], stdin: str | None = None,
            timeout: int | None = None) -> str:
    binary = resolve(name)
    if not binary:
        log(f"[warn] skipping {name}: binary not found on PATH")
        return ""
    cmd = [binary, *args]
    log(f"[run] {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, input=stdin, text=True,
                              capture_output=True, timeout=timeout, check=False)
        return proc.stdout
    except Exception as e:  # noqa: BLE001
        log(f"[warn] {name} failed: {e}")
        return ""

def iter_jsonl(path: Path) -> Iterator[dict]:
    if not Path(path).exists():
        return
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

class _null:
    def __enter__(self): return None
    def __exit__(self, *a): return False
