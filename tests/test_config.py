from pathlib import Path
from pucacon.config import resolve, Workspace, TOOLS, DEFAULTS

def test_resolve_known_installed_tool():
    assert resolve("httpx") is not None  # httpx is installed on this box

def test_resolve_unknown_returns_none():
    assert resolve("definitely-not-a-tool-xyz") is None

def test_workspace_ensure_creates_dirs(tmp_path):
    ws = Workspace(tmp_path / "out", run_id="run1").ensure()
    assert ws.raw.is_dir() and ws.scope.is_dir() and ws.hosts.is_dir()
    assert ws.state.is_dir()
    assert ws.run == tmp_path / "out" / "runs" / "run1"
    assert ws.artifact("subs.jsonl") == ws.raw / "subs.jsonl"

def test_defaults_have_required_keys():
    for k in ("resolvers", "wordlist", "top_ports", "severities"):
        assert k in DEFAULTS
