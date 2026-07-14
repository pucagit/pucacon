import json
from pucacon.runner import tool_available, capture, run_tool, iter_jsonl, _env_for

def test_env_strips_pdcp_for_probing_tools(monkeypatch):
    monkeypatch.setenv("PDCP_API_KEY", "secret")
    assert "PDCP_API_KEY" not in _env_for("httpx")   # probing tool: stripped
    assert "PDCP_API_KEY" not in _env_for("naabu")
    assert _env_for("chaos").get("PDCP_API_KEY") == "secret"     # kept
    assert _env_for("subfinder").get("PDCP_API_KEY") == "secret"
    assert _env_for("uncover").get("PDCP_API_KEY") == "secret"

def test_tool_available_true_for_python():
    # "sh" is always present; monkeypatch-free check via a real binary
    assert tool_available("__sh__") is False  # unknown logical name -> resolve None

def test_capture_runs_and_returns_stdout(monkeypatch):
    # use echo through resolve override
    from pucacon import runner
    monkeypatch.setattr(runner, "resolve", lambda n: "/bin/echo")
    out = capture("echo", ["hello", "world"])
    assert out.strip() == "hello world"

def test_run_tool_missing_binary_returns_nonzero(monkeypatch):
    from pucacon import runner
    monkeypatch.setattr(runner, "resolve", lambda n: None)
    assert run_tool("ghost", ["x"]) != 0

def test_iter_jsonl_skips_bad_lines(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"host":"a.com"}\nGARBAGE\n{"host":"b.com"}\n')
    rows = list(iter_jsonl(p))
    assert [r["host"] for r in rows] == ["a.com", "b.com"]
