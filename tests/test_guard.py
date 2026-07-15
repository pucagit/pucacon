from pucacon.config import Workspace
from pucacon.guard import assess_http, write_stop_report, render_stop_md

def _rows(codes):
    return [{"status_code": c, "url": f"https://h{i}"} for i, c in enumerate(codes)]

def test_healthy_run_no_stop():
    # 10 candidates, real responses -> no signal
    assert assess_http(10, _rows([200, 200, 404, 301, 403, 200, 200, 302])) is None

def test_waf_block_when_batch_probed_and_zero_alive():
    sig = assess_http(20, [])
    assert sig is not None and sig.reason == "waf_block"
    assert sig.evidence["candidates"] == 20

def test_no_false_positive_on_tiny_scope():
    # only 3 candidates, 0 alive -> too small to conclude a block
    assert assess_http(3, []) is None

def test_rate_limited_when_many_429_503():
    sig = assess_http(10, _rows([429, 429, 503, 200]))
    assert sig is not None and sig.reason == "rate_limited"
    assert sig.evidence["rate_limit_responses"] == 3

def test_few_429_not_flagged():
    # 1 rate-limit response among many is normal, not a stop
    assert assess_http(10, _rows([429, 200, 200, 200, 200, 200, 200, 200])) is None

def test_render_and_write_stop_report(tmp_path):
    ws = Workspace(tmp_path / "out", run_id="r1").ensure()
    sig = assess_http(20, [])
    md = render_stop_md(sig)
    assert "WAF" in md and sig.recommendation in md
    write_stop_report(ws, sig)
    assert (ws.run / "STOPPED.md").is_file()
    import json
    data = json.loads((ws.run / "stop_reason.json").read_text())
    assert data["reason"] == "waf_block"
