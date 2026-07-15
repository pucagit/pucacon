"""Detect WAF blocking / rate limiting mid-run so the pipeline can stop early
and report *why* — letting the operator cool down and rerun, or route through
different proxies, instead of hammering a WAF and wasting the run.

The httpx stage is the detection point: it is the first place a block shows
unambiguously (connections dropped -> nothing answers, or a flood of 429/503),
and it runs before the aggressive crawl/nuclei stages we want to avoid firing
into a WAF.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field

# explicit "you are being throttled / shed" responses
RATE_LIMIT_CODES = {429, 503}
# minimum batch size before "0 responded" is meaningful (avoid tiny-scope noise)
MIN_BATCH = 8
# minimum count + share of rate-limit responses before we call it throttling
MIN_RATE_HITS = 3
RATE_SHARE = 0.30

@dataclass
class StopSignal:
    reason: str            # machine code: "waf_block" | "rate_limited"
    title: str             # human-readable headline
    detail: str            # what was observed
    recommendation: str    # what the operator should do
    evidence: dict = field(default_factory=dict)

def assess_http(num_candidates: int, rows: list[dict]) -> "StopSignal | None":
    """Given how many candidates were probed and the httpx result rows, decide
    whether we appear to be blocked/throttled. Returns a StopSignal or None."""
    alive = len(rows)
    rate_hits = sum(1 for r in rows if r.get("status_code") in RATE_LIMIT_CODES)

    # 1) explicit rate limiting: a real share of responses are 429/503
    if rate_hits >= MIN_RATE_HITS and rate_hits / max(alive, 1) >= RATE_SHARE:
        return StopSignal(
            reason="rate_limited",
            title="Rate limiting detected",
            detail=(f"{rate_hits} of {alive} HTTP responses were 429/503 "
                    "(Too Many Requests / Service Unavailable)."),
            recommendation=("Wait for the limit to reset and rerun the same command, "
                            "or route httpx/nuclei through rotating proxies."),
            evidence={"candidates": num_candidates, "alive": alive,
                      "rate_limit_responses": rate_hits})

    # 2) WAF block: a meaningful batch was probed and NOTHING answered — the
    #    signature of a WAF (e.g. Cloudflare) dropping the scan's connections.
    if num_candidates >= MIN_BATCH and alive == 0:
        return StopSignal(
            reason="waf_block",
            title="Probable WAF block / dropped connections",
            detail=(f"Probed {num_candidates} candidates but 0 responded — "
                    "consistent with a WAF dropping the scan traffic (a live "
                    "host normally answers, even with 403/404)."),
            recommendation=("Lower concurrency, wait and rerun from a cooled-down "
                            "IP, or route through different proxies."),
            evidence={"candidates": num_candidates, "alive": 0})

    return None

def render_stop_md(signal: StopSignal) -> str:
    L = [f"# ⛔ Run stopped early: {signal.title}", "",
         f"- **Reason code:** `{signal.reason}`",
         f"- **What happened:** {signal.detail}", "",
         "## Evidence", ""]
    for k, v in signal.evidence.items():
        L.append(f"- **{k}:** {v}")
    L += ["", "## Recommended action", "", signal.recommendation, "",
          "The recon artifacts collected before the stop are still in this run "
          "folder. Re-run the same command once the condition clears (optionally "
          "with proxies) to complete the scan.", ""]
    return "\n".join(L)

def write_stop_report(ws, signal: StopSignal) -> None:
    (ws.run / "STOPPED.md").write_text(render_stop_md(signal))
    (ws.run / "stop_reason.json").write_text(json.dumps({
        "reason": signal.reason, "title": signal.title, "detail": signal.detail,
        "recommendation": signal.recommendation, "evidence": signal.evidence,
    }, indent=2))
