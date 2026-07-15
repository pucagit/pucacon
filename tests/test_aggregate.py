import shutil
from pathlib import Path
from pucacon.config import Workspace
from pucacon.aggregate import build_hosts

def _ws_with_fixtures(tmp_path):
    ws = Workspace(tmp_path / "out").ensure()
    fx = Path(__file__).parent / "fixtures"
    for f in ("http.jsonl", "dns.jsonl", "nuclei.jsonl", "tls.jsonl", "ports.jsonl",
              "crawl.jsonl", "cdncheck.jsonl"):
        shutil.copy(fx / f, ws.raw / f)
    shutil.copytree(fx / "shodan", ws.raw / "shodan")
    return ws

def _by_name(hosts):
    return {h.name: h for h in hosts}

def test_build_hosts_api_host(tmp_path):
    hosts = _by_name(build_hosts(_ws_with_fixtures(tmp_path)))
    h = hosts["api.example.com"]
    assert "93.184.216.34" in h.ips
    assert h.cdn.get("is_cdn") is True
    assert {80, 443, 3306} <= set(h.open_ports)

def test_bare_ip_host_created(tmp_path):
    hosts = _by_name(build_hosts(_ws_with_fixtures(tmp_path)))
    assert "198.51.100.7" in hosts            # ip-only host from naabu
    assert hosts["198.51.100.7"].is_ip is True

def test_cdn_edge_ip_not_made_into_bare_host(tmp_path):
    hosts = _by_name(build_hosts(_ws_with_fixtures(tmp_path)))
    assert "203.0.113.9" not in hosts         # WAF edge IP skipped
    assert "198.51.100.7" in hosts            # non-edge bare IP still created

def test_nuclei_findings_folded_in(tmp_path):
    h = _by_name(build_hosts(_ws_with_fixtures(tmp_path)))["api.example.com"]
    git = next(f for f in h.findings if f.title == "Exposed .git Config")
    assert git.severity == "medium" and git.source == "nuclei"

def test_expired_tls_becomes_finding(tmp_path):
    h = _by_name(build_hosts(_ws_with_fixtures(tmp_path)))["api.example.com"]
    assert any("expired" in f.title.lower() for f in h.findings)

def test_nonweb_port_finding(tmp_path):
    h = _by_name(build_hosts(_ws_with_fixtures(tmp_path)))["api.example.com"]
    assert any("MySQL" in f.title and f.source == "naabu" for f in h.findings)

def test_shodan_cve_finding(tmp_path):
    h = _by_name(build_hosts(_ws_with_fixtures(tmp_path)))["api.example.com"]
    cve = next(f for f in h.findings if "CVE-2021-44228" in f.title)
    assert cve.severity == "critical" and cve.source == "shodan"

def test_risky_http_and_sensitive_path_findings(tmp_path):
    hosts = _by_name(build_hosts(_ws_with_fixtures(tmp_path)))
    assert any("403" in f.title for f in hosts["admin.example.com"].findings)
    assert any("sensitive path" in f.title.lower() for f in hosts["api.example.com"].findings)
