from pathlib import Path
from pucacon.config import Workspace
from pucacon.model import Host, Service, Finding
from pucacon.report import render_readme, render_finding, write_report

def _host():
    h = Host(name="api.example.com", ips=["93.184.216.34"], open_ports=[80, 443],
             cdn={"is_cdn": True, "provider": "cloudflare"},
             asn={"asn": "AS15133", "org": "EdgeCast", "country": "US"})
    h.services.append(Service(url="https://api.example.com", port=443, scheme="https",
                              status_code=200, title="API", webserver="nginx", tech=["PHP"]))
    h.findings.append(Finding(title="Exposed .git Config", severity="medium",
                              source="nuclei", target="https://api.example.com/.git/config",
                              description="Git metadata exposed.", references=["https://x"]))
    return h

def test_render_readme_has_key_sections():
    md = render_readme(_host())
    assert "# api.example.com" in md
    assert "93.184.216.34" in md
    assert "cloudflare" in md
    assert "443" in md and "nginx" in md
    assert "Exposed .git Config" in md  # findings index

def test_render_finding_has_severity_and_target():
    md = render_finding(_host().findings[0])
    assert "medium" in md.lower()
    assert ".git/config" in md

def test_write_report_creates_tree(tmp_path):
    ws = Workspace(tmp_path / "out").ensure()
    write_report(ws, [_host()])
    hdir = ws.hosts / "api.example.com"
    assert (hdir / "README.md").is_file()
    finding_files = list((hdir / "findings").glob("*.md"))
    assert len(finding_files) == 1
    assert (ws.run / "summary.md").is_file()
