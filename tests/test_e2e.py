from pathlib import Path
from pucacon.config import Workspace
from pucacon.model import Host, Finding
from pucacon.report import write_report

def test_full_report_tree_from_synthetic_hosts(tmp_path):
    ws = Workspace(tmp_path / "out").ensure()
    h = Host(name="scanme.example.com", ips=["1.1.1.1"], open_ports=[443])
    h.findings.append(Finding(title="Test Finding", severity="high",
                              source="nuclei", target="https://scanme.example.com"))
    write_report(ws, [h])
    assert (ws.hosts / "scanme.example.com" / "README.md").exists()
    assert (ws.hosts / "scanme.example.com" / "findings" / "test-finding.md").exists()
    assert "scanme.example.com" in (ws.run / "summary.md").read_text()
