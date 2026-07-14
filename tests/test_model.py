from pucacon.model import slugify_host, slugify_finding, Host, Finding, Service

def test_slugify_host():
    assert slugify_host("sub.example.com") == "sub.example.com"
    assert slugify_host("https://1.2.3.4:8443") == "https___1.2.3.4_8443"

def test_slugify_finding():
    assert slugify_finding("Exposed .git/ Directory!") == "exposed-git-directory"
    assert slugify_finding("  CVE-2021-1234  ") == "cve-2021-1234"
    long = "x" * 100
    assert len(slugify_finding(long)) <= 60

def test_host_defaults_and_finding():
    h = Host(name="a.com", is_ip=False)
    assert h.ips == [] and h.findings == []
    h.findings.append(Finding(title="t", severity="high", source="nuclei",
                              target="https://a.com", description="d"))
    assert h.findings[0].slug == "t"
    assert h.findings[0].severity == "high"

def test_service_dataclass():
    s = Service(url="https://a.com", port=443, scheme="https",
                status_code=200, title="Home", webserver="nginx", tech=["PHP"])
    assert s.port == 443 and "PHP" in s.tech
