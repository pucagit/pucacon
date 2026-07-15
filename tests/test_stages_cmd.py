from pucacon.stages import subs, dns, cdn, http, ports, netintel, tls, crawl, vulns

# --- subs ---
def test_subfinder_cmd_uses_all_sources_and_jsonl():
    cmd = subs.build_subfinder_cmd("roots.txt", "out.jsonl")
    assert "-dL" in cmd and "roots.txt" in cmd
    assert "-all" in cmd and "-silent" in cmd
    assert "-oJ" in cmd

def test_shuffledns_cmd_bruteforce_mode():
    cmd = subs.build_shuffledns_cmd("example.com", "w.txt", "r.txt", "b.txt")
    assert "-d" in cmd and "example.com" in cmd
    assert "-w" in cmd and "-r" in cmd
    assert "bruteforce" in cmd  # -mode bruteforce

# --- dns ---
def test_dnsx_cmd_resolves_records_json():
    cmd = dns.build_dnsx_cmd("subs.txt", "dns.jsonl", "r.txt")
    assert "-l" in cmd and "subs.txt" in cmd
    assert "-a" in cmd and "-aaaa" in cmd and "-cname" in cmd
    assert "-resp" in cmd and "-json" in cmd
    # r.txt only appended if it exists; here it does not, so just check flags above

# --- http ---
def test_httpx_cmd_has_full_fingerprint_flags():
    cmd = http.build_httpx_cmd("in.txt", "http.jsonl")
    for flag in ("-l", "-json", "-silent", "-status-code", "-title",
                 "-tech-detect", "-web-server", "-ip", "-cname",
                 "-cdn", "-follow-redirects", "-o",
                 "-rate-limit", "-retries", "-random-agent"):  # WAF-safe
        assert flag in cmd, flag

# --- ports ---
def test_naabu_cmd_excludes_cdn_and_json():
    cmd = ports.build_naabu_cmd("ips.txt", "ports.jsonl", "1000", "1000")
    assert "-list" in cmd and "ips.txt" in cmd
    assert "-exclude-cdn" in cmd
    assert "-top-ports" in cmd and "1000" in cmd
    assert "-json" in cmd and "-o" in cmd

# --- netintel ---
def test_asnmap_cmd_json():
    cmd = netintel.build_asnmap_cmd("1.2.3.4")
    assert "-i" in cmd and "1.2.3.4" in cmd and "-json" in cmd and "-silent" in cmd

def test_cdncheck_cmd_json_resp():
    cmd = cdn.build_cdncheck_cmd("ips.txt", "cdn.jsonl")
    assert "-i" in cmd and "ips.txt" in cmd and "-resp" in cmd and "-jsonl" in cmd

def test_cdn_is_edge_matches_cdn_waf_cloud():
    assert cdn.is_edge({"cdn": True})
    assert cdn.is_edge({"waf": True})
    assert cdn.is_edge({"cloud": True})
    assert not cdn.is_edge({"cdn": False})
    assert not cdn.is_edge({})

# --- tls ---
def test_tlsx_cmd_grabs_san_and_flags():
    cmd = tls.build_tlsx_cmd("hosts.txt", "tls.jsonl")
    assert "-l" in cmd and "-json" in cmd and "-silent" in cmd
    assert "-expired" in cmd and "-self-signed" in cmd
    # -san/-cn conflict with the misconfig probes; default JSON still has them
    assert "-san" not in cmd and "-cn" not in cmd

# --- crawl ---
def test_katana_cmd_js_aware_depth_json():
    cmd = crawl.build_katana_cmd("urls.txt", "crawl.jsonl", "3")
    assert "-list" in cmd and "-jsonl" in cmd and "-silent" in cmd
    assert "-jc" in cmd            # crawl JS
    assert "-d" in cmd and "3" in cmd
    assert "-kf" in cmd            # known-files (robots, sitemap)

# --- vulns ---
def test_nuclei_cmd_jsonl_severity_stats():
    cmd = vulns.build_nuclei_cmd("urls.txt", "nuclei.jsonl", "low,medium,high,critical", "150")
    assert "-l" in cmd and "urls.txt" in cmd
    assert "-jsonl" in cmd
    assert "-severity" in cmd and "low,medium,high,critical" in cmd
    assert "-rate-limit" in cmd and "150" in cmd
