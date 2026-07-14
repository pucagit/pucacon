from pucacon.targets import classify, parse_targets

def test_classify():
    assert classify("example.com") == "domain"
    assert classify("*.example.com") == "wildcard"
    assert classify("1.2.3.4") == "ip"
    assert classify("10.0.0.0/24") == "cidr"
    assert classify("2001:db8::/48") == "cidr"
    assert classify("not a domain!!") == "invalid"
    assert classify("") == "invalid"

def test_parse_targets_buckets_and_comments():
    scope = parse_targets([
        "example.com", "*.acme.com", "8.8.8.8",
        "192.168.0.0/30", "# a comment", "  ", "bad_entry!",
    ])
    assert scope.domains == {"example.com"}
    assert scope.wildcards == {"acme.com"}
    assert scope.ips == {"8.8.8.8"}
    assert scope.cidrs == {"192.168.0.0/30"}

def test_enum_roots_merges_domains_and_wildcards():
    scope = parse_targets(["example.com", "*.acme.com"])
    assert scope.enum_roots() == {"example.com", "acme.com"}

def test_expand_cidrs_capped():
    scope = parse_targets(["192.168.0.0/30"])
    ips = scope.expand_cidrs()
    assert "192.168.0.1" in ips and len(ips) <= 4
