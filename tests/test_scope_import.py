from pathlib import Path
from pucacon.scope_import import parse_hackerone_csv, to_target

FIX = Path(__file__).parent / "fixtures" / "h1_scope.csv"

def test_to_target_normalizes_url():
    assert to_target("https://api.codacy.com/v1/things?x=1", "URL") == "api.codacy.com"
    assert to_target("app.codacy.com:8443", "URL") == "app.codacy.com"
    assert to_target("*.codacy.com", "WILDCARD") == "*.codacy.com"
    assert to_target("10.0.0.0/24", "CIDR") == "10.0.0.0/24"
    assert to_target("codacy/repo", "GITHUB_REPOSITORY") is None

def test_parse_extracts_recon_targets_in_scope_only():
    targets, skipped = parse_hackerone_csv(FIX)
    assert set(targets) == {
        "app.codacy.com", "*.codacy.com", "api.codacy.com",
        "10.0.0.0/24", "8.8.8.8",
    }
    # github repo skipped (non-recon), out-of-scope url skipped (not eligible)
    skipped_ids = {ident for ident, _ in skipped}
    assert "codacy/codacy-cli" in skipped_ids
    assert "out-of-scope.codacy.com" in skipped_ids

def test_parse_all_includes_ineligible():
    targets, _ = parse_hackerone_csv(FIX, only_eligible=False)
    assert "out-of-scope.codacy.com" in targets
