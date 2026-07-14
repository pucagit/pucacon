"""Import recon targets from a HackerOne structured-scope CSV export.

HackerOne's "Export scopes" produces a CSV with columns:
  identifier, asset_type, instruction, eligible_for_bounty,
  eligible_for_submission, ...requirements..., created_at, updated_at

Only network-recon asset types (URL / WILDCARD / DOMAIN / CIDR / IP_ADDRESS)
become pucacon targets; source-code, mobile-app, and other asset types are
reported as skipped. Run:
    python3 -m pucacon.scope_import scopes.csv -o targets.txt
"""
from __future__ import annotations
import argparse
import csv
import re
import sys
from pathlib import Path
from .targets import classify

# asset types that map to a network recon target
_HOSTY = {"URL", "WILDCARD", "DOMAIN"}
_NETY = {"CIDR", "IP_ADDRESS"}
_PORT_RE = re.compile(r":\d+$")

def to_target(identifier: str, asset_type: str) -> str | None:
    """Reduce a H1 (identifier, asset_type) to a pucacon target token
    (host / *.wildcard / ip / cidr), or None if it is not a recon target."""
    s = (identifier or "").strip()
    if not s:
        return None
    at = (asset_type or "").upper()
    if at in _NETY:
        return s                       # CIDR / IP used verbatim (keep the /mask)
    if at in _HOSTY:
        if "://" in s:                 # strip scheme
            s = s.split("://", 1)[1]
        if "@" in s:                   # strip userinfo
            s = s.split("@", 1)[1]
        s = s.split("/", 1)[0]         # strip path/query
        s = _PORT_RE.sub("", s)        # strip :port
        return s or None
    return None                        # GITHUB_REPOSITORY, SOURCE_CODE, apps, OTHER, …

def parse_hackerone_csv(path, only_eligible: bool = True):
    """Return (targets, skipped). `targets` is a sorted, de-duped list of valid
    pucacon target tokens. `skipped` is a list of (identifier, asset_type) that
    were dropped (non-recon type, invalid, or — by default — not eligible)."""
    targets: set[str] = set()
    skipped: list[tuple[str, str]] = []
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            ident = row.get("identifier", "")
            at = row.get("asset_type", "")
            if only_eligible and (row.get("eligible_for_submission", "").strip().lower() != "true"):
                skipped.append((ident, at)); continue
            tok = to_target(ident, at)
            if not tok or classify(tok) == "invalid":
                skipped.append((ident, at)); continue
            targets.add(tok)
    return sorted(targets), skipped

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pucacon.scope_import",
        description="Turn a HackerOne scope CSV export into a pucacon targets file")
    ap.add_argument("csv", help="path to the HackerOne scopes_*.csv export")
    ap.add_argument("-o", "--output", help="write targets to file (default: stdout)")
    ap.add_argument("--all", action="store_true",
                    help="include assets not marked eligible_for_submission")
    ns = ap.parse_args(argv)

    targets, skipped = parse_hackerone_csv(ns.csv, only_eligible=not ns.all)
    text = "\n".join(targets) + ("\n" if targets else "")
    if ns.output:
        Path(ns.output).write_text(text)
    else:
        sys.stdout.write(text)
    print(f"[scope] {len(targets)} target(s), {len(skipped)} skipped", file=sys.stderr)
    for ident, at in skipped:
        print(f"[scope] skipped {at or '?'}: {ident}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
