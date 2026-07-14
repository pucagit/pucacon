"""Command-line entrypoint for pucacon."""
from __future__ import annotations
import argparse
import sys
from datetime import datetime
from pathlib import Path
from .config import Workspace, load_env
from .targets import parse_targets
from .scope_import import parse_hackerone_csv
from .pipeline import run_pipeline
from .report import write_report
from .runner import log

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pucacon", description="Ultimate PD-pool recon tool")
    p.add_argument("targets_file", nargs="?",
                   help="file with domains / *.wildcards / IPs / CIDRs")
    p.add_argument("--from-hackerone", metavar="CSV",
                   help="parse targets from a HackerOne scope CSV export instead")
    p.add_argument("-o", "--output", default="pucacon-out", help="output directory")
    p.add_argument("--passive", action="store_true", help="skip active stages (naabu, katana, nuclei)")
    p.add_argument("--brute", action="store_true", help="shuffledns bruteforce (needs massdns+wordlist)")
    p.add_argument("--permute", action="store_true", help="alterx permutations")
    p.add_argument("--no-shodan", action="store_true", help="disable shodan/uncover enrichment")
    p.add_argument("--depth", default="3", help="katana crawl depth")
    p.add_argument("--timeout", type=int, default=None, help="per-tool timeout seconds")
    p.add_argument("--env", default=None,
                   help="path to a .env of API keys (default: ./.env then setup/.env)")
    return p

def main(argv=None) -> int:
    ns = build_parser().parse_args(argv)
    keys = load_env(ns.env)
    if keys:
        log(f"[env] loaded {len(keys)} key(s): {', '.join(sorted(keys))}")
    if ns.from_hackerone:
        targets, skipped = parse_hackerone_csv(ns.from_hackerone)
        log(f"[scope] {len(targets)} target(s) from HackerOne export, {len(skipped)} skipped")
        lines = targets
    elif ns.targets_file:
        lines = Path(ns.targets_file).read_text().splitlines()
    else:
        log("[err] provide a targets file or --from-hackerone CSV"); return 2
    scope = parse_targets(lines)
    if not (scope.domains or scope.wildcards or scope.ips or scope.cidrs):
        log("[err] no valid targets found"); return 2
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    ws = Workspace(Path(ns.output), run_id=run_id).ensure()
    opts = {"passive": ns.passive, "brute": ns.brute, "permute": ns.permute,
            "shodan": not ns.no_shodan, "uncover": not ns.no_shodan,
            "depth": ns.depth, "timeout": ns.timeout}
    hosts = run_pipeline(scope, ws, opts)
    write_report(ws, hosts)
    log(f"[done] {len(hosts)} alive host(s) -> {ws.hosts}/  |  summary: {ws.run}/summary.md")
    return 0
