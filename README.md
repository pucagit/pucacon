# Pucacon

Python-orchestrated recon over the ProjectDiscovery tool pool + Shodan.
Takes a mixed target list (domains, `*.wildcards`, IPs, CIDRs) and produces
one folder per alive host with a `README.md` and per-finding `findings/*.md`.

## Setup
    ./setup/install-deps.sh          # massdns, jq, anew, resolvers, wordlist, nuclei templates
    # optional keys — see setup/KEYS.md (subfinder providers, PDCP_API_KEY, shodan init)

## Usage
    python3 -m pucacon targets.txt -o engagement-1            # full active recon
    python3 -m pucacon targets.txt --passive                 # no naabu/katana/nuclei
    python3 -m pucacon targets.txt --brute --permute         # deep subdomain enum

## Output
    engagement-1/                       # a scope workspace (reuse across runs)
      latest -> runs/<id>               # newest run
      state/assets.json                 # cross-run inventory (for future --since diff)
      runs/<id>/
        summary.md
        hosts/<host>/README.md          # one folder per FQDN and per bare IP
        hosts/<host>/findings/<slug>.md # nuclei / TLS / ports / shodan / risky-HTTP
        _raw/*.jsonl                     # raw tool artifacts

## Scope
Pucacon actively scans **every host it discovers** (passive enum can surface
third-party assets). There is no built-in scope guard — only run it against
targets you are authorized to test. Findings are still recorded for everything found.

## Pipeline
subfinder/chaos/shuffledns/alterx → dnsx → naabu → httpx → asnmap/cdncheck/shodan/uncover
→ tlsx → katana/urlfinder → nuclei → aggregate → report
