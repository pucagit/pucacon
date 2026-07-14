#!/usr/bin/env bash
# Installs the pieces the ProjectDiscovery pipeline needs that are not preinstalled.
# Safe to re-run (idempotent-ish). Requires sudo for apt.
set -euo pipefail

echo "[*] apt deps (massdns, jq, libpcap, build tools)"
sudo apt-get update -y
sudo apt-get install -y massdns jq libpcap-dev git build-essential

echo "[*] anew (dedupe helper) via go"
command -v anew >/dev/null 2>&1 || go install -v github.com/tomnomnom/anew@latest
# ensure ~/go/bin on PATH in your shell rc: export PATH="$PATH:$(go env GOPATH)/bin"

WORDLIST_DIR="$HOME/.config/pucacon"
mkdir -p "$WORDLIST_DIR"

echo "[*] DNS resolvers list"
if [ ! -s "$WORDLIST_DIR/resolvers.txt" ]; then
  curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    -o "$WORDLIST_DIR/resolvers.txt" || echo "[warn] resolvers download failed; add manually"
fi

echo "[*] subdomain wordlist (SecLists top-20000)"
if [ ! -s "$WORDLIST_DIR/subdomains.txt" ]; then
  curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt \
    -o "$WORDLIST_DIR/subdomains.txt" || echo "[warn] wordlist download failed; add manually"
fi

echo "[*] nuclei templates"
nuclei -update-templates -silent || echo "[warn] template update failed"

echo "[*] done. Verify:"
for b in massdns jq anew; do
  command -v "$b" >/dev/null 2>&1 && echo "  ok: $b" || echo "  MISSING: $b"
done
echo "  resolvers: $(wc -l < "$WORDLIST_DIR/resolvers.txt" 2>/dev/null || echo 0) lines"
echo "  wordlist:  $(wc -l < "$WORDLIST_DIR/subdomains.txt" 2>/dev/null || echo 0) lines"
