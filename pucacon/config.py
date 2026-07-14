"""Central config: tool binary map, workspace layout, tunable defaults."""
from __future__ import annotations
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

# repo root (…/pucacon), one level above this package dir — holds setup/.env
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

def load_env(path: str | Path | None = None) -> list[str]:
    """Load KEY=VALUE lines from a .env into os.environ (existing vars win).

    PD tools read keys from the environment (PDCP_API_KEY for chaos/nuclei,
    SHODAN_API_KEY / CENSYS_API_* / FOFA_* for uncover), and subprocesses
    inherit os.environ, so loading the .env here wires them all up. Returns
    the list of key names loaded (values never logged)."""
    candidates = [Path(path)] if path else [Path.cwd() / ".env",
                                             _PROJECT_ROOT / "setup" / ".env"]
    for c in candidates:
        if not (c and c.is_file()):
            continue
        loaded: list[str] = []
        for line in c.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:  # do not overwrite a real env var
                os.environ[key] = val
            loaded.append(key)
        return loaded
    return []

# logical stage name -> binary name resolved on PATH
TOOLS = {
    "subfinder": "subfinder", "chaos": "chaos", "shuffledns": "shuffledns",
    "alterx": "alterx", "dnsx": "dnsx", "asnmap": "asnmap", "cdncheck": "cdncheck",
    "mapcidr": "mapcidr", "naabu": "naabu", "httpx": "httpx", "tlsx": "tlsx",
    "katana": "katana", "urlfinder": "urlfinder", "nuclei": "nuclei",
    "uncover": "uncover", "massdns": "massdns", "shodan": "shodan",
}

_CFG = Path.home() / ".config" / "pucacon"

DEFAULTS = {
    "resolvers": str(_CFG / "resolvers.txt"),
    "wordlist": str(_CFG / "subdomains.txt"),
    "top_ports": "1000",
    "crawl_depth": "3",
    "severities": "low,medium,high,critical",
    "naabu_rate": "1000",
    "httpx_threads": "50",
    "nuclei_rate": "150",
}

_PDTM_BIN = Path.home() / ".pdtm" / "go" / "bin"

def resolve(name: str) -> str | None:
    """Absolute path to a tool binary, or None if not installed.

    Resolve pdtm-installed binaries FIRST: on Kali, `/usr/bin/httpx` is the
    unrelated Python httpx HTTP-client CLI that shadows ProjectDiscovery's
    httpx on PATH. Preferring ~/.pdtm/go/bin also picks the newer nuclei."""
    binary = TOOLS.get(name, name)
    pdtm = _PDTM_BIN / binary
    if pdtm.is_file():
        return str(pdtm)
    return shutil.which(binary)

@dataclass
class Workspace:
    """A scope workspace. Each run nests under runs/<run_id>/ so future
    diff/monitor mode can compare two runs' state/assets.json. `run_id`
    defaults to a fixed literal so tests are deterministic; the CLI passes
    a timestamp."""
    root: Path              # the -o dir = the scope workspace (persists across runs)
    run_id: str = "run"     # CLI overrides with a timestamp, e.g. 20260713-142530
    @property
    def run(self) -> Path: return self.root / "runs" / self.run_id
    @property
    def raw(self) -> Path: return self.run / "_raw"
    @property
    def scope(self) -> Path: return self.run / "_scope"
    @property
    def hosts(self) -> Path: return self.run / "hosts"
    @property
    def state(self) -> Path: return self.root / "state"   # cross-run inventory for diff
    def ensure(self) -> "Workspace":
        for p in (self.raw, self.scope, self.hosts, self.state):
            p.mkdir(parents=True, exist_ok=True)
        # maintain a `latest` pointer to the newest run (best-effort symlink)
        link = self.root / "latest"
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(self.run.relative_to(self.root))
        except OSError:
            pass  # filesystems without symlink support: skip silently
        return self
    def artifact(self, name: str) -> Path:
        return self.raw / name
