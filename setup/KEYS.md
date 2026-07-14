# API Keys & Config used by Pucacon

All optional — the pipeline degrades gracefully without them.

| Capability | Where Pucacon reads it | How to set |
|---|---|---|
| subfinder passive sources | `~/.config/subfinder/provider-config.yaml` | add provider keys (virustotal, securitytrails, github, censys, shodan …) per subfinder docs |
| chaos dataset | env `PDCP_API_KEY` | get key at cloud.projectdiscovery.io, `export PDCP_API_KEY=...` |
| uncover engines | env `SHODAN_API_KEY`, `CENSYS_API_ID/SECRET`, `FOFA_KEY` | export the ones you have |
| shodan host lookups | `~/.config/shodan/` | run `shodan init <API_KEY>` once |
| nuclei cloud / PDCP upload | env `PDCP_API_KEY` | same key as chaos |
| notify (optional alerts) | `~/.config/notify/provider-config.yaml` | slack/discord/telegram webhook |

Wordlists Pucacon expects (created by `install-deps.sh`):
- `~/.config/pucacon/resolvers.txt`
- `~/.config/pucacon/subdomains.txt`
