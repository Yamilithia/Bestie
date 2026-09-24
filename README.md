# Bestie

> **Bestie: tells your story to the AI, keeps your secrets with her.**

Bestie sits between you and Claude. Before a prompt leaves your machine it swaps
every sensitive value (hostnames, IPs, usernames, internal domains, customer names,
secrets, IOCs) for a consistent typed placeholder. When the answer comes back it
swaps the real values back in.

```
you type      jdoe (ACME\jdoe) on dc01.corp.acme.com connected to 10.20.4.17 and evil-cdn.xyz
Claude sees   USER_001 (ORG_001\USER_001) on HOST_001.DOMAIN_001 connected to IP_001 and DOMAIN_002
Claude says   Isolate HOST_001 and reset USER_001's credentials.
you read      Isolate dc01 and reset jdoe's credentials.
```

The model still gets full reasoning context: the same value is always the same
token, and the token type tells it what kind of thing it is. Structure is kept too:
`HOST_001.DOMAIN_001` is a host inside a domain, and `DOMAIN_003.sharepoint.com` is a
SharePoint tenant. The real values never leave your machine.

## How it works

```
Claude Code / SDK / scripts          Claude desktop / claude.ai
        │ ANTHROPIC_BASE_URL                │ copy · paste
        ▼                                   ▼
  bestie serve (127.0.0.1:8787)       bestie clip redact | restore
        │
        ├─ detect: dictionary · patterns · vault-known values · allowlist
        ├─ replace with tokens from the local vault   (real ⇄ token)
        ├─ leak guard: block if any known/detectable value survived
        ├─ forward to api.anthropic.com
        └─ restore tokens in the answer (streaming-aware, tool calls included)
```

* **Fail closed.** If a redaction error or a leak is found, or content can't be
  inspected (images, PDFs), the request is blocked. Nothing is sent.
* **Redact by default.** Private and public IPs, unknown domains, users, hashes and
  secrets are all masked. Only allowlisted public context such as `8.8.8.8` or
  `microsoft.com` stays readable.
* **Local only.** The proxy listens on `127.0.0.1`, and your real API key lives only
  in the proxy. Vaults and dictionaries are `0600` files under `~/.bestie`.

### What gets detected

| Layer | Examples |
|---|---|
| Your dictionary | org and customer names, internal domains, AD domain, codenames, known hosts and users, hostname regexes |
| Patterns | IPv4/IPv6/CIDR, FQDNs (validated TLDs, not `setup.py` or `System.Net`), emails, `DOMAIN\user`, `user=`/`hostname:`/`Account Name:` fields, Sysmon `<Data Name=…>`, UNC paths, profile paths (`C:\Users\jdoe`), `svc_*` accounts, MACs, SIDs, hashes, secrets (passwords, bearer/JWT, AWS/GitHub/Slack/Anthropic keys, private keys) |
| Vault | anything masked before is masked everywhere after, even as a bare word |
| Allowlist (kept) | public resolvers, documentation ranges, well-known vendor domains, Windows built-in accounts, plus your own `allow:` entries |

**Limits:** free-text names that aren't in your dictionary ("ask Maria from the
SOC") can't be caught by rules. Always run `bestie preview` on your own data first,
and grow your dictionary.

## Install

```bash
git clone … && cd Bestie
uv venv && uv pip install -e ".[dev]"       # or: pipx install .
```

### Windows (PowerShell)

```powershell
winget install --id=astral-sh.uv -e          # or: pip install uv  (needs Python 3.10+)
git clone https://github.com/Yamilithia/Bestie; cd Bestie
uv venv; uv pip install -e .
.\.venv\Scripts\Activate.ps1                  # makes `bestie` available in this shell
```

If activation is blocked, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once. Otherwise, call
`.\.venv\Scripts\bestie.exe` directly. Bestie's files live in
`$env:USERPROFILE\.bestie`.

PowerShell equivalents of the commands below:

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."; bestie serve                     # terminal 1
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8787"; $env:ANTHROPIC_API_KEY = "bestie"; claude   # terminal 2
Get-Content alert.log | bestie redact | Set-Clipboard                    # pipe mode
Get-Clipboard | bestie restore
```

## Setup (once)

```bash
bestie init                     # asks for org names, internal domains, AD domain, customers…
bestie preview real_alert.log   # see exactly what would leave; nothing is saved
bestie dict add host fs01       # add anything that slipped through, preview again
```

See [`bestie.example.yaml`](bestie.example.yaml) for the dictionary format. You can
layer a shared team file with `dictionaries:` in `~/.bestie/config.yaml`, and add
per-incident terms with `bestie dict add … --vault IR-2026-042`.

## Daily use

### Claude Code, SDK and scripts: the proxy

You need an **Anthropic API key**. Only Bestie holds it:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
bestie serve                              # add --vault IR-2026-042 for a per-incident vault
```

Then point your tool at Bestie, with a dummy key:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 ANTHROPIC_API_KEY=bestie claude
```

```python
client = anthropic.Anthropic(base_url="http://127.0.0.1:8787", api_key="bestie")
```

This works for any tool that lets you set a custom Anthropic base URL. File
contents and command output that an agent sends back are redacted too. Tool calls
the model makes (`ping HOST_001`) are restored before your tool runs them.

A request can pick a vault with the header `X-Bestie-Vault: <name>`.

### Claude desktop and claude.ai: clipboard mode

These apps use your subscription login and can't be pointed at a proxy, so use the
clipboard instead:

```bash
bestie clip redact     # copy your log → run → paste into Claude (now masked)
bestie clip restore    # copy Claude's answer → run → paste/read with real values
```

It uses the same vault, so tokens mean the same thing everywhere. On Linux this
needs `xclip`, `xsel` or `wl-clipboard`. With pipes it works too:
`bestie redact alert.log | pbcopy`, then `pbpaste | bestie restore`.

## Commands

| Command | What it does |
|---|---|
| `bestie init` | first-run dictionary wizard |
| `bestie dict add <kind> <values…> [--vault]` | kinds: `org customer domain ad-domain host user term hostname-pattern allow` |
| `bestie dict show` | merged dictionary |
| `bestie preview [file]` | highlighted view of what the AI would see; saves nothing |
| `bestie redact [file]` / `bestie restore [file]` | stdin/stdout filters |
| `bestie clip redact` / `bestie clip restore [--print]` | clipboard in place |
| `bestie serve [--vault] [--port] [--dump-upstream]` | local Anthropic-compatible proxy |
| `bestie vault ls` / `show [name]` / `clear <name>` | manage mappings (per incident) |
| `bestie audit` | recent requests: what types were masked, what was blocked (never values) |

## Files (`~/.bestie`, override with `BESTIE_HOME`)

```
config.yaml                    settings: port, upstream_url, default_vault, dictionaries, redact_hashes, allow_binary
dictionary.yaml                your dictionary
vaults/<name>.json             real ⇄ token mappings
vaults/<name>.dictionary.yaml  per-vault dictionary
audit.log                      JSONL, types and counts only
```

The dictionary and vaults contain your real secrets, so keep them out of git and
backups you don't control.

## Development

```bash
uv run pytest        # detectors, round-trip, streaming splits, leak guard, proxy (mock upstream), CLI
uv run ruff check src tests
```

## Roadmap

- **Phase 3:** encrypted vault (key in the OS keyring), `dict import` from AD/CMDB CSV
  exports, learn-from-preview, `--confirm` approval mode.
- **Phase 4:** optional NER (spaCy/Presidio) for free-text names, subnet-relationship
  hints, and an optional local-model second opinion.
- **Phase 5:** global hotkey for clipboard mode, a claude.ai browser extension, a
  `bestie chat` TUI, and packaging.
