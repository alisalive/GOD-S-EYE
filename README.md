# GOD'S EYE v1.0.0

An AI-powered penetration testing and red team automation tool built in Python.
Combines GOD'S EYE deep scanning, Claude AI analysis, and modular attack phases
into a single CLI workflow.

> **For authorized security testing only.**

---

## Features

- **GOD'S EYE Integration** — 35+ technology fingerprints, WAF detection, vulnerability checks, CVE correlation
- **AI Analysis** — Claude (claude-sonnet-4-6) generates executive summaries and attack narratives
- **Subdomain Enumeration** — async DNS brute-force with 500+ wordlist
- **Web Analysis** — security headers, endpoint enumeration, SQLi probes, WAF bypass payloads
- **Default Credentials Checker** — FTP, SSH, HTTP, Telnet (MITRE T1078)
- **Directory Brute-Force** — async 20-concurrent, auto-slow on 429, 200+ path wordlist
- **JWT Analyzer** — alg:none detection, weak HS256 secrets, RS256→HS256 confusion, expiry checks
- **AD Analysis** — LDAP anonymous bind, SMB null session, MS17-010, Kerberos pre-auth, BloodHound
- **CVE Correlation** — NVD API v2.0 + GOD'S EYE CVE lookup, 7-day local cache
- **Shodan Enrichment** — port/banner/org/vuln data merged into recon results
- **Metasploit Bridge** — findings automatically mapped to MSF module paths
- **Screenshots** — Playwright headless Chromium, base64-embedded in HTML report
- **OPSEC Scoring** — 0–100 score with deductions/bonuses for red team mode
- **HTML Report** — dark mode, CVE table, OPSEC timeline, kill chain, print CSS
- **PDF Export** — WeasyPrint or print-optimized HTML fallback

---

## Installation

### Windows

```bat
git clone https://github.com/alisalive/gods-eye
cd gods-eye
setup.bat
```

Or manually:

```bat
pip install -r requirements.txt
playwright install chromium
```

### Kali Linux / Debian

Tested on Kali Linux (root and non-root).

```bash
git clone https://github.com/alisalive/gods-eye
cd gods-eye
chmod +x setup.sh && ./setup.sh
```

### Install as global command (`godseye`)

```bash
pip install -e .
godseye --target 10.0.0.1 --mode pentest
```

---

## Usage

```
godseye --target TARGET [OPTIONS]
```

### All flags

| Flag | Description |
|------|-------------|
| `--target`, `-t` | Target IP or hostname (required) |
| `--mode`, `-m` | `pentest` (default) or `redteam` |
| `--ai` | Enable Claude AI analysis (off by default; requires `--api-key`) |
| `--api-key`, `-k` | Anthropic API key (or `ANTHROPIC_API_KEY` env var) |
| `--output`, `-o` | Output directory (default: `./reports`) |
| `--output-dir` | Alias for `--output` |
| `--stealth` | Enable stealth mode (delays, UA rotation) |
| `--interactive` | Pause between phases |
| `--subdomains` | Enable subdomain enumeration |
| `--screenshot` | Enable Playwright screenshots |
| `--dirbrute` | Enable directory brute-force |
| `--shodan-key` | Shodan API key (or `SHODAN_API_KEY` env) |
| `--pdf` | Export report as PDF |
| `--config` | Path to YAML config file |
| `--no-report` | Skip report generation |

### Examples

```bash
# Basic pentest — no AI (default)
godseye --target 127.0.0.1 --mode pentest

# With Claude AI analysis enabled
godseye --target 10.0.0.1 --mode pentest --ai --api-key sk-ant-...

# Full red team engagement without AI
godseye --target 10.0.0.1 --mode redteam --stealth --subdomains --screenshot --dirbrute

# Full red team engagement with AI
godseye --target 10.0.0.1 --mode redteam --stealth --subdomains --screenshot --dirbrute \
               --ai --api-key sk-ant-...

# With Shodan and PDF export
godseye --target 192.168.1.1 --mode pentest --shodan-key YOUR_KEY --pdf

# With AI key from environment variable
export ANTHROPIC_API_KEY=sk-ant-...
godseye --target example.com --mode pentest --ai --output ./my-reports

# Interactive with all modules
godseye --target 10.0.0.1 --mode redteam --stealth --subdomains --screenshot \
               --dirbrute --pdf --interactive --ai --api-key sk-ant-...
```

---

## Phase Order

| Phase | Name | Flag |
|-------|------|------|
| 0 | Config load | always |
| 1 | Recon (GOD'S EYE) | always |
| 1b | Shodan enrichment | `--shodan-key` |
| 2 | Subdomain enum | `--subdomains` |
| 2.5 | Default credentials | always (if ports open) |
| 3 | Web analysis + WAF bypass + JWT | always |
| 3b | Directory brute-force | `--dirbrute` |
| 4 | AD analysis | always |
| 5 | CVE correlation + MSF bridge | always |
| 6 | Screenshots | `--screenshot` |
| 7 | AI analysis (Claude) | `--ai` (off by default) |
| 8 | Report (HTML + JSON + PDF) | unless `--no-report` |

---

## Configuration

Edit `config/config.yaml`:

```yaml
scan:
  timeout: 2.0
  max_parallel_ports: 50

ai:
  model: "claude-sonnet-4-6"
  max_tokens: 2000
  enabled: true

stealth:
  min_delay: 1.0
  max_delay: 3.0
  rotate_ua: true

paths:
  gods_eye: "C:\\Users\\User\\Documents\\GODs_EYE"
  wordlists: "./config/wordlists"
  reports: "./reports"
```

---

## GOD'S EYE

Set the path via `config/config.yaml` or environment variable:

```bash
set GODS_EYE_PATH=C:\Users\User\Documents\GODs_EYE
```

---

## License

MIT License

---

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md)

---

## Author

**alisalive** — GOD'S EYE v1.0.0
