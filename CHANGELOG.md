# Changelog

All notable changes to GOD'S EYE are documented here.

---

## [1.0.0] — 2026-04-24

### Added
- GOD'S EYE scanner integration (35+ tech fingerprints, WAF detection, vuln checks, CVE)
- `modules/subdomain.py` — async DNS brute-force, 500+ wordlist, 50 concurrent
- `modules/screenshot.py` — Playwright headless Chromium screenshots, base64 HTML embed
- `modules/waf_bypass.py` — WAF-specific payloads for XSS/SQLi/LFI/XXE/SSRF/RCE
- `modules/opsec.py` — OPSEC scoring 0–100 with NINJA/GHOST/NOISY/LOUD/BUSTED ratings
- `modules/cve.py` — NVD API v2.0 + GOD'S EYE CVE lookup, 7-day JSON cache
- `modules/default_creds.py` — FTP/SSH/HTTP/Telnet default credential testing (T1078)
- `modules/msf_bridge.py` — automatic finding → Metasploit module mapping
- `modules/shodan_recon.py` — Shodan host enrichment via direct REST API
- `modules/dirbrute.py` — async directory brute-force, 20 concurrent, WAF rate-limit handling
- `modules/jwt_analyzer.py` — JWT alg:none, weak HS256, RS256→HS256 confusion, expiry (T1550.001)
- `output/pdf_export.py` — PDF via WeasyPrint or print-CSS fallback
- `utils/logger.py` — credential-masking file logger
- `modules/gods_eye_bridge.py` — GOD'S EYE integration bridge
- New AD checks: LDAP anonymous bind, SMB null session, MS17-010, Kerberos pre-auth, BloodHound
- HTML report: dark mode, CVE table, OPSEC timeline, kill chain diagram, print CSS
- CLI flags: `--stealth`, `--interactive`, `--subdomains`, `--screenshot`, `--dirbrute`,
  `--shodan-key`, `--pdf`, `--config`, `--output-dir`, `--no-report`, `--api-key`
- `config/config.yaml` configuration file
- Wordlists: 500+ subdomains, 200+ endpoints, top-100 passwords
- `setup.bat` (Windows) and `setup.sh` (Kali/Linux) setup scripts
- `setup.py` + `pyproject.toml` for `pip install -e .` and `godseye` global command
- `.github/workflows/ci.yml` — Python 3.11/3.12/3.13 CI matrix
- Banner subtitle changed to "by alisalive" with `[bold green]` color
- Version v1.0.0 added to banner

### Changed
- CVE lookup now skips technologies with no detected version (prevents false positives)
- OPSEC bonus cap raised to 120 before clamping to allow pre-deduction buffers
- Report generator: XSS-safe HTML escaping for all user-controlled content

---

*For authorized security testing only.*
