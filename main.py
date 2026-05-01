#!/usr/bin/env python3
# Force UTF-8 output before any other imports (Windows cp1252 compatibility)
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
"""
GOD'S EYE v2.0.0 — Main CLI
For authorized security testing only.

Usage:
  python main.py --target 10.0.0.1 --mode pentest
  python main.py --target example.com --mode redteam --stealth --subdomains --screenshot
  python main.py --target 192.168.1.1 --mode pentest --ai --api-key sk-ant-... --output ./reports
"""

import asyncio
import os
import time
import random
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

from core.orchestrator import EngagementState, Mode, Phase, Severity
from modules.recon import run_recon
from modules.web import run_web_analysis
from modules.ai_engine import get_ai_analysis
from output.report import save_report

console = Console(legacy_windows=False)

BANNER = """
[bold green]
  ██████╗  ██████╗ ██████╗ ███████╗    ███████╗██╗   ██╗███████╗
 ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝
 ██║  ███╗██║   ██║██║  ██║███████╗    █████╗   ╚████╔╝ █████╗
 ██║   ██║██║   ██║██║  ██║╚════██╗    ██╔══╝    ╚██╔╝  ██╔══╝
 ╚██████╔╝╚██████╔╝██████╔╝███████║    ███████╗   ██║   ███████╗
  ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝    ╚══════╝   ╚═╝   ╚══════╝
[/bold green][dim]  GOD'S EYE v2.0.0 -- by alisalive[/dim]
[red]  For authorized security testing only[/red]
"""

SEVERITY_STYLE = {
    "critical": "bold red", "high": "red", "medium": "yellow",
    "low": "blue", "info": "dim",
}

STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
]


def load_config(config_path: str = None) -> dict:
    """Load config from YAML file."""
    default_config = {
        "scan": {"timeout": 2.0, "max_parallel_ports": 50, "port_list": "common"},
        "ai": {"model": "claude-sonnet-4-6", "max_tokens": 2000, "enabled": True},
        "output": {"screenshots": True, "json": True, "html": True, "open_browser": False},
        "stealth": {"min_delay": 1.0, "max_delay": 3.0, "rotate_ua": True},
        "paths": {
            "gods_eye": r"C:\Users\User\Documents\GODs_EYE",
            "wordlists": "./config/wordlists",
            "reports": "./reports",
        },
    }
    candidates = [
        config_path,
        "config/config.yaml",
        os.path.join(os.path.dirname(__file__), "config", "config.yaml"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            try:
                import yaml
                with open(path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                for section, values in loaded.items():
                    if section in default_config and isinstance(values, dict):
                        default_config[section].update(values)
                    else:
                        default_config[section] = values
                break
            except ImportError:
                pass
            except Exception as e:
                console.print(f"[yellow]Config load warning: {e}[/yellow]")
    return default_config


def print_banner():
    console.print(BANNER)
    console.print(Rule(style="dim"))


def print_phase_header(phase: str, icon: str = "◆"):
    console.print(f"\n[bold cyan]{icon} {phase.upper()}[/bold cyan]")
    console.print(Rule(style="cyan dim"))


def print_findings_table(state: EngagementState):
    if not state.findings:
        console.print("[dim]  No findings yet[/dim]")
        return
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold", padding=(0, 1))
    table.add_column("Sev", style="bold", width=8)
    table.add_column("Title", min_width=40)
    table.add_column("MITRE", style="dim", width=10)
    table.add_column("Phase", style="dim", width=8)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(state.findings, key=lambda x: sev_order.get(x.severity.value, 5)):
        style = SEVERITY_STYLE.get(f.severity.value, "")
        tactic = f.mitre_tactic[:8] + ".." if len(f.mitre_tactic) > 10 else f.mitre_tactic
        table.add_row(
            Text(f.severity.value.upper(), style=style),
            f.title[:60], tactic, f.phase,
        )
    console.print(table)


def print_summary_panel(state: EngagementState):
    counts = state.finding_counts()

    def bar(n, total, color):
        pct = int((n / max(total, 1)) * 20)
        return f"[{color}]{'#' * pct}{'.' * (20 - pct)}[/{color}] {n}"

    total = sum(counts.values())
    opsec_color = "green" if state.opsec_score >= 70 else "yellow" if state.opsec_score >= 40 else "red"
    content = (
        f"[bold]Target:[/bold]  {state.target}\n"
        f"[bold]Mode:[/bold]    {state.mode.value.upper()}\n"
        f"[bold]Duration:[/bold] {state.elapsed()}\n"
        f"[bold]OPSEC:[/bold]   [{opsec_color}]{state.opsec_score}/100[/{opsec_color}]\n\n"
        f"[bold red]CRITICAL[/bold red] {bar(counts.get('critical',0), total, 'red')}\n"
        f"[red]HIGH    [/red] {bar(counts.get('high',0), total, 'red')}\n"
        f"[yellow]MEDIUM  [/yellow] {bar(counts.get('medium',0), total, 'yellow')}\n"
        f"[blue]LOW     [/blue] {bar(counts.get('low',0), total, 'blue')}\n"
        f"[dim]INFO    [/dim] {bar(counts.get('info',0), total, 'white')}\n\n"
        f"[bold]Total:[/bold] {total} findings"
    )
    console.print(Panel(content, title="[bold]Engagement Summary[/bold]", border_style="cyan"))


async def stealth_delay(config: dict):
    """Apply random delay in stealth mode."""
    min_d = config.get("stealth", {}).get("min_delay", 1.0)
    max_d = config.get("stealth", {}).get("max_delay", 3.0)
    delay = random.uniform(min_d, max_d)
    await asyncio.sleep(delay)


async def run_engagement(
    target: str,
    mode: str,
    api_key: str = None,
    output_dir: str = "./reports",
    enable_ai: bool = False,
    stealth: bool = False,
    interactive: bool = False,
    enable_subdomains: bool = False,
    enable_screenshots: bool = False,
    config_path: str = None,
    no_report: bool = False,
    enable_dirbrute: bool = False,
    enable_pdf: bool = False,
):
    print_banner()
    config = load_config(config_path)

    if output_dir == "./reports":
        output_dir = config.get("paths", {}).get("reports", "./reports")

    gods_eye_path = config.get("paths", {}).get("gods_eye")

    state = EngagementState(
        target=target,
        mode=Mode(mode),
        scope=[target],
        opsec_score=100,
    )

    mode_color = "green" if mode == "pentest" else "red"
    console.print(Panel(
        f"[bold]Target:[/bold] [cyan]{target}[/cyan]\n"
        f"[bold]Mode:[/bold]   [{mode_color}]{mode.upper()}[/{mode_color}]\n"
        f"[bold]Stealth:[/bold] {'[green]ON[/green]' if stealth else '[dim]OFF[/dim]'}\n"
        f"[bold]Time:[/bold]   {time.strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold]Engagement Start[/bold]",
        border_style=mode_color,
    ))

    console.print(f"  [green]✓[/green] Config loaded | GOD'S EYE: {gods_eye_path}")

    # ── Phase 1: Recon ────────────────────────────────────────────────────────
    print_phase_header("Phase 1 — Reconnaissance (GOD'S EYE)", "◆")
    if stealth:
        console.print("  [yellow]⚡ Stealth mode: slow scan, UA rotation, random delays[/yellow]")
    with console.status("[cyan]Running GOD'S EYE recon...[/cyan]", spinner="dots"):
        await run_recon(state, console, stealth=stealth, gods_eye_path=gods_eye_path)
    if stealth:
        await stealth_delay(config)

    open_port_count = len(state.recon_data.get("open_ports", {}))
    console.print(f"  [green]✓[/green] Recon complete: [bold]{open_port_count}[/bold] open ports found")

    if state.recon_data.get("open_ports"):
        t = Table(box=box.SIMPLE, padding=(0, 1), show_header=True, header_style="dim")
        t.add_column("Port", width=6)
        t.add_column("Service", width=14)
        t.add_column("Banner", min_width=30)
        for port, info in sorted(state.recon_data["open_ports"].items()):
            t.add_row(str(port), info["service"], (info.get("banner", "") or "—")[:50])
        console.print(t)

    if interactive:
        console.input("\n[dim]  Press Enter to continue to next phase...[/dim]")

    # ── Phase 2: Subdomain enum ───────────────────────────────────────────────
    if enable_subdomains:
        print_phase_header("Phase 2 — Subdomain Enumeration", "◆")
        with console.status("[cyan]Brute-forcing subdomains...[/cyan]", spinner="dots"):
            from modules.subdomain import run_subdomain_enum
            sub_data = await run_subdomain_enum(state, console)
        console.print(f"  [green]✓[/green] Subdomains: [bold]{len(sub_data.get('found', []))}[/bold] found")
        if stealth:
            await stealth_delay(config)

    # ── Phase 3: Web analysis ─────────────────────────────────────────────────
    print_phase_header("Phase 3 — Web Analysis", "◆")
    with console.status("[cyan]Analyzing web services...[/cyan]", spinner="dots"):
        await run_web_analysis(state, console)
    web_count = len(state.web_data) if state.web_data else 0
    console.print(f"  [green]✓[/green] Web analysis: [bold]{web_count}[/bold] services analyzed")

    _emails = state.recon_data.get("emails", [])
    if _emails:
        console.print(
            f"  [green]✓[/green] Emails: [cyan]{', '.join(_emails[:6])}[/cyan]"
            + (f"[dim] (+{len(_emails)-6} more)[/dim]" if len(_emails) > 6 else "")
        )

    if state.web_data:
        with console.status("[cyan]Analyzing JWT tokens...[/cyan]", spinner="dots"):
            from modules.jwt_analyzer import run_jwt_analysis
            await run_jwt_analysis(state, console)

    # ── Phase 3b: Technology fingerprinting ──────────────────────────────────
    print_phase_header("Phase 3b — Technology Fingerprinting (50+ detections)", "◆")
    from modules.fingerprint import run_fingerprint
    _all_techs: list = []
    _web_services = state.recon_data.get("web", {})
    if _web_services:
        with console.status("[cyan]Fingerprinting technologies...[/cyan]", spinner="dots"):
            fp_tasks = [
                asyncio.wait_for(run_fingerprint(_winfo.get("url", ""), console), timeout=10)
                for _winfo in _web_services.values()
                if _winfo.get("url", "")
            ]
            fp_results = await asyncio.gather(*fp_tasks, return_exceptions=True)
            for res in fp_results:
                if isinstance(res, dict):
                    _all_techs.extend(res.get("technologies", []))
    state.recon_data["technologies"] = _all_techs

    # ── Phase 3b+: Outdated library findings ─────────────────────────────────
    _OUTDATED_VERSIONS = {
        "jquery": [
            ("< 1.9.0", "high",   "CVE-2011-4969 XSS vulnerability"),
            ("< 3.0.0", "high",   "CVE-2019-11358 prototype pollution"),
            ("< 3.5.0", "high",   "CVE-2020-11022 XSS via HTML parsing"),
        ],
        "bootstrap": [
            ("< 3.4.1", "medium", "CVE-2019-8331 XSS in tooltip/popover"),
            ("< 4.3.1", "medium", "CVE-2019-8331 XSS in tooltip/popover"),
        ],
        "angularjs": [
            ("< 1.8.0", "high",   "Multiple XSS vulnerabilities (sandbox escape)"),
        ],
        "angular": [
            ("< 1.8.0", "high",   "Multiple XSS vulnerabilities (sandbox escape)"),
        ],
    }
    try:
        from packaging.version import Version, InvalidVersion

        _seen_lib_findings: set = set()
        for _tech in _all_techs:
            _tname = _tech.get("name", "").lower()
            _tver  = _tech.get("version", "")
            if not _tver:
                continue
            try:
                _detected_ver = Version(_tver)
            except InvalidVersion:
                continue

            for _lib_key, _rules in _OUTDATED_VERSIONS.items():
                if _lib_key not in _tname:
                    continue
                # Find highest applicable threshold (most recent unfixed rule)
                _best_rule = None
                for _threshold_str, _sev, _cve_ref in _rules:
                    _op, _ver_str = _threshold_str.split()
                    try:
                        _threshold_ver = Version(_ver_str)
                    except InvalidVersion:
                        continue
                    if _op == "<" and _detected_ver < _threshold_ver:
                        if _best_rule is None:
                            _best_rule = (_threshold_str, _sev, _cve_ref, _threshold_ver)
                        else:
                            # Keep the rule with the highest threshold (most recent)
                            if _threshold_ver > _best_rule[3]:
                                _best_rule = (_threshold_str, _sev, _cve_ref, _threshold_ver)

                if _best_rule:
                    _threshold_str, _sev, _cve_ref, _threshold_ver = _best_rule
                    _finding_key = f"{_tname}:{_tver}"
                    if _finding_key not in _seen_lib_findings:
                        _seen_lib_findings.add(_finding_key)
                        from core.orchestrator import Finding, Severity
                        state.add_finding(Finding(
                            title=(
                                f"Outdated library: {_tech.get('name', _lib_key)} "
                                f"{_tver} ({_cve_ref})"
                            ),
                            severity=Severity(_sev),
                            description=(
                                f"Detected version {_tver} of "
                                f"{_tech.get('name', _lib_key)} is below "
                                f"{_threshold_str.replace('< ', '')}. "
                                f"Known vulnerability: {_cve_ref}."
                            ),
                            evidence=(
                                f"Detected version: {_tver} | "
                                f"Vulnerable range: {_threshold_str} | "
                                f"CVE reference: {_cve_ref}"
                            ),
                            mitre_tactic="Initial Access",
                            mitre_technique="T1190 - Exploit Public-Facing Application",
                            remediation=(
                                f"Upgrade {_tech.get('name', _lib_key)} to "
                                f"{_threshold_ver} or later. "
                                "Check the project's official changelog for migration notes."
                            ),
                            phase="web",
                        ))
                break  # matched a lib key — no need to check further keys
    except ImportError:
        pass  # packaging not available — skip version comparison

    # Display by category
    _CAT_ORDER = {"Server": 0, "Language": 1, "CDN": 2, "CDN/Hosting": 2,
                  "CMS": 3, "E-commerce": 4, "Framework": 5, "Library": 6,
                  "Analytics": 7, "Security": 8}
    if _all_techs:
        for _t in sorted(_all_techs, key=lambda x: (_CAT_ORDER.get(x.get("category", ""), 9), x.get("name", ""))):
            _ver = f" [dim]{_t['version']}[/dim]" if _t.get("version") else ""
            _conf_color = "cyan" if _t["confidence"] == "high" else "dim"
            console.print(
                f"  [dim]→[/dim] [{_conf_color}]{_t['category']}[/]: "
                f"[bold cyan]{_t['name']}[/bold cyan]{_ver} "
                f"[dim]({_t['confidence']})[/dim]"
            )
        console.print(f"  [green]✓[/green] Technologies: [bold]{len(_all_techs)}[/bold] detected")
    else:
        console.print("  [dim]→ No technologies detected[/dim]")

    if stealth:
        await stealth_delay(config)

    # ── Phase 2.5: Default Credentials ───────────────────────────────────────
    if state.recon_data.get("open_ports"):
        print_phase_header("Phase 2.5 — Default Credentials Check", "◆")
        with console.status("[cyan]Testing default credentials...[/cyan]", spinner="dots"):
            from modules.default_creds import run_default_creds_check
            creds_data = await run_default_creds_check(state, console)
        vuln_count = len(creds_data.get("vulnerable", []))
        if vuln_count:
            console.print(f"  [bold red]⚠ {vuln_count} service(s) with default credentials![/bold red]")
        else:
            console.print("  [green]✓[/green] No default credentials found")
        if stealth:
            await stealth_delay(config)

    # ── Directory Brute-Force (optional) ─────────────────────────────────────
    if enable_dirbrute:
        print_phase_header("Phase 3c — Directory Brute-Force", "◆")
        with console.status("[cyan]Brute-forcing directories...[/cyan]", spinner="dots"):
            from modules.dirbrute import run_dirbrute
            dirbrute_data = await run_dirbrute(state, console)
        dir_total = dirbrute_data.get("total", 0)
        console.print(f"  [green]✓[/green] Dirbrute: [bold]{dir_total}[/bold] interesting paths")
        if stealth:
            await stealth_delay(config)

    # ── Phase 4: CVE correlation ──────────────────────────────────────────────
    print_phase_header("Phase 4 — CVE Correlation", "◆")
    with console.status("[cyan]Correlating CVEs...[/cyan]", spinner="dots"):
        from modules.cve import run_cve_correlation
        cve_data = await run_cve_correlation(state, console)
    cve_total = cve_data.get("total", 0)
    console.print(f"  [green]✓[/green] CVE correlation: [bold]{cve_total}[/bold] CVEs found")

    # ── Metasploit Bridge ─────────────────────────────────────────────────────
    from modules.msf_bridge import run_msf_bridge, print_msf_table
    run_msf_bridge(state, console)
    if state.findings:
        mapped = len([f for f in state.findings if getattr(f, "msf_module", "")])
        if mapped:
            console.print(f"  [cyan]MSF modules mapped:[/cyan] {mapped} finding(s)")
            print_msf_table(state, console)

    # ── Phase 5: Screenshots ──────────────────────────────────────────────────
    if enable_screenshots:
        print_phase_header("Phase 5 — Screenshots", "◆")
        screenshot_dir = os.path.join(output_dir, "screenshots")
        with console.status("[cyan]Taking screenshots...[/cyan]", spinner="dots"):
            from modules.screenshot import run_screenshots
            screenshots = await run_screenshots(state, console, output_dir=screenshot_dir)
        ss_count = sum(1 for s in screenshots.values() if not s.get("error"))
        console.print(f"  [green]✓[/green] Screenshots: [bold]{ss_count}[/bold] captured")

    # ── OPSEC score ───────────────────────────────────────────────────────────
    from modules.opsec import calculate_opsec_score
    opsec_score = calculate_opsec_score(state, stealth=stealth, ua_rotation=stealth, delays=stealth)
    opsec_color = "green" if opsec_score >= 70 else "yellow" if opsec_score >= 40 else "red"
    console.print(f"\n  [bold]OPSEC Score:[/bold] [{opsec_color}]{opsec_score}/100[/{opsec_color}] "
                  f"({getattr(state, 'opsec_tracker_data', {}).get('rating', 'N/A')})")

    # ── Phase 6: AI analysis ──────────────────────────────────────────────────
    ai_result = {}
    if enable_ai:
        print_phase_header("Phase 6 — AI Analysis (Claude)", "◆")
        with console.status("[cyan]Claude is analyzing findings...[/cyan]", spinner="dots"):
            ai_result = await get_ai_analysis(state, api_key)
        if "error" not in ai_result:
            console.print(f"  [green]✓[/green] AI analysis complete ({ai_result.get('tokens_used', '?')} tokens)")
        else:
            console.print(f"  [yellow]⚠[/yellow] AI: {ai_result.get('error', 'failed')} — using fallback")
    else:
        console.print("\n  [dim]Phase 6 — AI Analysis skipped (use --ai to enable)[/dim]")

    # ── PART 9: Global deduplication ────────────────────────────────────────
    # Normalise titles so header findings with different phrasing collapse:
    #   "X-Content-Type-Options missing"          → "x-content-type-options"
    #   "Missing security header: X-Content-Type-Options" → "x-content-type-options"
    #   "CSP header missing"                      → "content-security-policy"
    #   "HSTS header missing" / "HSTS missing"   → "strict-transport-security"
    _TITLE_ALIASES: dict = {
        # CSP variants
        "csp header missing":                    "content-security-policy",
        "csp missing":                           "content-security-policy",
        "missing csp header":                    "content-security-policy",
        "content security policy missing":       "content-security-policy",
        "content-security-policy header missing": "content-security-policy",
        # HSTS variants
        "hsts header missing":                   "strict-transport-security",
        "hsts missing":                          "strict-transport-security",
        "missing hsts header":                   "strict-transport-security",
        "http strict transport security missing": "strict-transport-security",
        "strict-transport-security header missing": "strict-transport-security",
        # X-Frame-Options variants
        "x-frame-options header missing":        "x-frame-options",
        "x-frame-options missing":               "x-frame-options",
        "clickjacking protection missing":       "x-frame-options",
        # X-Content-Type-Options variants
        "x-content-type-options header missing": "x-content-type-options",
        "x-content-type-options missing":        "x-content-type-options",
        # Referrer-Policy variants
        "referrer-policy header missing":        "referrer-policy",
        "referrer-policy missing":               "referrer-policy",
        # Permissions-Policy variants
        "permissions-policy header missing":     "permissions-policy",
        "permissions-policy missing":            "permissions-policy",
        "feature-policy header missing":         "permissions-policy",
        "feature-policy missing":                "permissions-policy",
    }

    def _norm_title(t: str) -> str:
        s = (t or "").lower().strip()
        # Exact alias lookup first (handles known abbreviations and shorthands)
        if s in _TITLE_ALIASES:
            return _TITLE_ALIASES[s]
        # Strip common prefixes / suffixes used by different scanner backends
        s = s.removeprefix("missing security header: ")
        s = s.removesuffix(" missing")
        return s.strip()

    # For duplicate normalised titles, prefer "web" > "recon" > others.
    _PHASE_PRIORITY = {"web": 0, "recon": 1}
    _best: dict = {}   # norm_title → Finding
    for _f in state.findings:
        _key = _norm_title(_f.title)
        if _key not in _best:
            _best[_key] = _f
        else:
            _curr_pri = _PHASE_PRIORITY.get(getattr(_best[_key], "phase", ""), 99)
            _new_pri  = _PHASE_PRIORITY.get(getattr(_f, "phase", ""), 99)
            if _new_pri < _curr_pri:
                _best[_key] = _f
    # Re-emit in original encounter order (stable, deterministic)
    _seen_keys: set = set()
    _unique_findings = []
    for _f in state.findings:
        _key = _norm_title(_f.title)
        if _key not in _seen_keys:
            _seen_keys.add(_key)
            _unique_findings.append(_best[_key])
    state.findings = _unique_findings

    # ── Summary ───────────────────────────────────────────────────────────────
    console.print()
    print_summary_panel(state)
    console.print("\n[bold]All Findings:[/bold]")
    print_findings_table(state)

    # ── Phase 7: Report ───────────────────────────────────────────────────────
    if not no_report:
        print_phase_header("Phase 7 — Report Generation", "◆")
        os.makedirs(output_dir, exist_ok=True)
        paths = save_report(state, ai_result if ai_result else None, output_dir)
        console.print(f"  [green]✓[/green] HTML report: [link={paths['html']}]{paths['html']}[/link]")
        console.print(f"  [green]✓[/green] JSON export: {paths['json']}")

        if enable_pdf:
            from output.pdf_export import export_pdf
            pdf_path = export_pdf(paths["html"], output_dir, target, console)
            if pdf_path:
                console.print(f"  [green]✓[/green] PDF export: {pdf_path}")
    else:
        paths = {}
        console.print("  [dim]Report skipped (--no-report)[/dim]")

    console.print()
    console.print(Rule(style="green"))
    counts = state.finding_counts()
    if counts.get("critical", 0) > 0:
        risk = "CRITICAL"
    elif counts.get("high", 0) > 0:
        risk = "HIGH"
    elif counts.get("medium", 0) > 0:
        risk = "MEDIUM"
    elif counts.get("low", 0) > 0:
        risk = "LOW"
    elif counts.get("info", 0) > 0:
        risk = "INFO"
    else:
        risk = "NONE"
    console.print(
        f"[bold green]Engagement complete.[/bold green] "
        f"Risk: [bold red]{risk}[/bold red] | "
        f"{sum(counts.values())} findings | "
        f"OPSEC: {state.opsec_score}/100"
    )
    console.print("[dim]For authorized security testing only.[/dim]")
    console.print()

    return state, paths


def main():
    parser = argparse.ArgumentParser(
        description="GOD'S EYE v2.0.0 — Web fingerprinting & security analysis\nFor authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py 10.0.0.1
  python main.py example.com --mode redteam --stealth --subdomains --screenshot
  python main.py --target 10.0.0.1 --mode pentest --ai --api-key sk-ant-...
  python main.py --target 192.168.1.1 --mode pentest --ai --output ./reports
        """
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="Target IP or hostname (positional)")
    parser.add_argument("--target", "-t", dest="target_flag", default=None,
                        help="Target IP or hostname (flag form)")
    parser.add_argument("--mode", "-m", choices=["pentest", "redteam"], default="pentest")
    parser.add_argument("--ai", action="store_true",
                        help="Enable Claude AI analysis (requires --api-key or ANTHROPIC_API_KEY)")
    parser.add_argument("--api-key", "-k", help="Anthropic API key (or ANTHROPIC_API_KEY env var)")
    parser.add_argument("--output", "-o", default="./reports", help="Output directory")
    parser.add_argument("--output-dir", dest="output_dir", default=None, help="Output directory (alias)")
    parser.add_argument("--stealth", action="store_true",
                        help="Enable stealth mode (delays, UA rotation)")
    parser.add_argument("--interactive", action="store_true", help="Pause between phases")
    parser.add_argument("--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("--screenshot", action="store_true",
                        help="Enable screenshots (requires playwright)")
    parser.add_argument("--config", default=None, help="Config file path (YAML)")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    parser.add_argument("--dirbrute", action="store_true", help="Enable directory brute-force")
    parser.add_argument("--pdf", action="store_true", help="Export report as PDF")

    args = parser.parse_args()

    target = args.target or args.target_flag
    if not target:
        parser.error(
            "target is required: pass it as a positional argument or via --target/-t\n"
            "  e.g.  godseye example.com\n"
            "  e.g.  godseye --target example.com"
        )

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    output_dir = args.output_dir or args.output

    if args.ai and not api_key:
        parser.error(
            "--ai flag requires --api-key or the ANTHROPIC_API_KEY environment variable.\n"
            "  Set it with:  --api-key sk-ant-...\n"
            "  Or export:    set ANTHROPIC_API_KEY=sk-ant-..."
        )

    try:
        asyncio.run(run_engagement(
            target=target,
            mode=args.mode,
            api_key=api_key,
            output_dir=output_dir,
            enable_ai=args.ai,
            stealth=args.stealth,
            interactive=args.interactive,
            enable_subdomains=args.subdomains,
            enable_screenshots=args.screenshot,
            config_path=args.config,
            no_report=args.no_report,
            enable_dirbrute=args.dirbrute,
            enable_pdf=args.pdf,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
