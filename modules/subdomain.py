"""
Subdomain Enumeration Module — async DNS brute-force.
"""

import asyncio
import socket
import os
from pathlib import Path
from core.orchestrator import EngagementState, Finding, Severity

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "wordlists", "subdomains.txt")

CONCURRENT = 50


def _load_wordlist(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return FALLBACK_SUBDOMAINS


FALLBACK_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "portal", "dev", "staging", "test",
    "api", "app", "vpn", "remote", "webmail", "blog", "shop", "cdn",
    "static", "media", "images", "docs", "wiki", "help", "support",
    "beta", "alpha", "demo", "sandbox", "uat", "qa", "prod", "backup",
    "db", "mysql", "redis", "mongo", "elastic", "jenkins", "gitlab",
    "smtp", "ns1", "ns2", "dns", "proxy", "gateway", "internal",
    "intranet", "auth", "login", "sso", "oauth", "accounts", "payment",
    "billing", "search", "graphql", "rest", "webhook", "monitor",
    "dashboard", "panel", "cpanel", "phpmyadmin", "old", "new", "secure",
]


async def resolve_subdomain(subdomain: str, domain: str, semaphore: asyncio.Semaphore) -> dict:
    fqdn = f"{subdomain}.{domain}"
    async with semaphore:
        try:
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(None, socket.getaddrinfo, fqdn, None)
            ips = list(set(i[4][0] for i in info))
            return {"fqdn": fqdn, "ips": ips, "found": True}
        except Exception:
            return {"fqdn": fqdn, "ips": [], "found": False}


def extract_domain(target: str) -> str:
    """Extract base domain from target (strip subdomains, IPs treated as-is)."""
    # If it's an IP, return as-is
    try:
        socket.inet_aton(target)
        return target
    except OSError:
        pass
    parts = target.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return target


async def run_subdomain_enum(state: EngagementState, console=None,
                              wordlist_path: str = None) -> dict:
    target = state.target
    domain = extract_domain(target)

    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    wl_path = wordlist_path or WORDLIST_PATH
    wordlist = _load_wordlist(wl_path)
    log(f"Subdomain brute-force: {domain} ({len(wordlist)} words, {CONCURRENT} concurrent)")

    semaphore = asyncio.Semaphore(CONCURRENT)
    tasks = [resolve_subdomain(sub, domain, semaphore) for sub in wordlist]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    found = []
    for result in results:
        if isinstance(result, dict) and result.get("found"):
            found.append(result)
            log(f"[green]Found:[/green] {result['fqdn']} → {', '.join(result['ips'])}")
            state.add_finding(Finding(
                title=f"Subdomain found: {result['fqdn']}",
                severity=Severity.INFO,
                description=f"Subdomain {result['fqdn']} resolves to {', '.join(result['ips'])}",
                evidence=f"DNS resolution: {result['fqdn']} → {result['ips']}",
                mitre_tactic="Reconnaissance",
                mitre_technique="T1596.001 - DNS/Passive DNS",
                remediation="Audit all subdomains and ensure none expose unintended services.",
                phase="subdomain",
            ))

    subdomain_data = {
        "domain": domain,
        "found": found,
        "total_checked": len(wordlist),
    }

    if not hasattr(state, "subdomains"):
        state.subdomains = []
    state.subdomains = found
    state.recon_data["subdomains"] = subdomain_data

    log(f"Subdomain enum complete: {len(found)}/{len(wordlist)} found")
    state.add_note(f"Subdomain enum: {len(found)} subdomains found for {domain}")
    return subdomain_data
