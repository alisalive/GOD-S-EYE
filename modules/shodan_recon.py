"""
Shodan Integration — enriches recon data using Shodan REST API.
Requires --shodan-key flag or SHODAN_API_KEY environment variable.
"""

import asyncio
import os
from core.orchestrator import EngagementState, Finding, Severity

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"


async def fetch_shodan_host(ip: str, api_key: str, timeout: float = 15.0) -> dict:
    """Fetch host data from Shodan API. Returns raw dict or {} on failure."""
    try:
        import aiohttp
        url = SHODAN_HOST_URL.format(ip=ip)
        params = {"key": api_key}
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    return await resp.json(content_type=None)
                elif resp.status == 404:
                    return {}  # No Shodan data for this IP
                else:
                    return {}
    except Exception:
        return {}


def _extract_shodan_findings(shodan_data: dict, state: EngagementState) -> list:
    """Create Finding objects from Shodan vulnerability data."""
    findings = []
    vulns = shodan_data.get("vulns", {})
    for cve_id, vuln_info in vulns.items():
        cvss = float(vuln_info.get("cvss", 0)) if vuln_info.get("cvss") else 0.0
        summary = vuln_info.get("summary", f"Shodan-reported vulnerability: {cve_id}")
        sev = Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH if cvss >= 7.0 else Severity.MEDIUM
        f = Finding(
            title=f"Shodan: {cve_id} (CVSS {cvss})",
            severity=sev,
            description=summary[:400],
            evidence=f"Reported by Shodan for {state.target} | CVSS: {cvss}",
            mitre_tactic="Initial Access",
            mitre_technique="T1190 - Exploit Public-Facing Application",
            remediation=f"Patch {cve_id}. See https://nvd.nist.gov/vuln/detail/{cve_id}",
            cvss=cvss,
            phase="shodan",
        )
        state.add_finding(f)
        findings.append(f)
    return findings


def _parse_shodan_data(shodan_data: dict, state: EngagementState) -> dict:
    """Merge Shodan data into recon_data and return structured summary."""
    if not shodan_data:
        return {}

    ports = shodan_data.get("ports", [])
    hostnames = shodan_data.get("hostnames", [])
    org = shodan_data.get("org", "")
    isp = shodan_data.get("isp", "")
    country = shodan_data.get("country_name", "")
    os_str = shodan_data.get("os", "")
    tags = shodan_data.get("tags", [])

    # Merge ports into existing open_ports
    existing_ports = state.recon_data.setdefault("open_ports", {})
    for svc in shodan_data.get("data", []):
        port = svc.get("port")
        if port and str(port) not in existing_ports:
            existing_ports[str(port)] = {
                "service": svc.get("_shodan", {}).get("module", "unknown"),
                "banner": (svc.get("data", "") or "")[:200],
                "source": "shodan",
            }

    # Merge hostnames
    state.recon_data.setdefault("hostnames", [])
    for h in hostnames:
        if h not in state.recon_data["hostnames"]:
            state.recon_data["hostnames"].append(h)

    summary = {
        "ports": ports,
        "hostnames": hostnames,
        "org": org,
        "isp": isp,
        "country": country,
        "os": os_str,
        "tags": tags,
        "vuln_count": len(shodan_data.get("vulns", {})),
    }

    state.recon_data["shodan"] = summary
    return summary


async def run_shodan_recon(state: EngagementState, api_key: str, console=None) -> dict:
    """Main entry point: fetch Shodan data, merge into state, generate findings."""
    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    if not api_key:
        log("No Shodan API key — skipping Shodan enrichment")
        return {}

    # Only works for IPs; skip for domains
    import socket
    try:
        ip = socket.gethostbyname(state.target)
    except Exception:
        ip = state.target

    log(f"Querying Shodan for {ip}...")

    shodan_data = await fetch_shodan_host(ip, api_key)
    if not shodan_data:
        log("No Shodan data found for this host")
        return {}

    summary = _parse_shodan_data(shodan_data, state)
    findings = _extract_shodan_findings(shodan_data, state)

    log(
        f"Shodan: {len(summary.get('ports', []))} ports, "
        f"{summary.get('vuln_count', 0)} vulns, "
        f"org={summary.get('org', 'unknown')}"
    )
    if summary.get("os"):
        log(f"OS (Shodan): {summary['os']}")
    if summary.get("tags"):
        log(f"Tags: {', '.join(summary['tags'])}")

    state.add_note(
        f"Shodan: {summary.get('vuln_count', 0)} vulnerabilities, "
        f"org={summary.get('org', 'unknown')}, "
        f"country={summary.get('country', 'unknown')}"
    )
    return summary
