"""
CVE Correlation Module — NVD API integration with local cache.
Wraps GOD'S EYE cve.py and adds NVD API fetching.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional
from core.orchestrator import EngagementState, Finding, Severity

CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "config", "cve_cache.json")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = 86400 * 7  # 7 days


def _load_cache() -> dict:
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    try:
        Path(CACHE_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


async def fetch_nvd_cves(keyword: str, cvss_min: float = 7.0) -> list:
    """Fetch CVEs from NVD API for a keyword. Returns list of CVE dicts."""
    cache = _load_cache()
    cache_key = f"nvd_{keyword}_{cvss_min}"

    cached = cache.get(cache_key)
    if cached and time.time() - cached.get("ts", 0) < CACHE_TTL:
        return cached.get("data", [])

    try:
        import aiohttp
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 50,
        }
        timeout = aiohttp.ClientTimeout(total=20)
        results = []
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(NVD_API_URL, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in data.get("vulnerabilities", []):
                        cve_data = item.get("cve", {})
                        cve_id = cve_data.get("id", "")
                        if not cve_id:
                            continue

                        desc = ""
                        for d in cve_data.get("descriptions", []):
                            if d.get("lang") == "en":
                                desc = d.get("value", "")
                                break

                        cvss = 0.0
                        metrics = cve_data.get("metrics", {})
                        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            entries = metrics.get(key, [])
                            if entries:
                                cvss = entries[0].get("cvssData", {}).get("baseScore", 0.0)
                                break

                        if cvss < cvss_min:
                            continue

                        sev = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM"
                        refs = cve_data.get("references", [])
                        ref_url = refs[0].get("url", "") if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                        results.append({
                            "cve_id": cve_id,
                            "technology": keyword,
                            "severity": sev,
                            "cvss_score": cvss,
                            "description": desc[:500],
                            "reference_url": ref_url,
                            "affected_versions": "see NVD",
                            "fixed_version": "see NVD",
                        })

        cache[cache_key] = {"ts": time.time(), "data": results}
        _save_cache(cache)
        return results

    except Exception:
        return []


def lookup_from_gods_eye(technologies: list) -> list:
    """Use GOD'S EYE cve module for version-aware CVE lookup."""
    try:
        _gods_eye = os.environ.get("GODS_EYE_PATH", r"C:\Users\User\Documents\GODs_EYE")
        if _gods_eye not in sys.path:
            sys.path.insert(0, _gods_eye)
        from gods_eye.cve import lookup_all

        class _TechStub:
            def __init__(self, name, version):
                self.name = name
                self.version = version

        stubs = [_TechStub(t.get("name", ""), t.get("version")) for t in technologies if t.get("version")]
        cves = lookup_all(stubs)
        return [
            {
                "cve_id": c.cve_id,
                "technology": c.technology,
                "severity": c.severity,
                "cvss_score": c.cvss_score,
                "description": c.description,
                "reference_url": c.reference_url,
                "affected_versions": c.affected_versions,
                "fixed_version": c.fixed_version,
                "detected_version": c.detected_version,
            }
            for c in cves
        ]
    except Exception:
        return []


async def run_cve_correlation(state: EngagementState, console=None) -> dict:
    """Correlate detected technologies with CVE database."""
    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    all_technologies = []
    for port, wdata in state.recon_data.get("web", {}).items():
        for tech in wdata.get("technologies_detailed", []):
            if isinstance(tech, dict) and tech.get("name"):
                all_technologies.append(tech)
            elif isinstance(tech, str):
                all_technologies.append({"name": tech, "version": None})

    if not all_technologies:
        return {"cves": [], "total": 0}

    log(f"CVE lookup for {len(all_technologies)} technologies...")

    # GOD'S EYE version-aware lookup
    ge_cves = lookup_from_gods_eye(all_technologies)

    # NVD API skipped for techs without a known version (no version = no reliable match)
    nvd_cves = []
    seen_ids = {c["cve_id"] for c in ge_cves}

    all_cves = ge_cves + nvd_cves
    all_cves.sort(key=lambda c: c.get("cvss_score", 0), reverse=True)

    cve_data = {"cves": all_cves, "total": len(all_cves)}

    if not hasattr(state, "cve_data"):
        state.cve_data = {}
    state.cve_data = cve_data

    # High/critical CVEs → findings
    for cve in all_cves:
        if cve.get("cvss_score", 0) >= 7.0:
            sev = Severity.CRITICAL if cve["cvss_score"] >= 9.0 else Severity.HIGH
            state.add_finding(Finding(
                title=f"{cve['cve_id']}: {cve['technology']} ({cve['severity']})",
                severity=sev,
                description=cve["description"][:300],
                evidence=(
                    f"CVSS: {cve['cvss_score']} | "
                    f"Affected: {cve.get('affected_versions', 'see NVD')} | "
                    f"Fixed: {cve.get('fixed_version', 'see NVD')}"
                ),
                mitre_tactic="Initial Access",
                mitre_technique="T1190 - Exploit Public-Facing Application",
                remediation=f"Upgrade {cve['technology']} to fixed version. See {cve['reference_url']}",
                cvss=cve["cvss_score"],
                phase="cve",
            ))

    log(f"CVE correlation: {len(all_cves)} CVEs found "
        f"({sum(1 for c in all_cves if c.get('cvss_score', 0) >= 9.0)} critical)")
    state.add_note(f"CVE correlation: {len(all_cves)} total, "
                   f"{sum(1 for c in all_cves if c.get('cvss_score', 0) >= 7.0)} high+")
    return cve_data
