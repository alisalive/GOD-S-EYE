"""
GOD'S EYE Bridge — integrates GOD'S EYE scanner into the orchestrator.
"""

import asyncio
import os
import sys
from typing import Optional
from pathlib import Path


def _add_gods_eye_to_path(gods_eye_path: Optional[str] = None) -> bool:
    """Add GOD'S EYE to sys.path. Returns True if successful."""
    candidates = [
        gods_eye_path,
        os.environ.get("GODS_EYE_PATH"),
        r"C:\Users\User\Documents\GODs_EYE",
        str(Path.home() / "Documents" / "GODs_EYE"),
    ]
    for candidate in candidates:
        if candidate and os.path.isdir(candidate):
            if candidate not in sys.path:
                sys.path.insert(0, candidate)
            return True
    return False


async def run_gods_eye_scan(target_url: str, gods_eye_path: Optional[str] = None) -> dict:
    """
    Run a full GOD'S EYE scan on a URL.
    Returns dict with technologies, waf, cves, vulns, crawl_urls.
    Falls back gracefully if GOD'S EYE is unavailable.
    """
    result = {
        "url": target_url,
        "technologies": [],
        "waf": [],
        "cves": [],
        "vulns": [],
        "crawl_urls": [],
        "title": None,
        "server": None,
        "error": None,
    }

    if not _add_gods_eye_to_path(gods_eye_path):
        result["error"] = "GOD'S EYE not found — skipping deep scan"
        return result

    try:
        from gods_eye.engine import Engine
        from gods_eye.fingerprint import fingerprint_target
        from gods_eye.waf import detect_waf
        from gods_eye.vuln import run_vuln_checks
        from gods_eye.crawler import crawl

        async with Engine(concurrency=10, timeout=10) as engine:
            # Run fingerprinting + WAF detection in parallel
            fp_task = fingerprint_target(target_url, engine, run_cve=True)
            waf_task = detect_waf(target_url, engine)
            fp_result, waf_results = await asyncio.gather(fp_task, waf_task, return_exceptions=True)

            if isinstance(fp_result, Exception):
                result["error"] = f"Fingerprint error: {fp_result}"
            else:
                result["title"] = fp_result.get("title")
                result["server"] = fp_result.get("server")
                result["technologies"] = [
                    {
                        "name": t.name,
                        "category": t.category,
                        "version": t.version,
                        "confidence": t.confidence,
                    }
                    for t in fp_result.get("technologies", [])
                ]
                result["cves"] = [
                    {
                        "cve_id": c.cve_id,
                        "technology": c.technology,
                        "severity": c.severity,
                        "cvss_score": c.cvss_score,
                        "description": c.description,
                        "reference_url": c.reference_url,
                        "affected_versions": c.affected_versions,
                        "fixed_version": c.fixed_version,
                    }
                    for c in fp_result.get("cves", [])
                ]

            if isinstance(waf_results, Exception):
                pass
            else:
                result["waf"] = [
                    {"name": w.name, "confidence": w.confidence, "evidence": w.evidence}
                    for w in waf_results
                    if w.confidence > 30
                ]

            # Vulnerability checks using detected technologies
            tech_objs = fp_result.get("technologies", []) if not isinstance(fp_result, Exception) else []
            try:
                vuln_findings = await run_vuln_checks(target_url, engine, depth=2, technologies=tech_objs)
                result["vulns"] = [
                    {
                        "name": v.name,
                        "severity": v.severity,
                        "url": v.url,
                        "evidence": v.evidence,
                        "recommendation": v.recommendation,
                        "category": v.category,
                    }
                    for v in vuln_findings
                ]
            except Exception as e:
                result["vulns"] = []

            # Crawl for URL discovery
            try:
                crawl_results = await crawl(target_url, engine, depth=2, max_urls=50)
                result["crawl_urls"] = [r.url for r in crawl_results]
            except Exception:
                result["crawl_urls"] = []

    except ImportError as e:
        result["error"] = f"GOD'S EYE import error: {e}"
    except Exception as e:
        result["error"] = f"GOD'S EYE scan error: {e}"

    return result


def gods_eye_to_recon_format(ge_result: dict, port: int, ssl: bool) -> dict:
    """Convert GOD'S EYE result to the format expected by recon_data['web']."""
    waf_name = None
    waf_confidence = 0
    for w in ge_result.get("waf", []):
        if w["confidence"] > waf_confidence:
            waf_name = w["name"]
            waf_confidence = w["confidence"]

    return {
        "url": ge_result.get("url", ""),
        "status_code": 200,
        "server": ge_result.get("server", ""),
        "technologies": [t["name"] for t in ge_result.get("technologies", [])],
        "technologies_detailed": ge_result.get("technologies", []),
        "waf": waf_name,
        "waf_results": ge_result.get("waf", []),
        "headers": {},
        "error": ge_result.get("error"),
        "cves": ge_result.get("cves", []),
        "vulns": ge_result.get("vulns", []),
        "crawl_urls": ge_result.get("crawl_urls", []),
        "title": ge_result.get("title"),
    }
