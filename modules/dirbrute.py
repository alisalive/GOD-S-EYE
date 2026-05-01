"""
Directory Brute-Force — async HTTP path discovery.
Uses config/wordlists/endpoints.txt + built-in fallback list.
"""

import asyncio
import os
import time
from core.orchestrator import EngagementState, Finding, Severity

CONCURRENT = 20
RATE_LIMIT_PAUSE = 5.0  # seconds to wait on 429
DEFAULT_PATHS = [
    "/admin", "/login", "/wp-admin", "/phpmyadmin", "/dashboard",
    "/.env", "/.git/HEAD", "/config", "/backup", "/api", "/api/v1",
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/server-status", "/server-info", "/nginx_status",
    "/admin.php", "/admin.html", "/login.php", "/wp-login.php",
    "/xmlrpc.php", "/wp-config.php.bak", "/web.config", "/web.config.bak",
    "/debug", "/test", "/staging", "/dev", "/.htaccess", "/.htpasswd",
    "/etc/passwd", "/proc/self/environ",
    "/console", "/manager", "/jmx-console", "/admin-console",
    "/api/swagger", "/api/docs", "/v1", "/v2", "/graphql", "/graphiql",
    "/upload", "/uploads", "/files", "/file", "/static", "/assets",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/old", "/temp", "/tmp", "/cache",
    "/.DS_Store", "/Thumbs.db",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/info.php", "/phpinfo.php", "/test.php",
    "/trace.axd", "/elmah.axd",
    "/health", "/status", "/ping", "/version", "/info",
]

STATUS_SEVERITY = {
    200: (Severity.HIGH, "Accessible path discovered"),
    201: (Severity.HIGH, "Resource created endpoint accessible"),
    204: (Severity.MEDIUM, "No-content endpoint accessible"),
    301: (Severity.INFO, "Redirect (may indicate valid path)"),
    302: (Severity.INFO, "Redirect (may indicate valid path)"),
    401: (Severity.MEDIUM, "Authentication required (path exists)"),
    403: (Severity.LOW, "Forbidden (path exists but protected)"),
}


def _load_wordlist() -> list:
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "config", "wordlists", "endpoints.txt"),
        "config/wordlists/endpoints.txt",
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                if lines:
                    return lines
            except Exception:
                pass
    return DEFAULT_PATHS


async def _check_path(
    session, base_url: str, path: str, semaphore: asyncio.Semaphore, results: list,
    rate_limited: asyncio.Event
) -> None:
    async with semaphore:
        if rate_limited.is_set():
            await asyncio.sleep(RATE_LIMIT_PAUSE)
            rate_limited.clear()
        url = base_url.rstrip("/") + path
        try:
            import aiohttp
            async with session.get(url, allow_redirects=False, ssl=False) as resp:
                status = resp.status
                if status == 429:
                    rate_limited.set()
                    return
                content_length = resp.headers.get("Content-Length", "?")
                location = resp.headers.get("Location", "")
                if status in STATUS_SEVERITY or (200 <= status < 400):
                    results.append({
                        "path": path,
                        "url": url,
                        "status": status,
                        "content_length": content_length,
                        "redirect": location,
                    })
        except Exception:
            pass


async def run_dirbrute(
    state: EngagementState,
    console=None,
    extra_paths: list = None,
) -> dict:
    """Brute-force directories on all discovered web ports."""
    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    open_ports = state.recon_data.get("open_ports", {})
    web_ports = []
    for port_str, info in open_ports.items():
        port = int(port_str)
        svc = (info.get("service") or "").lower()
        if port in (80, 443, 8080, 8443, 8888, 3000, 5000, 9000) or "http" in svc:
            scheme = "https" if port in (443, 8443) else "http"
            web_ports.append((port, scheme))

    if not web_ports:
        log("No web ports found — skipping dirbrute")
        return {"results": {}, "total": 0}

    wordlist = _load_wordlist()
    if extra_paths:
        wordlist = list(set(wordlist + extra_paths))

    log(f"Brute-forcing {len(wordlist)} paths on {len(web_ports)} web port(s)...")

    import aiohttp
    all_results = {}
    semaphore = asyncio.Semaphore(CONCURRENT)
    rate_limited = asyncio.Event()

    timeout = aiohttp.ClientTimeout(total=8)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}

    for port, scheme in web_ports:
        base_url = f"{scheme}://{state.target}:{port}"
        port_results = []
        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                tasks = [
                    _check_path(session, base_url, path, semaphore, port_results, rate_limited)
                    for path in wordlist
                ]
                await asyncio.gather(*tasks)
        except Exception:
            pass

        all_results[str(port)] = port_results
        log(f"Port {port}: {len(port_results)} interesting paths found")

        # Generate findings for this port
        for entry in port_results:
            status = entry["status"]
            if status not in STATUS_SEVERITY:
                continue
            sev, label = STATUS_SEVERITY[status]
            path = entry["path"]
            url = entry["url"]

            # Extra context for particularly juicy paths
            extra = ""
            juicy_keywords = [
                ".env", ".git", "backup", "config", "phpinfo", "admin",
                "swagger", "actuator", "debug", "console", "passwd",
                "sql", "dump", ".htpasswd"
            ]
            if any(k in path.lower() for k in juicy_keywords):
                sev = Severity.CRITICAL if sev == Severity.HIGH else sev
                extra = " [SENSITIVE]"

            state.add_finding(Finding(
                title=f"Dirbrute: {label}{extra} — {path} (HTTP {status})",
                severity=sev,
                description=(
                    f"Path '{path}' returned HTTP {status} on {base_url}. "
                    f"{label}."
                ),
                evidence=(
                    f"URL: {url} | Status: {status} | "
                    f"Content-Length: {entry['content_length']}"
                    + (f" | Redirect: {entry['redirect']}" if entry["redirect"] else "")
                ),
                mitre_tactic="Discovery",
                mitre_technique="T1083 - File and Directory Discovery",
                remediation=(
                    "Restrict access to sensitive paths. Remove or protect "
                    "admin panels, backup files, and configuration endpoints."
                ),
                phase="dirbrute",
            ))

    total = sum(len(v) for v in all_results.values())
    data = {"results": all_results, "total": total, "wordlist_size": len(wordlist)}

    if not hasattr(state, "dirbrute_data"):
        state.dirbrute_data = {}
    state.dirbrute_data = data

    state.add_note(f"Dirbrute: {total} interesting paths found across {len(web_ports)} port(s)")
    return data
