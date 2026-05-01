"""
Web / WAF Module — SQLi, WAF detection, email harvesting, cookie analysis.
"""

import asyncio
import logging
import re
import urllib.parse
import aiohttp
import ssl as ssl_lib
from core.orchestrator import EngagementState, Finding, Severity

logger = logging.getLogger(__name__)


# ── Email harvesting ──────────────────────────────────────────────────────────

# TLD capped at 6 chars: rejects image extensions that look like TLDs (.jpeg=4,
# .webp=4, but also stops long garbage matches).
_EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b')

_IMAGE_EXTENSIONS = frozenset([
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff",
])

_EMAIL_LOCAL_BLACKLIST = frozenset([
    "noreply", "no-reply", "donotreply", "test", "support",
    "webmaster", "postmaster", "bounce",
])
_EMAIL_DOMAIN_BLACKLIST = frozenset([
    "example.com", "test.com", "domain.com", "yourdomain.com",
    "email.com", "sentry.io", "w3.org", "schema.org",
])


def extract_emails(text: str) -> list:
    """
    Extract valid, non-placeholder email addresses from HTML / plain text.

    Sources checked (in order):
      1. Raw regex scan of the full text
      2. mailto: link hrefs (strips query strings after ?)
      3. <meta name="…email…" content="…"> tags

    Filters out:
      - Known placeholder domains (example.com, test.com, …)
      - Common role-address local-parts (noreply, test, webmaster, …)
    """
    if not text or not isinstance(text, str):
        return []

    found: set = set()

    def _accept(addr: str) -> bool:
        addr = addr.lower().strip()
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]{2,6}$', addr):
            return False
        # Reject retina-image filenames: "icon@2x.png", "logo@2x-large.png"
        if "@2x" in addr:
            return False
        # Reject if URL path slipped in
        if "/" in addr:
            return False
        local, _, domain = addr.partition("@")
        # Reject if domain ends with an image file extension
        if any(domain.endswith(ext) for ext in _IMAGE_EXTENSIONS):
            return False
        if domain in _EMAIL_DOMAIN_BLACKLIST:
            return False
        if any(bl in local for bl in _EMAIL_LOCAL_BLACKLIST):
            return False
        return True

    # 1. Plain regex scan
    for m in _EMAIL_RE.finditer(text):
        addr = m.group(0).lower()
        if _accept(addr):
            found.add(addr)

    # 2. mailto: links (strip query-string parameters after ?)
    for m in re.finditer(r'mailto:([^"\'<>\s#]+)', text, re.IGNORECASE):
        raw = m.group(1).split("?")[0]
        if _accept(raw):
            found.add(raw.lower())

    # 3. Meta content tags that look like email addresses
    for m in re.finditer(
        r'<meta[^>]+content=["\']([^"\']+)["\']', text, re.IGNORECASE
    ):
        val = m.group(1)
        if "@" in val and _accept(val):
            found.add(val.lower())

    return sorted(found)


# ── Cookie security analysis ──────────────────────────────────────────────────

_SESSION_COOKIE_TECH: dict = {
    "phpsessid":         "PHP",
    "jsessionid":        "Java/JSP",
    "laravel_session":   "Laravel",
    "connect.sid":       "Node.js",
    "sessionid":         "Django",
    "aspsessionid":      "ASP.NET",
    "asp.net_sessionid": "ASP.NET",
    "_session_id":       "Ruby on Rails",
}

# Any cookie whose name contains one of these substrings is treated as a
# session/auth cookie and checked for security flags.
_SESSION_COOKIE_KEYWORDS = frozenset([
    "phpsessid", "jsessionid", "laravel_session", "connect.sid",
    "sessionid", "aspsessionid", "asp.net_sessionid", "_session_id",
    "sess", "session", "auth", "token",
])

# Cookies with these substrings are high-sensitivity — missing HttpOnly → HIGH
_HIGH_SENSITIVITY_COOKIE_KEYWORDS = frozenset([
    "token", "jwt", "auth", "bearer", "api_key", "apikey",
])

# 1 year in seconds
_ONE_YEAR_SECS = 365 * 24 * 3600


def analyze_set_cookie_headers(set_cookie_list: list) -> tuple:
    """
    Parse a list of raw Set-Cookie header values.

    Returns:
        (tech_names, security_findings)
        tech_names       — list[str] of technology names inferred from cookie names
        security_findings — list[dict] with keys: title, severity, description,
                            evidence, remediation
    """
    tech_names: list = []
    findings: list = []

    for hval in set_cookie_list:
        if not hval or not isinstance(hval, str):
            continue
        parts = [p.strip() for p in hval.split(";")]
        if not parts:
            continue

        name_part   = parts[0]
        cookie_name = (name_part.split("=")[0] if "=" in name_part else name_part).strip()
        cname_lower = cookie_name.lower()

        # ── Tech detection from well-known session cookie names ───────────────
        if cname_lower in _SESSION_COOKIE_TECH:
            tech_names.append(_SESSION_COOKIE_TECH[cname_lower])

        # ── Security flag analysis — only for session/auth cookies ───────────
        is_session = any(kw in cname_lower for kw in _SESSION_COOKIE_KEYWORDS)
        if not is_session:
            continue

        flags = [p.strip().lower() for p in parts[1:]]
        has_httponly = any("httponly" in f for f in flags)
        has_secure   = any(f == "secure" or f.startswith("secure;")
                           or f.startswith("secure ") for f in flags)
        has_secure   = has_secure or "secure" in flags
        samesite     = next((f for f in flags if "samesite" in f), None)

        evidence_snip = hval[:150] + ("…" if len(hval) > 150 else "")

        # Determine if this is a high-sensitivity cookie
        is_high_sensitivity = any(
            kw in cname_lower for kw in _HIGH_SENSITIVITY_COOKIE_KEYWORDS
        )

        if not has_httponly:
            sev = "high" if is_high_sensitivity else "medium"
            findings.append({
                "title": f"Session cookie missing HttpOnly flag: {cookie_name}",
                "severity": sev,
                "description": (
                    f"The '{cookie_name}' cookie does not carry the HttpOnly flag. "
                    "JavaScript running in the page can read it, enabling session "
                    "hijacking via XSS."
                ),
                "evidence": f"Set-Cookie: {evidence_snip}",
                "remediation": (
                    f"Set the HttpOnly attribute: "
                    f"Set-Cookie: {cookie_name}=...; HttpOnly; Secure; SameSite=Lax"
                ),
            })

        if not has_secure:
            findings.append({
                "title": f"Session cookie missing Secure flag: {cookie_name}",
                "severity": "medium",
                "description": (
                    f"The '{cookie_name}' cookie does not carry the Secure flag. "
                    "It may be transmitted over plain HTTP, exposing it to "
                    "network eavesdropping."
                ),
                "evidence": f"Set-Cookie: {evidence_snip}",
                "remediation": (
                    f"Add the Secure flag: "
                    f"Set-Cookie: {cookie_name}=...; HttpOnly; Secure; SameSite=Lax"
                ),
            })

        if not samesite:
            findings.append({
                "title": f"Session cookie missing SameSite attribute: {cookie_name}",
                "severity": "low",
                "description": (
                    f"The '{cookie_name}' cookie has no SameSite attribute. "
                    "Browsers may send it with cross-site requests, "
                    "widening the CSRF attack surface."
                ),
                "evidence": f"Set-Cookie: {evidence_snip}",
                "remediation": (
                    f"Add SameSite=Lax (or Strict): "
                    f"Set-Cookie: {cookie_name}=...; HttpOnly; Secure; SameSite=Lax"
                ),
            })

        # ── Long expiry check ─────────────────────────────────────────────────
        max_age_m = re.search(r'max-age=(\d+)', hval, re.IGNORECASE)
        if max_age_m:
            try:
                max_age_secs = int(max_age_m.group(1))
                if max_age_secs > _ONE_YEAR_SECS:
                    findings.append({
                        "title": f"Session cookie has very long expiry: {cookie_name}",
                        "severity": "low",
                        "description": (
                            f"The '{cookie_name}' cookie has Max-Age={max_age_secs}s "
                            f"(>{max_age_secs // _ONE_YEAR_SECS} year(s)). "
                            "Long-lived session cookies increase the window for "
                            "session theft and token replay attacks."
                        ),
                        "evidence": f"Set-Cookie: {evidence_snip}",
                        "remediation": (
                            "Reduce session cookie lifetime. Implement server-side "
                            "session expiry and short Max-Age values."
                        ),
                    })
            except ValueError:
                pass

    return tech_names, findings


# ── Sensitive endpoint paths ──────────────────────────────────────────────────

SENSITIVE_ENDPOINTS = [
    # Secrets & config (CRITICAL)
    "/.env", "/.git/HEAD", "/config.php", "/wp-config.php", "/.htpasswd",
    "/.DS_Store", "/backup.zip",
    # Dev / diagnostic
    "/phpinfo.php", "/debug", "/console",
    # Admin panels
    "/adminer.php", "/phpmyadmin/", "/admin/", "/login",
    # APIs & explorers
    "/api/", "/graphql", "/swagger.json",
    # Public metadata
    "/sitemap.xml", "/robots.txt", "/.well-known/security.txt",
]

# Body-keyword confirmation for specific high-value paths.
# (keywords_list, Severity, title_template)
ENDPOINT_CONFIRMATIONS: dict = {
    "/.env": (
        ["DB_PASSWORD", "API_KEY", "SECRET", "APP_KEY", "DATABASE_URL", "MAIL_PASSWORD"],
        Severity.CRITICAL,
        "Environment file exposed: secrets in .env",
    ),
    "/.git/HEAD": (
        ["ref:"],
        Severity.CRITICAL,
        "Git repository exposed: .git/HEAD accessible",
    ),
    "/phpinfo.php": (
        ["PHP Version", "phpinfo"],
        Severity.HIGH,
        "PHP info page exposed",
    ),
    "/adminer.php": (
        ["Adminer", "adminer", "database"],
        Severity.CRITICAL,
        "Database admin panel exposed: Adminer",
    ),
    "/debug": (
        ["Traceback", "Exception", "stack trace", "StackTrace", "SyntaxError"],
        Severity.HIGH,
        "Debug endpoint exposes application errors",
    ),
    "/swagger.json": (
        ["swagger", "openapi", "paths"],
        Severity.MEDIUM,
        "API documentation exposed: swagger.json",
    ),
    "/graphql": (
        ["__schema", "query", "mutation"],
        Severity.MEDIUM,
        "GraphQL introspection enabled",
    ),
    "/api/": (
        ["{", '"data"', '"result"', '"items"'],
        Severity.MEDIUM,
        "Unauthenticated API endpoint accessible",
    ),
}


async def _is_port_responsive(url: str, timeout: int = 3) -> bool:
    """Quick HTTP connectivity check — returns True only if the URL responds
    with any HTTP status within *timeout* seconds.  Uses a dedicated session
    (no shared connector) so failures do not pollute the main session."""
    _ssl_ctx = ssl_lib.create_default_context()
    _ssl_ctx.check_hostname = False
    _ssl_ctx.verify_mode    = ssl_lib.CERT_NONE
    try:
        _conn = aiohttp.TCPConnector(ssl=_ssl_ctx)
        async with aiohttp.ClientSession(connector=_conn) as s:
            async with s.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as r:
                return r.status < 600
    except Exception:
        return False

# ── Endpoint classification sets ──────────────────────────────────────────────

# Always INFO — standard, expected public paths
INFO_PATHS = {
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
}

# Paths whose 200 response always merits ≥ MEDIUM regardless of content-type
ADMIN_PATH_PREFIXES = (
    "/phpmyadmin", "/adminer", "/admin", "/administrator", "/wp-admin",
    "/console", "/h2-console", "/dashboard", "/debug",
)

# Non-HTML extensions that are suspicious even if served as text/html
NON_HTML_EXTENSIONS = (
    ".zip", ".sql", ".bak", ".tar", ".gz", ".env",
    ".config", ".yml", ".yaml", ".json", ".xml",
    ".log", ".key", ".pem", ".DS_Store",
)

# Paths that elevate severity to CRITICAL when found accessible
CRITICAL_KEYWORDS = (".env", ".git", "backup", "dump.sql", ".DS_Store", "wp-config")

# Expected body keywords per admin-panel path prefix.
ADMIN_KEYWORDS: dict = {
    "/phpmyadmin":    ["phpmyadmin", "mysql", "pma"],
    "/adminer":       ["adminer", "mysql", "database"],
    "/console":       ["console", "rails", "groovy", "shell"],
    "/h2-console":    ["h2", "H2", "java", "H2 Console"],
    "/wp-admin":      ["wordpress", "wp-login", "WordPress"],
    "/graphql":       ["graphql", "__schema", "query"],
    "/swagger":       ["swagger", "openapi", "Swagger UI"],
    "/openapi":       ["openapi", "swagger", "paths"],
    "/debug":         ["debug", "exception", "traceback", "stack"],
    "/server-status": ["apache", "server status", "requests/sec"],
    "/phpinfo":       ["phpinfo", "PHP Version", "Configuration"],
    "/info.php":      ["phpinfo", "PHP Version"],
}

# ── Security headers ──────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "X-Frame-Options": "Clickjacking protection",
    "Content-Security-Policy": "XSS/injection policy",
    "X-XSS-Protection": "Browser XSS filter",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Strict-Transport-Security": "HTTPS enforcement",
    "Referrer-Policy": "Referrer info control",
    "Permissions-Policy": "Feature policy",
}

# Severity for each missing header
SECURITY_HEADER_SEVERITIES: dict = {
    "Content-Security-Policy":   "high",
    "Strict-Transport-Security": "high",
    "X-Content-Type-Options":    "medium",
    "X-Frame-Options":           "medium",
    "X-XSS-Protection":          "low",
    "Referrer-Policy":           "low",
    "Permissions-Policy":        "low",
}

# Remediation per header
SECURITY_HEADER_REMEDIATION: dict = {
    "Content-Security-Policy": (
        "Add a Content-Security-Policy header to restrict resource loading. "
        "Example: Content-Security-Policy: default-src 'self'"
    ),
    "Strict-Transport-Security": (
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload "
        "to enforce HTTPS on all connections."
    ),
    "X-Content-Type-Options": (
        "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing attacks."
    ),
    "X-Frame-Options": (
        "Add X-Frame-Options: DENY (or SAMEORIGIN) to prevent clickjacking. "
        "Alternatively use CSP frame-ancestors directive."
    ),
    "X-XSS-Protection": (
        "Add X-XSS-Protection: 1; mode=block for legacy browser XSS filter support."
    ),
    "Referrer-Policy": (
        "Add Referrer-Policy: strict-origin-when-cross-origin to control "
        "referrer information leakage."
    ),
    "Permissions-Policy": (
        "Add Permissions-Policy header to restrict access to browser features "
        "like camera, microphone, and geolocation."
    ),
}

_EMAIL_HARVEST_PATHS = ["/", "/contact"]


async def harvest_emails_from_pages(session, base_url: str) -> list:
    """
    Fetch 2 pages concurrently (2 s timeout each) and return de-duplicated
    email addresses. Errors on individual paths are silently swallowed.
    """
    all_emails: set = set()

    async def _fetch(path: str):
        try:
            url = base_url.rstrip("/") + path
            async with session.get(
                url, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=2),
            ) as resp:
                body = await resp.text(errors="ignore")
                if isinstance(body, str):
                    all_emails.update(extract_emails(body))
        except Exception:
            pass

    await asyncio.gather(*[_fetch(p) for p in _EMAIL_HARVEST_PATHS], return_exceptions=True)
    return sorted(all_emails)


async def check_endpoint(session, base_url: str, path: str) -> dict:
    """Probe a single path. Returns actual body byte count, not Content-Length header.
    Also returns the first 8 KB of decoded body text for keyword verification."""
    url = base_url.rstrip("/") + path
    try:
        async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3)) as resp:
            ct = resp.headers.get("Content-Type", "").lower()
            body = await resp.content.read(512 * 1024)
            return {
                "url": url,
                "status": resp.status,
                "size": resp.headers.get("Content-Length", "?"),
                "content_type": ct,
                "content_length": len(body),
                "body_text": body[:8192].decode("utf-8", errors="ignore"),
                "interesting": resp.status in (200, 301, 302, 403, 401),
            }
    except Exception:
        return {
            "url": url, "status": 0, "content_type": "",
            "content_length": 0, "body_text": "", "interesting": False,
        }


async def get_baseline_body_size(session, base_url: str) -> int:
    """Fetch a guaranteed-nonexistent path to establish a soft-404 baseline."""
    canary_url = base_url.rstrip("/") + "/this-path-does-not-exist-12345-godseye"
    try:
        async with session.get(
            canary_url,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=4),
        ) as resp:
            body = await resp.content.read(512 * 1024)
            return len(body)
    except Exception:
        return -1


async def get_homepage_body_size(session, base_url: str, console=None) -> int:
    """Fetch the homepage (GET /) to establish a content baseline."""
    homepage_url = base_url.rstrip("/") + "/"

    try:
        async with session.get(
            homepage_url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=4),
        ) as resp:
            body = await resp.content.read(512 * 1024)
            return len(body)
    except Exception as e:
        logger.debug("homepage baseline aiohttp failed (%s): %s — trying requests fallback",
                     base_url, str(e)[:120])

    try:
        import requests as req_lib
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = req_lib.get(homepage_url, verify=False, timeout=3, allow_redirects=True)
        return len(r.content)
    except Exception as e2:
        logger.debug("homepage baseline requests fallback also failed (%s): %s",
                     base_url, str(e2)[:120])
        return -1


async def check_security_headers(session, url: str) -> dict:
    """
    Check security headers. Returns:
      missing — list of {header, description, severity}
      present — list of header names
      headers — raw response headers (lowercased keys)
    """
    missing = []
    present = []
    raw_headers: dict = {}
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            for h, desc in SECURITY_HEADERS.items():
                if h.lower() in raw_headers:
                    present.append(h)
                else:
                    missing.append({
                        "header": h,
                        "description": desc,
                        "severity": SECURITY_HEADER_SEVERITIES.get(h, "low"),
                    })
    except Exception as e:
        return {"error": str(e), "missing": [], "present": [], "headers": {}}
    return {"missing": missing, "present": present, "headers": raw_headers}


_CSRF_PATTERNS = [
    r'<input[^>]+name=["\'](_token|csrf_token|csrfmiddlewaretoken|__RequestVerificationToken'
    r'|authenticity_token|_csrf|csrf|token)["\']',
    r'<meta[^>]+name=["\']csrf-token["\']',
]


async def _page_has_csrf(session, url: str) -> bool:
    """Return True if the base page contains a CSRF token field."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=4),
                               allow_redirects=True) as resp:
            if resp.status not in (200, 302):
                return False
            body = await resp.text(errors="ignore")
            for pat in _CSRF_PATTERNS:
                if re.search(pat, body, re.IGNORECASE):
                    return True
    except Exception:
        pass
    return False


_SQLI_ERROR_PATTERNS = [
    r"sql syntax.*mysql",           r"warning.*mysql_",     r"mysqlexception",
    r"valid mysql result",          r"check the manual that corresponds",
    r"ora-\d{5}",                   r"oracle.*error",       r"pls-\d{5}",
    r"unclosed quotation mark",     r"quoted string not properly",
    r"microsoft ole db provider for odbc",
    r"adodb\.field error",          r"sqlserver jdbc driver",
    r"postgresql.*error",           r"psycopg2",
    r"sqlite.*error",               r"syntax error.*sql",
    r"mysql_fetch",                 r"sql syntax",
    r"syntax error near",           r"pg_query",
    r"warning: mysql",              r"sqlite3\.operationalerror",
]

# CDN/WAF providers — SQLi probes will never produce genuine DB errors
_CDN_WAF_NAMES = frozenset([
    "cloudflare", "vercel", "akamai", "fastly", "cloudfront", "cdn",
    "netlify", "imperva", "incapsula", "sucuri",
])

# Parameters to test for SQLi (up to 3, 2 requests each = 6 max)
_SQLI_TEST_PARAMS = ["id", "search", "q"]


async def check_sqli(session, url: str, waf: str = "") -> list:
    """
    Differential SQL injection probe.

    Tests up to 3 common parameter names (id, search, q).
    For each: baseline request + single-quote injection.
    Only flags when: status or body size changes AND SQL error keyword present.
    Skips CDN/WAF sites and CSRF-protected pages.
    """
    findings: list = []

    # Guard 1: never probe through CDN / WAF
    if any(w in (waf or "").lower() for w in _CDN_WAF_NAMES):
        return findings

    # Guard 2: skip when CSRF tokens are required
    if await _page_has_csrf(session, url):
        return findings

    for param in _SQLI_TEST_PARAMS:
        # Step 1: fetch normal baseline
        baseline_url = f"{url}?{param}=1"
        try:
            async with session.get(baseline_url,
                                   timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status in (400, 403, 405):
                    continue
                baseline_status = r.status
                baseline_body   = await r.text(errors="ignore")
                baseline_size   = len(baseline_body)
        except Exception:
            continue

        # Step 2: inject unbalanced quote
        probe_url = f"{url}?{param}=1'"
        try:
            async with session.get(probe_url,
                                   timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status in (400, 403, 405):
                    continue
                probe_status = r.status
                probe_body   = await r.text(errors="ignore")
                probe_size   = len(probe_body)
        except Exception:
            continue

        # Differential check
        status_changed = probe_status != baseline_status
        size_changed   = abs(probe_size - baseline_size) > 500
        if not (status_changed or size_changed):
            continue

        # SQL error keyword confirmation
        for pattern in _SQLI_ERROR_PATTERNS:
            if re.search(pattern, probe_body, re.IGNORECASE):
                findings.append({
                    "url":           probe_url,
                    "param":         param,
                    "payload":       "'",
                    "error_pattern": pattern,
                })
                break

        if findings:
            break  # one confirmed finding is enough

    return findings


async def check_xss_reflection(session, url: str, waf: str = "") -> list:
    """
    Basic reflected XSS check on 2 common query parameters.

    Only runs on HTTP/HTTPS ports (80/443) and skips CDN/WAF-protected sites.
    Probes q and search params with a script tag payload; flags when the
    payload appears unescaped in the response body.
    """
    findings: list = []

    # Never probe CDN/WAF sites
    if any(w in (waf or "").lower() for w in _CDN_WAF_NAMES):
        return findings

    payload = "<script>xss</script>"
    encoded = urllib.parse.quote(payload)

    for param in ["q", "search"]:
        probe_url = f"{url}?{param}={encoded}"
        try:
            async with session.get(probe_url,
                                   timeout=aiohttp.ClientTimeout(total=3),
                                   allow_redirects=True) as r:
                if r.status == 200:
                    body = await r.text(errors="ignore")
                    # Unescaped payload in response → reflected XSS
                    if payload.lower() in body.lower():
                        findings.append({
                            "url":     probe_url,
                            "param":   param,
                            "payload": payload,
                        })
                        break
        except Exception:
            pass

    return findings


async def run_web_analysis(state: EngagementState, console=None) -> dict:
    recon = state.recon_data
    web_results = recon.get("web", {})

    if not web_results:
        state.add_note("No web services found, skipping web module")
        return {}

    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    def _add(finding):
        if not any(x.title == finding.title for x in state.findings):
            state.add_finding(finding)

    # ── Step 0: filter to only responsive ports ───────────────────────────────
    # Ports 80/443 always use an 8s timeout and are NEVER dropped — slow sites
    # like spacex.com still respond, just not within 3s.
    # Ports 8080/8443 and others keep the 3s fast-fail timeout.
    log("Checking port responsiveness...")
    _resp_results = await asyncio.gather(
        *[
            _is_port_responsive(
                winfo.get("url", ""),
                timeout=8 if int(port) in (80, 443) else 3,
            )
            for port, winfo in web_results.items()
        ],
        return_exceptions=True,
    )
    responsive: dict = {
        port: winfo
        for (port, winfo), ok in zip(web_results.items(), _resp_results)
        # Never drop standard HTTP/HTTPS ports regardless of check outcome
        if ok is True or int(port) in (80, 443)
    }
    for port in web_results:
        if port not in responsive:
            log(f"Port {port} did not respond — skipped")

    if not responsive:
        state.add_note("No responsive web ports found")
        return {}

    ssl_ctx = ssl_lib.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode    = ssl_lib.CERT_NONE
    web_data: dict = {}

    # ── Inner analysis — wrapped in global 90 s ceiling ───────────────────────
    async def _do_all():
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
        ) as session:

            async def _analyze_port(port, winfo):
                base_url  = winfo.get("url", "")
                _port_int = int(port) if str(port).isdigit() else 0

                port_data = {
                    "base_url":         base_url,
                    "technologies":     winfo.get("technologies", []),
                    "waf":              winfo.get("waf"),
                    "security_headers": {},
                    "endpoints":        [],
                    "sqli_findings":    [],
                }

                # ── PART 1: Security headers — individual findings per header ─
                log(f"Checking security headers: {base_url}")
                sec_hdr_result = await check_security_headers(session, base_url)
                port_data["security_headers"] = sec_hdr_result

                # Raw response headers (from the security-header request)
                _raw_hdrs = sec_hdr_result.get("headers", {})

                # Individual finding per missing header
                for mh in sec_hdr_result.get("missing", []):
                    hname = mh["header"]
                    hsev  = mh.get("severity", "low")
                    hrem  = SECURITY_HEADER_REMEDIATION.get(hname, f"Add {hname} header.")
                    _add(Finding(
                        title=f"Missing security header: {hname}",
                        severity=Severity(hsev),
                        description=(
                            f"{hname} is absent on {base_url}. "
                            f"Purpose: {mh['description']}."
                        ),
                        evidence=f"Header not present in HTTP response from {base_url}",
                        mitre_tactic="Initial Access",
                        mitre_technique="T1190 - Exploit Public-Facing Application",
                        remediation=hrem,
                        phase="web",
                    ))

                # ── PART 3: Clickjacking detection ───────────────────────────
                _csp_value    = _raw_hdrs.get("content-security-policy", "")
                _x_frame      = _raw_hdrs.get("x-frame-options", "")
                if not _x_frame and "frame-ancestors" not in _csp_value.lower():
                    _add(Finding(
                        title="Clickjacking protection missing",
                        severity=Severity.MEDIUM,
                        description=(
                            "Neither X-Frame-Options nor CSP frame-ancestors directive "
                            "is set. The page can be embedded in iframes on "
                            "attacker-controlled sites, enabling clickjacking attacks."
                        ),
                        evidence=(
                            "Neither X-Frame-Options nor CSP frame-ancestors directive "
                            f"found in response headers from {base_url}"
                        ),
                        mitre_tactic="Defense Evasion",
                        mitre_technique="T1185 - Browser Session Hijacking",
                        remediation=(
                            "Add 'X-Frame-Options: DENY' or "
                            "'Content-Security-Policy: frame-ancestors \\'none\\'' "
                            "to all HTTP responses."
                        ),
                        phase="web",
                    ))

                # ── PART 6: Information disclosure in headers ─────────────────

                # Server version disclosure
                _server_hdr = _raw_hdrs.get("server", "")
                if _server_hdr and re.search(r'\w+/\d+[\d.]+', _server_hdr):
                    _add(Finding(
                        title=f"Server version disclosed: {_server_hdr[:80]}",
                        severity=Severity.LOW,
                        description=(
                            f"The Server header reveals product version information: "
                            f"'{_server_hdr}'. Attackers can use this to target "
                            "known CVEs for that specific version."
                        ),
                        evidence=f"Server: {_server_hdr}",
                        mitre_tactic="Discovery",
                        mitre_technique="T1082 - System Information Discovery",
                        remediation=(
                            "Configure the web server to omit or genericise the "
                            "Server header (e.g. 'server_tokens off' in Nginx)."
                        ),
                        phase="web",
                    ))

                # X-Powered-By
                _xpb = _raw_hdrs.get("x-powered-by", "")
                if _xpb:
                    _add(Finding(
                        title=f"Technology stack exposed via X-Powered-By: {_xpb[:80]}",
                        severity=Severity.LOW,
                        description=(
                            f"The X-Powered-By header discloses the server-side "
                            f"technology: '{_xpb}'. This aids attacker fingerprinting."
                        ),
                        evidence=f"X-Powered-By: {_xpb}",
                        mitre_tactic="Discovery",
                        mitre_technique="T1082 - System Information Discovery",
                        remediation=(
                            "Remove the X-Powered-By header. In PHP: "
                            "'expose_php = Off'. In Express: "
                            "'app.disable(\"x-powered-by\")'."
                        ),
                        phase="web",
                    ))

                # X-Generator
                _xgen = _raw_hdrs.get("x-generator", "")
                if _xgen:
                    _add(Finding(
                        title=f"CMS generator exposed via X-Generator: {_xgen[:80]}",
                        severity=Severity.INFO,
                        description=(
                            f"The X-Generator header reveals the CMS or framework: "
                            f"'{_xgen}'."
                        ),
                        evidence=f"X-Generator: {_xgen}",
                        mitre_tactic="Discovery",
                        mitre_technique="T1082 - System Information Discovery",
                        remediation="Remove the X-Generator response header.",
                        phase="web",
                    ))

                # X-AspNet-Version
                _aspnet = _raw_hdrs.get("x-aspnet-version", "")
                if _aspnet:
                    _add(Finding(
                        title=f"ASP.NET version disclosed: {_aspnet[:80]}",
                        severity=Severity.LOW,
                        description=(
                            f"The X-AspNet-Version header reveals the .NET version: "
                            f"'{_aspnet}'."
                        ),
                        evidence=f"X-AspNet-Version: {_aspnet}",
                        mitre_tactic="Discovery",
                        mitre_technique="T1082 - System Information Discovery",
                        remediation=(
                            "Add <httpRuntime enableVersionHeader='false' /> to "
                            "Web.config to suppress this header."
                        ),
                        phase="web",
                    ))

                # Via (proxy/CDN infrastructure exposure)
                _via = _raw_hdrs.get("via", "")
                if _via:
                    _add(Finding(
                        title=f"Proxy/CDN infrastructure exposed via Via header",
                        severity=Severity.INFO,
                        description=(
                            f"The Via header discloses proxy or CDN infrastructure: "
                            f"'{_via}'."
                        ),
                        evidence=f"Via: {_via}",
                        mitre_tactic="Discovery",
                        mitre_technique="T1590 - Gather Victim Network Information",
                        remediation=(
                            "Configure your load balancer or CDN to strip the "
                            "Via header before forwarding responses."
                        ),
                        phase="web",
                    ))

                # X-Backend-Server (may reveal internal IPs)
                _xbs = _raw_hdrs.get("x-backend-server", "")
                if _xbs:
                    _add(Finding(
                        title=f"Backend server exposed: {_xbs[:80]}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The X-Backend-Server header reveals an internal server "
                            f"address: '{_xbs}'. This may expose internal network topology."
                        ),
                        evidence=f"X-Backend-Server: {_xbs}",
                        mitre_tactic="Discovery",
                        mitre_technique="T1590 - Gather Victim Network Information",
                        remediation=(
                            "Remove the X-Backend-Server header from responses. "
                            "Configure your reverse proxy to not pass this header."
                        ),
                        phase="web",
                    ))

                # ── Cookie security + tech fingerprint (4 s) ──────────────────
                log(f"Analyzing cookies: {base_url}")
                try:
                    async with session.get(
                        base_url,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=4),
                    ) as _cookie_resp:
                        try:
                            _set_cookie_hdrs = list(_cookie_resp.headers.getall("Set-Cookie", []))
                        except (AttributeError, TypeError):
                            _sc = (_cookie_resp.headers.get("Set-Cookie") or "")
                            _set_cookie_hdrs = [_sc] if _sc else []

                    _cookie_techs, _cookie_sec = analyze_set_cookie_headers(_set_cookie_hdrs)
                    for _tn in dict.fromkeys(_cookie_techs):
                        _add(Finding(
                            title=f"Technology fingerprint from cookie: {_tn}",
                            severity=Severity.INFO,
                            description=(
                                f"Server-side technology detected from session cookie name: {_tn}. "
                                "Consider using generic cookie names to reduce information disclosure."
                            ),
                            evidence=f"Session cookie name pattern on {base_url}",
                            mitre_tactic="Discovery",
                            mitre_technique="T1082 - System Information Discovery",
                            remediation="Use opaque, technology-neutral cookie names.",
                            phase="web",
                        ))
                    for _cf in _cookie_sec:
                        _add(Finding(
                            title=_cf["title"],
                            severity=Severity(_cf["severity"]),
                            description=_cf["description"],
                            evidence=_cf["evidence"],
                            mitre_tactic="Credential Access",
                            mitre_technique="T1539 - Steal Web Session Cookie",
                            remediation=_cf["remediation"],
                            phase="web",
                        ))
                except Exception:
                    pass

                # Email harvesting — 2 pages, concurrent, 2 s each
                log(f"Harvesting emails from {base_url}...")
                try:
                    _port_emails = await harvest_emails_from_pages(session, base_url)
                    if _port_emails:
                        _existing = set(state.recon_data.get("emails", []))
                        _existing.update(_port_emails)
                        state.recon_data["emails"] = sorted(_existing)
                        log(f"Emails: {', '.join(_port_emails[:5])}"
                            + (f" (+{len(_port_emails)-5} more)" if len(_port_emails) > 5 else ""))
                except Exception:
                    pass

                # ── Baselines (4 s each) ──────────────────────────────────────
                log(f"Fetching baselines for {base_url}...")
                baseline_size = await get_baseline_body_size(session, base_url)
                homepage_size = await get_homepage_body_size(session, base_url, console)

                if homepage_size == -1:
                    try:
                        import requests as _req_sync
                        import urllib3 as _urllib3_sync
                        _urllib3_sync.disable_warnings(
                            _urllib3_sync.exceptions.InsecureRequestWarning)
                        _sync_r = _req_sync.get(
                            base_url.rstrip("/") + "/",
                            verify=False, timeout=3, allow_redirects=True,
                        )
                        homepage_size = len(_sync_r.content)
                    except Exception:
                        pass

                # ── PART 4: Endpoint enumeration with body-confirmed checks ──
                log(f"Endpoint enumeration ({len(SENSITIVE_ENDPOINTS)} paths)...")
                _ep_sem = asyncio.Semaphore(15)

                async def _cep(ep):
                    async with _ep_sem:
                        return await check_endpoint(session, base_url, ep)

                ep_results = await asyncio.gather(
                    *[_cep(ep) for ep in SENSITIVE_ENDPOINTS], return_exceptions=True
                )
                found_endpoints = [
                    r for r in ep_results
                    if isinstance(r, dict) and r.get("interesting") and r.get("status", 0) != 404
                ]
                port_data["endpoints"] = found_endpoints

                for ep in found_endpoints:
                    if ep.get("status") != 200:
                        continue
                    path        = ep["url"].replace(base_url, "") or "/"
                    ct          = ep.get("content_type", "")
                    body_len    = ep.get("content_length", 0)
                    body_text   = ep.get("body_text", "")
                    is_html     = "text/html" in ct
                    has_bin_ext = path.lower().endswith(NON_HTML_EXTENSIONS)
                    _bn = ""
                    if baseline_size >= 0:
                        _bn += f" | canary: {baseline_size}B"
                    if homepage_size >= 0:
                        _bn += f" | homepage: {homepage_size}B"
                    evidence = (f"HTTP {ep['status']} | "
                                f"Content-Type: {ct or 'unknown'} | "
                                f"Body: {body_len} bytes{_bn}")

                    # ── Body-keyword confirmed findings (ENDPOINT_CONFIRMATIONS)
                    matched_confirmation = False
                    for conf_path, (keywords, conf_sev, conf_title) in ENDPOINT_CONFIRMATIONS.items():
                        if path == conf_path or path.startswith(conf_path):
                            if any(kw.lower() in body_text.lower() for kw in keywords):
                                _add(Finding(
                                    title=conf_title,
                                    severity=conf_sev,
                                    description=(
                                        f"Sensitive path {path} is accessible at "
                                        f"{ep['url']} and response body confirms "
                                        "real exposure (keyword match)."
                                    ),
                                    evidence=(
                                        f"{evidence} | "
                                        f"Confirmed by keyword match in response body"
                                    ),
                                    mitre_tactic="Discovery",
                                    mitre_technique="T1083 - File and Directory Discovery",
                                    remediation=(
                                        f"Remove or restrict access to {path}. "
                                        "Apply server-level deny rules."
                                    ),
                                    phase="web",
                                ))
                                matched_confirmation = True
                                break
                    if matched_confirmation:
                        continue

                    if is_html and has_bin_ext:
                        continue

                    if path in INFO_PATHS:
                        _add(Finding(
                            title=f"Informational endpoint: {path}",
                            severity=Severity.INFO,
                            description=f"Standard public path accessible: {ep['url']}",
                            evidence=evidence,
                            mitre_tactic="Discovery",
                            mitre_technique="T1083 - File and Directory Discovery",
                            remediation="Ensure no sensitive data is disclosed in this file.",
                            phase="web",
                        ))
                        continue

                    if path.startswith(ADMIN_PATH_PREFIXES):
                        if is_html:
                            if baseline_size >= 0 and abs(body_len - baseline_size) < 1000:
                                continue
                            if homepage_size >= 0 and abs(body_len - homepage_size) < 5000:
                                continue
                        _kw_match = True
                        for kw_prefix, kw_list in ADMIN_KEYWORDS.items():
                            if path.startswith(kw_prefix):
                                if body_len < 500:
                                    _kw_match = False
                                elif not any(kw.lower() in body_text.lower() for kw in kw_list):
                                    _kw_match = False
                                break
                        if not _kw_match:
                            continue
                        sev  = Severity.MEDIUM if is_html else Severity.HIGH
                        desc = (
                            f"Admin panel returning "
                            f"{'distinct HTML (likely a real login page)' if is_html else 'non-HTML content (possible direct access)'}: "
                            f"{ep['url']}"
                        )
                        _add(Finding(
                            title=f"Admin panel accessible: {path}",
                            severity=sev, description=desc, evidence=evidence,
                            mitre_tactic="Discovery",
                            mitre_technique="T1083 - File and Directory Discovery",
                            remediation="Restrict admin paths via IP allowlist or strong authentication.",
                            phase="web",
                        ))
                        continue

                    if is_html and not (has_bin_ext and body_len > 5000):
                        continue
                    if homepage_size >= 0 and abs(body_len - homepage_size) < 1000:
                        continue

                    sev = (Severity.CRITICAL
                           if any(kw in path for kw in CRITICAL_KEYWORDS)
                           else Severity.HIGH)
                    _add(Finding(
                        title=f"Sensitive endpoint exposed: {path}",
                        severity=sev,
                        description=f"Sensitive path is publicly accessible: {ep['url']}",
                        evidence=evidence,
                        mitre_tactic="Discovery",
                        mitre_technique="T1083 - File and Directory Discovery",
                        remediation=(
                            "Restrict access or remove sensitive files from the "
                            "web root. Apply server-level deny rules."
                        ),
                        phase="web",
                    ))

                # ── SQLi probe (skips CDN/WAF automatically) ──────────────────
                waf = winfo.get("waf") or "Generic"
                log(f"SQLi probe: {base_url}")
                port_data["sqli_findings"] = await check_sqli(session, base_url, waf=waf)
                for sqli in port_data["sqli_findings"]:
                    _add(Finding(
                        title=f"Possible SQL injection: {sqli['param']} parameter",
                        severity=Severity.CRITICAL,
                        description=f"SQL error triggered at {sqli['url']}",
                        evidence=f"Payload: {sqli['payload']} | Pattern: {sqli['error_pattern']}",
                        mitre_tactic="Initial Access",
                        mitre_technique="T1190 - Exploit Public-Facing Application",
                        remediation="Use parameterized queries / prepared statements.",
                        cvss=9.8,
                        phase="web",
                    ))

                # ── PART 7: XSS reflection check (ports 80/443 only) ─────────
                if _port_int in (80, 443):
                    log(f"XSS reflection probe: {base_url}")
                    xss_results = await check_xss_reflection(session, base_url, waf=waf)
                    for xss in xss_results:
                        _add(Finding(
                            title=f"Reflected XSS: {xss['param']} parameter",
                            severity=Severity.HIGH,
                            description=(
                                f"User input in the '{xss['param']}' query parameter "
                                "is reflected in the response body without HTML encoding. "
                                "An attacker can inject arbitrary scripts."
                            ),
                            evidence=(
                                f"Payload '<script>xss</script>' reflected unescaped "
                                f"at {xss['url']}"
                            ),
                            mitre_tactic="Initial Access",
                            mitre_technique="T1059.007 - JavaScript",
                            remediation=(
                                "HTML-encode all user-controlled input before rendering. "
                                "Use a Content-Security-Policy to block inline scripts."
                            ),
                            cvss=6.1,
                            phase="web",
                        ))

                web_data[str(port)] = port_data

            # ── All ports concurrently, each with a hard 45 s ceiling ─────────
            async def _safe_analyze(port, winfo):
                try:
                    await asyncio.wait_for(_analyze_port(port, winfo), timeout=45)
                except asyncio.TimeoutError:
                    log(f"[yellow]Port {port} analysis timed out (>45s) — skipping[/yellow]")
                except Exception as exc:
                    logger.debug("Port %s analysis error: %s", port, exc)

            await asyncio.gather(
                *[_safe_analyze(port, winfo) for port, winfo in responsive.items()]
            )

    # Global 90 s ceiling
    try:
        await asyncio.wait_for(_do_all(), timeout=90)
    except asyncio.TimeoutError:
        if console:
            console.print("  [yellow]⚡ Web analysis hit 90s global limit — returning partial results[/yellow]")

    state.web_data = web_data
    state.add_note(f"Web analysis complete on {len(web_data)} ports")
    return web_data
