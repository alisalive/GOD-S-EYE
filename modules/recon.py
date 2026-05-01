"""
Recon Module — powered by GOD'S EYE with fallback to built-in scanner.
"""

import asyncio
import socket
import re
import os
import sys
from pathlib import Path
from core.orchestrator import EngagementState, Finding, Severity

# ── GOD'S EYE path setup ──────────────────────────────────────────────────────
def _add_gods_eye(path: str = None):
    candidates = [
        path,
        os.environ.get("GODS_EYE_PATH"),
        r"C:\Users\User\Documents\GODs_EYE",
        str(Path.home() / "Documents" / "GODs_EYE"),
    ]
    for c in candidates:
        if c and os.path.isdir(c) and c not in sys.path:
            sys.path.insert(0, c)
            return True
    return False

_add_gods_eye()

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 139, 443, 445,
                8080, 8443, 8888, 9200,
                3000, 3306, 5432, 6379, 27017]

STEALTH_PORTS = [22, 25, 53, 80, 443, 8080]


def get_service_name(port: int) -> str:
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kpasswd",
        636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
        1521: "Oracle", 3268: "GC-LDAP", 3269: "GC-LDAPS",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
        9200: "Elasticsearch", 27017: "MongoDB",
    }
    return services.get(port, f"port-{port}")


async def port_scan(target: str, ports: list = None, timeout: float = 1.0,
                    stealth: bool = False) -> dict:
    if ports is None:
        ports = STEALTH_PORTS if stealth else COMMON_PORTS

    if stealth:
        timeout = max(timeout, 3.0)

    open_ports = {}

    async def check_port(port):
        try:
            if stealth:
                await asyncio.sleep(0.1)
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=0.5)
                banner = data.decode("utf-8", errors="ignore").strip()[:100]
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True, banner
        except Exception:
            return port, False, ""

    if stealth:
        # Sequential in stealth mode
        for p in ports:
            result = await check_port(p)
            if result[1]:
                open_ports[result[0]] = {"service": get_service_name(result[0]), "banner": result[2]}
    else:
        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, tuple) and result[1]:
                port, _, banner = result
                open_ports[port] = {"service": get_service_name(port), "banner": banner}

    return open_ports


def dns_lookup(target: str) -> dict:
    result = {"hostname": target, "ips": [], "reverse": []}
    try:
        info = socket.getaddrinfo(target, None)
        ips = list(set(i[4][0] for i in info))
        result["ips"] = ips
        for ip in ips[:3]:
            try:
                rev = socket.gethostbyaddr(ip)[0]
                result["reverse"].append(rev)
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result


async def _fetch_response_headers(url: str) -> dict:
    """HEAD request to *url*; returns response headers as a plain dict.

    Used to supplement wdata['headers'] when the GOD'S EYE bridge doesn't
    populate that field, so that header-presence vuln filters work correctly.
    Returns an empty dict on any failure — callers treat that as 'unknown'.
    """
    if not url or not isinstance(url, str):
        return {}
    import aiohttp
    import ssl as ssl_lib
    try:
        ssl_ctx = ssl_lib.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_lib.CERT_NONE
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_ctx),
            timeout=aiohttp.ClientTimeout(total=3),
        ) as session:
            async with session.head(url, allow_redirects=True) as resp:
                return dict(resp.headers)
    except Exception:
        return {}


def _sync_check_redirect(url: str) -> bool:
    """Synchronous fallback redirect check using the requests library.

    Used when the aiohttp probe returns a non-redirect (e.g. Cloudflare
    serves a 200 challenge page to aiohttp but a proper 301 to requests).
    Returns True on any exception — benefit of the doubt, suppress finding.
    """
    try:
        import requests as req_lib
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = req_lib.get(url, allow_redirects=False, timeout=3, verify=False)
        if r.status_code in (301, 302, 307, 308):
            loc = r.headers.get("Location", "")
            return loc.lower().startswith("https://")
    except Exception:
        return True  # can't confirm — assume redirect, suppress finding
    return False


async def _check_https_redirect(target: str, port: int) -> bool:
    """Return True if an HTTP request to this port receives a 301/302/307/308
    redirect whose Location starts with 'https://'.  Used to suppress the
    'HTTPS not used' false positive on sites that properly enforce HTTPS.

    Strategy:
    1. aiohttp probe  — fast async check, ssl=False to avoid TLS handshake noise
    2. requests fallback (thread executor) — Cloudflare and some CDNs return a
       200 challenge page to aiohttp but issue a proper 301 to a stock UA;
       the synchronous probe uses a different TLS stack and User-Agent.

    Returns True on any unrecoverable exception so network errors suppress
    the finding rather than surface it as a false positive.
    """
    import aiohttp
    url = f"http://{target}" if port == 80 else f"http://{target}:{port}"
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=5),
        ) as session:
            async with session.get(url, allow_redirects=False) as resp:
                if resp.status in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    return location.lower().startswith("https://")
                # Non-redirect from aiohttp — try requests fallback
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, _sync_check_redirect, url)
    except Exception:
        # aiohttp failed entirely — try requests fallback before giving up
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _sync_check_redirect, url)
        except Exception:
            return True  # both probes failed — suppress finding


async def web_fingerprint_fallback(target: str, port: int = 80, ssl: bool = False) -> dict:
    """Fallback web fingerprinting when GOD'S EYE is unavailable."""
    import aiohttp
    import ssl as ssl_lib

    TECH_FINGERPRINTS = {
        "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
        "Joomla": [r"Joomla!", r"/components/com_"],
        "Drupal": [r"Drupal", r"/sites/default/"],
        "Laravel": [r"laravel_session", r"Laravel"],
        "Django": [r"csrfmiddlewaretoken", r"django"],
        "React": [r"react\.production\.min\.js", r"__NEXT_DATA__", r"data-reactroot"],
        "Angular": [r"ng-version", r"angular\.min\.js"],
        "Vue.js": [r"vue\.runtime", r"__vue__"],
        "Apache": [r"Apache/", r"Server: Apache"],
        "Nginx": [r"nginx/", r"Server: nginx"],
        "IIS": [r"Microsoft-IIS", r"X-Powered-By: ASP.NET"],
        "PHP": [r"X-Powered-By: PHP", r"PHPSESSID"],
    }

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "ModSecurity": ["mod_security", "NAXSI", "modsec"],
        "Sucuri": ["sucuri", "x-sucuri-id"],
        "Imperva": ["imperva", "incapsula", "visid_incap"],
        "AWS WAF": ["awselb", "x-amzn-requestid"],
        "Akamai": ["akamai", "ak_bmsc"],
        "F5 BIG-IP": ["bigipserver", "f5_cspm"],
        "Barracuda": ["barra_counter_session", "barracuda_"],
    }

    proto = "https" if ssl or port == 443 else "http"
    url = f"{proto}://{target}:{port}" if port not in (80, 443) else f"{proto}://{target}"

    result = {
        "url": url, "status_code": None, "server": "", "technologies": [],
        "waf": None, "headers": {}, "error": None,
        "technologies_detailed": [], "waf_results": [], "cves": [], "vulns": [],
        "_body": "",
    }

    try:
        ssl_ctx = ssl_lib.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_lib.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        timeout = aiohttp.ClientTimeout(total=8)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(url, allow_redirects=True) as resp:
                result["status_code"] = resp.status
                result["server"] = resp.headers.get("Server", "")
                result["headers"] = dict(resp.headers)
                body = await resp.text(errors="ignore")
                result["_body"] = body
                all_content = body + str(resp.headers)

                for tech, patterns in TECH_FINGERPRINTS.items():
                    for pattern in patterns:
                        if re.search(pattern, all_content, re.IGNORECASE):
                            if tech not in result["technologies"]:
                                result["technologies"].append(tech)
                            break

                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                for waf, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if any(sig in v for v in headers_lower.values()):
                            result["waf"] = waf
                            break
                    if result["waf"]:
                        break
    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def _check_ssl_expiry_days(host: str, port: int = 443) -> int:
    """Connect to *host*:*port* with TLS and return days until the certificate expires.

    Uses Python's built-in ssl module to retrieve the real certificate, so the
    result always reflects the current cert — not a cached or estimated value.

    Returns:
        ≥ 0  — days until expiry (0 means expiring today)
        -1   — check failed (host unreachable, TLS handshake error, etc.)
    """
    import ssl as _ssl_mod
    import socket
    import datetime

    try:
        ctx = _ssl_mod.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                not_after = cert.get("notAfter", "")
                if not_after:
                    # e.g. "Apr 17 12:00:00 2026 GMT"
                    exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                    return (exp - now).days
    except Exception:
        pass
    return -1


async def run_recon(state: EngagementState, console=None,
                    stealth: bool = False, gods_eye_path: str = None) -> dict:
    target = state.target

    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    log(f"DNS lookup: {target}")
    dns = dns_lookup(target)

    port_list = STEALTH_PORTS if stealth else COMMON_PORTS
    timeout = 3.0 if stealth else 2.0
    log(f"Port scan ({len(port_list)} ports, stealth={stealth})...")
    open_ports = await port_scan(target, port_list, timeout=timeout, stealth=stealth)

    web_results = {}

    # ── Phase 1: concurrent GOD'S EYE scans ──────────────────────────────────
    http_ports = {
        port: info for port, info in open_ports.items()
        if info["service"] in ("HTTP", "HTTP-Alt", "HTTPS", "HTTPS-Alt")
    }

    async def _tcp_ok(port):
        """3-second TCP pre-check — returns True only if the port responds."""
        try:
            _, _w = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=3
            )
            _w.close()
            try:
                await _w.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    if http_ports:
        tcp_checks = await asyncio.gather(
            *[_tcp_ok(p) for p in http_ports], return_exceptions=True
        )
        responsive_http = {
            p for p, ok in zip(http_ports, tcp_checks) if ok is True
        }
    else:
        responsive_http = set()

    async def _scan_one_port(port, info):
        """Run GOD'S EYE (or fallback) for a single port; returns (port, result)."""
        svc = info["service"]
        ssl = svc in ("HTTPS", "HTTPS-Alt")
        proto = "https" if ssl else "http"
        url = (
            f"{proto}://{target}:{port}"
            if port not in (80, 443)
            else f"{proto}://{target}"
        )
        log(f"GOD'S EYE scan on {url}...")
        try:
            from modules.gods_eye_bridge import run_gods_eye_scan, gods_eye_to_recon_format
            ge_result = await asyncio.wait_for(
                run_gods_eye_scan(url, gods_eye_path), timeout=20
            )
            result = gods_eye_to_recon_format(ge_result, port, ssl)
            if ge_result.get("error"):
                log(f"  GOD'S EYE fallback: {ge_result['error']}")
                result = await asyncio.wait_for(
                    web_fingerprint_fallback(target, port, ssl), timeout=8
                )
            return port, result
        except asyncio.TimeoutError:
            log(f"  GOD'S EYE timed out for {url} — using fallback")
        except Exception as e:
            log(f"  Fingerprint fallback ({e})")
        # Fallback path
        try:
            result = await asyncio.wait_for(
                web_fingerprint_fallback(target, port, ssl), timeout=8
            )
            return port, result
        except Exception:
            return port, None

    async def _run_all_scans():
        tasks = [_scan_one_port(p, http_ports[p]) for p in responsive_http]
        if not tasks:
            return
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, tuple) and r[1] is not None:
                web_results[r[0]] = r[1]

    try:
        await asyncio.wait_for(_run_all_scans(), timeout=30)
    except asyncio.TimeoutError:
        log("GOD'S EYE scans hit 30s ceiling — using partial results")

    # ── Fallback: ensure ports 80/443 always have a web_results entry ──────────
    # Only standard HTTP (80) and HTTPS (443) get stubs — alternate ports like
    # 8080/8443 are frequently slow or unresponsive on the same host that caused
    # the 30s ceiling, and adding stubs for them would make Phase 3 web analysis
    # hang for minutes waiting on timeouts.
    _FALLBACK_PORTS = {80: ("http", False), 443: ("https", True)}
    for _p, (_proto, _ssl) in _FALLBACK_PORTS.items():
        if _p not in open_ports:
            continue  # port wasn't open — nothing to do
        if _p in web_results:
            continue  # already populated by GOD'S EYE — leave as-is
        _url = f"{_proto}://{target}"
        web_results[_p] = {
            "url": _url,
            "port": _p,
            "vulns": [],
            "technologies": [],
            "headers": {},
            "cves": [],
            "waf": None,
            "status_code": None,
        }

    recon_data = {
        "dns": dns,
        "open_ports": open_ports,
        "web": web_results,
        "stealth": stealth,
    }

    state.recon_data = recon_data

    # ── Generate findings ─────────────────────────────────────────────────────
    # Each entry: title, severity, description, remediation
    DANGEROUS_PORTS = {
        22: (
            "SSH exposed on port 22",
            Severity.MEDIUM,
            "SSH service is publicly accessible. Brute-force and credential-stuffing "
            "attacks are common against internet-facing SSH.",
            "Restrict SSH access to trusted IPs via firewall. Disable password "
            "authentication; use key-based auth only. Consider moving to a non-standard port.",
        ),
        23: (
            "Telnet exposed on port 23",
            Severity.HIGH,
            "Telnet transmits all data (including credentials) in plaintext. "
            "Any network observer can capture login sessions.",
            "Disable Telnet immediately and replace with SSH. "
            "Block port 23 at the perimeter firewall.",
        ),
        139: (
            "NetBIOS exposed on port 139",
            Severity.HIGH,
            "NetBIOS/SMB on port 139 enables Windows file sharing and is a frequent "
            "vector for lateral movement and credential relay attacks.",
            "Block port 139 at the perimeter firewall. Disable NetBIOS over TCP/IP "
            "unless required for internal Windows networking.",
        ),
        445: (
            "SMB port exposed (ransomware risk)",
            Severity.HIGH,
            "SMB port 445 is directly reachable from the internet. Exploits like "
            "EternalBlue (MS17-010) target this port and have been used by WannaCry, "
            "NotPetya, and other ransomware campaigns.",
            "Block SMB port 445 at the perimeter firewall immediately. Apply MS17-010 "
            "patches. Disable SMBv1. Use VPN for legitimate file-share access.",
        ),
        3000: (
            "Development port exposed (port 3000)",
            Severity.MEDIUM,
            "Port 3000 is commonly used by Node.js applications, Grafana dashboards, "
            "and development servers. Development services often lack proper hardening.",
            "Ensure this is not a development server exposed to the internet. "
            "Restrict access to port 3000 via firewall if the service is internal.",
        ),
        3306: (
            "MySQL port publicly exposed",
            Severity.HIGH,
            "MySQL database port is directly reachable from the internet. "
            "Database services should never be exposed publicly; they are prime targets "
            "for brute-force and data exfiltration attacks.",
            "Block port 3306 at the firewall. Bind MySQL to 127.0.0.1 only. "
            "Use SSH tunnels or a VPN for remote database access.",
        ),
        3389: (
            "RDP exposed on port 3389",
            Severity.MEDIUM,
            "Remote Desktop Protocol is publicly accessible. RDP has a history of "
            "critical vulnerabilities (BlueKeep, DejaBlue) and is targeted by ransomware operators.",
            "Restrict RDP to trusted IPs via firewall. Enable NLA. "
            "Apply all Windows security updates. Use VPN for remote access.",
        ),
        5432: (
            "PostgreSQL port publicly exposed",
            Severity.HIGH,
            "PostgreSQL database port is directly reachable from the internet. "
            "Exposed database ports enable brute-force attacks and potential data theft.",
            "Block port 5432 at the firewall. Bind PostgreSQL to 127.0.0.1 only "
            "or use pg_hba.conf to restrict connections to trusted IPs.",
        ),
        5900: (
            "VNC exposed on port 5900",
            Severity.HIGH,
            "VNC (Virtual Network Computing) is publicly accessible. "
            "VNC is often weakly authenticated and provides full graphical desktop access.",
            "Block port 5900 at the firewall. If VNC is needed, tunnel it over SSH. "
            "Enable strong VNC authentication; avoid password-only auth.",
        ),
        6379: (
            "Redis port exposed (unauthenticated access likely)",
            Severity.CRITICAL,
            "Redis on port 6379 is publicly reachable. Redis has no authentication "
            "by default and attackers can read/write all keys, execute Lua code, "
            "and in some configurations achieve remote code execution via CONFIG SET.",
            "Block port 6379 at the firewall immediately. Enable Redis authentication "
            "(requirepass). Bind Redis to 127.0.0.1 only. Disable dangerous commands "
            "(CONFIG, DEBUG, SLAVEOF) in production.",
        ),
        8888: (
            "Jupyter Notebook port exposed",
            Severity.CRITICAL,
            "Jupyter Notebook on port 8888 is publicly accessible. An unauthenticated "
            "or weakly authenticated Jupyter server grants full code execution on the "
            "host — attackers can run arbitrary Python/shell commands.",
            "Block port 8888 at the firewall immediately. Enable token or password "
            "authentication. Run Jupyter only on localhost and use an SSH tunnel "
            "for remote access. Never expose Jupyter directly to the internet.",
        ),
        9200: (
            "Elasticsearch port exposed (data leak risk)",
            Severity.CRITICAL,
            "Elasticsearch HTTP API on port 9200 is publicly reachable. Elasticsearch "
            "has no authentication by default; all stored indices are readable and "
            "writable by anyone. Billions of records have been leaked via exposed "
            "Elasticsearch clusters.",
            "Block port 9200 at the firewall immediately. Enable Elasticsearch "
            "security features (X-Pack/security). Use TLS and role-based access control. "
            "Never expose the Elasticsearch API directly to the internet.",
        ),
        27017: (
            "MongoDB port exposed (unauthenticated access likely)",
            Severity.CRITICAL,
            "MongoDB on port 27017 is publicly reachable. MongoDB has no authentication "
            "enabled by default; the entire database is readable and writable without "
            "credentials. Mass data breaches have exploited this configuration.",
            "Block port 27017 at the firewall immediately. Enable MongoDB authentication "
            "(--auth). Bind to 127.0.0.1 only. Apply security hardening checklist "
            "from the MongoDB documentation.",
        ),
    }
    for port, (title, sev, desc, rem) in DANGEROUS_PORTS.items():
        if port in open_ports:
            banner = open_ports[port].get("banner", "N/A")
            f = Finding(
                title=title,
                severity=sev,
                description=desc,
                evidence=f"Port {port} open, banner: {banner}",
                mitre_tactic="Discovery",
                mitre_technique="T1046 - Network Service Scanning",
                remediation=rem,
                phase="recon",
            )
            if not any(x.title == f.title for x in state.findings):
                state.add_finding(f)

    def _add(finding):
        if not any(x.title == finding.title for x in state.findings):
            state.add_finding(finding)

    for port, wdata in web_results.items():
        # Pre-compute HTTPS-redirect flag.
        # Use the port number — not the stored URL — to identify HTTP ports,
        # because GOD'S EYE stores the *final* (post-redirect) URL.  For port 80
        # that redirects to HTTPS the stored URL already starts with "https://"
        # which would wrongly set _svc_is_http=False and skip the redirect check.
        redirects_to_https = False
        if port in (80, 8080):
            redirects_to_https = await _check_https_redirect(target, port)

        # If GOD'S EYE didn't populate response headers (the bridge omits them),
        # fetch them with a single HEAD request so header-presence filters work.
        if not wdata.get("headers"):
            wdata["headers"] = await _fetch_response_headers(wdata.get("url", ""))

        if wdata.get("waf"):
            _add(Finding(
                title=f"WAF detected: {wdata['waf']} on port {port}",
                severity=Severity.INFO,
                description=f"{wdata['waf']} WAF protecting port {port}. Bypass attempts needed.",
                evidence="WAF signatures found in response headers",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562 - Impair Defenses",
                phase="recon",
            ))

        # GOD'S EYE CVE findings
        for cve in wdata.get("cves", []):
            if cve.get("cvss_score", 0) >= 7.0:
                sev = Severity.CRITICAL if cve["cvss_score"] >= 9.0 else Severity.HIGH
                _add(Finding(
                    title=f"{cve['cve_id']}: {cve['technology']} vulnerability",
                    severity=sev,
                    description=cve["description"][:300],
                    evidence=f"Detected version matches affected range: {cve['affected_versions']}",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1190 - Exploit Public-Facing Application",
                    remediation=f"Upgrade {cve['technology']} to version {cve['fixed_version']} or later.",
                    cvss=cve["cvss_score"],
                    phase="recon",
                ))

        # GOD'S EYE vuln findings
        for vuln in wdata.get("vulns", []):
            vuln_name    = vuln.get("name") or ""
            evidence     = vuln.get("evidence") or ""
            vuln_name_lc = vuln_name.lower()
            server_hdr   = wdata.get("server") or ""
            body_text    = wdata.get("_body") or ""
            technologies = wdata.get("technologies") or []

            # ── False-positive guards ─────────────────────────────────────────

            # 1. "HTTPS not used / missing / not enforced / HTTP only"
            #    Match any vuln whose name suggests HTTPS is absent.
            #    • URL already https:// OR port is 443/8443 → skip unconditionally
            #    • HTTP port that redirects → HTTPS → skip
            #    • Any other HTTP port where redirect check failed → skip
            #      (redirect check returns True on exception → benefit of doubt)
            _is_https_vuln = (
                "https" in vuln_name_lc
                and any(w in vuln_name_lc for w in ("not", "miss", "no ", "lack", "without", "enforc"))
            ) or "http only" in vuln_name_lc
            if _is_https_vuln:
                _url_is_https = wdata.get("url", "").startswith("https://")
                if _url_is_https or port in (443, 8443):
                    continue
                if redirects_to_https:   # True for HTTP ports that redirect, or on exception
                    continue

            # 2. "Open redirect" — only flag when Location is an absolute URL
            #    pointing to a host OTHER than the target.
            #    Relative paths (/foo), same-domain URLs, and missing Location
            #    are all skipped.
            if "redirect" in vuln_name_lc:
                loc_match = re.search(r'[Ll]ocation:\s*(\S+)', evidence)
                if loc_match:
                    location = loc_match.group(1)
                    is_absolute = (location.startswith("http://") or
                                   location.startswith("https://"))
                    is_external = target not in location
                    if not (is_absolute and is_external):
                        continue
                else:
                    # No Location in evidence — can't verify, skip
                    continue

            # 3. "jQuery outdated / vulnerable" — skip when jQuery not on the page
            if "jquery" in vuln_name_lc:
                jquery_present = (
                    any("jquery" in t.lower() for t in technologies)
                    or "jquery" in body_text.lower()
                )
                if not jquery_present:
                    continue

            # 4. "Server version disclosed / banner" — skip when Server header
            #    contains only a product name with no version number.
            if "server" in vuln_name_lc and any(w in vuln_name_lc for w in ("version", "banner", "disclos")):
                if not re.search(r'\w+/\d+[\d.]+', server_hdr):
                    continue

            # 5. "X-Content-Type-Options missing / not set"
            #    Primary check: case-insensitive header lookup in wdata["headers"].
            #    Fallback: if "nosniff" appears in the evidence the header IS set —
            #    some scanner backends embed the header value rather than storing
            #    it in the headers dict.
            if "x-content-type-options" in vuln_name_lc:
                _resp_hdrs_lc = {k.lower() for k in wdata.get("headers", {}).keys()}
                _xcto_in_hdrs = "x-content-type-options" in _resp_hdrs_lc
                _xcto_in_evidence = "nosniff" in evidence.lower()
                if _xcto_in_hdrs or _xcto_in_evidence:
                    continue

            # 6. "SSL certificate expiring soon" — GOD'S EYE flags within 90 days;
            #    we re-verify by actually connecting and checking the real expiry.
            #    Only report when the cert expires within 30 days.  Suppressed when:
            #    • days_left > 30 — cert is valid for >30 days (A+ sites like openai.com)
            #    • days_left == -1 — live check failed (benefit of doubt → suppress)
            if "ssl" in vuln_name_lc and "expir" in vuln_name_lc:
                _ssl_days = _check_ssl_expiry_days(target)
                if _ssl_days < 0 or _ssl_days > 30:
                    continue

            sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                       "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO}
            sev = sev_map.get(vuln.get("severity", "INFO"), Severity.INFO)
            _add(Finding(
                title=vuln_name,
                severity=sev,
                description=evidence[:300],
                evidence=evidence,
                mitre_tactic="Discovery",
                mitre_technique="T1083 - File and Directory Discovery",
                remediation=vuln.get("recommendation", ""),
                phase="recon",
            ))

    # ── Post-processing false-positive filter ────────────────────────────────
    # Applied after all vuln-loop processing so runtime checks that may have
    # failed silently earlier get one guaranteed last chance.

    import requests as _req
    import urllib3 as _urllib3
    _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)

    https_ports_open = [p for p in web_results.keys() if p in (443, 8443)]

    # Collect XCTO findings so we can re-verify each affected port live.
    xcto_by_port: dict = {}   # port → Finding (last one wins per port)

    findings_to_remove = []
    for f in state.findings:
        if not f.title:
            continue
        title_lc = f.title.lower()

        # "HTTPS not used" — meaningless when the same host has 443/8443 open
        if "https" in title_lc and "not" in title_lc and "used" in title_lc:
            if https_ports_open:
                findings_to_remove.append(f)
            continue

        # "X-Content-Type-Options missing" — remove now, re-add only if confirmed
        if "x-content-type-options" in title_lc:
            # Match the finding back to a port so we verify the right URL
            for p, wdata in web_results.items():
                if str(p) in f.title or p in (
                    int(x) for x in str(f.title).split() if x.isdigit()
                ) or True:  # check all web ports if we can't isolate
                    xcto_by_port[p] = f
                    break
            findings_to_remove.append(f)

    for f in findings_to_remove:
        try:
            state.findings.remove(f)
        except ValueError:
            pass

    # Re-verify X-Content-Type-Options with a live requests.head() call
    verified_xcto_ports: set = set()
    for p, wdata in web_results.items():
        if p in verified_xcto_ports:
            continue
        url = wdata.get("url", "")
        if not url:
            continue
        # Prefer HTTPS URL for the live check
        check_url = url if url.startswith("https://") else f"https://{target}"
        try:
            resp = _req.head(check_url, verify=False, timeout=3,
                             allow_redirects=True)
            hdrs_lc = {k.lower() for k in resp.headers}
            if "x-content-type-options" not in hdrs_lc:
                # Header is genuinely absent — restore the finding (once only)
                _xcto_title = "X-Content-Type-Options missing"
                if not any(f.title == _xcto_title for f in state.findings):
                    state.add_finding(Finding(
                        title=_xcto_title,
                        severity=Severity.MEDIUM,
                        description=(
                            "The X-Content-Type-Options: nosniff header is not set. "
                            "Browsers may MIME-sniff responses away from the declared "
                            "content-type, enabling drive-by download attacks."
                        ),
                        evidence=f"Header absent in live HEAD {check_url}",
                        mitre_tactic="Defense Evasion",
                        mitre_technique="T1562 - Impair Defenses",
                        remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
                        phase="recon",
                    ))
            verified_xcto_ports.add(p)
        except Exception:
            # Live check failed — restore original finding conservatively
            if p in xcto_by_port:
                original = xcto_by_port[p]
                if not any(f.title == original.title for f in state.findings):
                    state.add_finding(original)
            verified_xcto_ports.add(p)

    # ── Global deduplication: keep only the first occurrence of each title ──────
    seen_titles: set = set()
    unique_findings = []
    for f in state.findings:
        if f.title not in seen_titles:
            seen_titles.add(f.title)
            unique_findings.append(f)
    state.findings = unique_findings

    state.recon_data.update({"gods_eye_used": True})
    state.add_note(f"Recon complete: {len(open_ports)} open ports, {len(web_results)} web services")
    return recon_data
