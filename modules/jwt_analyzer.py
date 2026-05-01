"""
JWT Analyzer — detects and analyzes JSON Web Tokens in HTTP responses.
MITRE ATT&CK: T1550.001 - Use Alternate Authentication Material: Application Access Token
"""

import asyncio
import base64
import json
import re
from core.orchestrator import EngagementState, Finding, Severity

JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
)

WEAK_SECRETS = [
    "secret", "password", "123456", "key", "jwt_secret",
    "your-256-bit-secret", "changeme", "supersecret", "mykey",
    "jwttoken", "tokensecret", "mysecret", "test", "admin",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
]

SENSITIVE_FIELDS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key", "credit_card",
    "ssn", "social_security", "dob", "date_of_birth", "cvv",
}


def _b64_decode(s: str) -> bytes:
    """Base64url decode with padding."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def decode_jwt(token: str) -> tuple:
    """Decode JWT without verification. Returns (header, payload, valid)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}, {}, False
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload, True
    except Exception:
        return {}, {}, False


def check_alg_none(header: dict) -> bool:
    """Check if JWT uses alg:none (critical vulnerability)."""
    alg = str(header.get("alg", "")).lower()
    return alg in ("none", "null", "")


def check_weak_hs256(token: str, header: dict) -> str:
    """Try common weak secrets for HS256. Returns secret if found, else ''."""
    if header.get("alg", "").upper() != "HS256":
        return ""
    try:
        import hmac
        import hashlib
        parts = token.split(".")
        msg = f"{parts[0]}.{parts[1]}".encode()
        sig = _b64_decode(parts[2])
        for secret in WEAK_SECRETS:
            expected = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            if expected == sig:
                return secret
    except Exception:
        pass
    return ""


def check_expiry(payload: dict) -> dict:
    """Check JWT expiry. Returns {expired: bool, exp_ts: int}."""
    import time
    exp = payload.get("exp")
    if exp is None:
        return {"no_expiry": True, "expired": False}
    now = time.time()
    return {"no_expiry": False, "expired": exp < now, "exp_ts": exp}


def find_sensitive_payload_fields(payload: dict) -> list:
    """Return list of sensitive field names found in payload."""
    found = []
    for key in payload:
        if key.lower() in SENSITIVE_FIELDS:
            found.append(key)
    return found


def analyze_token(token: str, source: str, state: EngagementState) -> list:
    """Analyze a single JWT token and generate findings. Returns list of Finding."""
    header, payload, valid = decode_jwt(token)
    if not valid:
        return []

    findings = []
    alg = header.get("alg", "unknown")
    token_preview = token[:40] + "..."

    # 1. alg:none
    if check_alg_none(header):
        f = Finding(
            title="JWT: Algorithm None (Signature Bypass)",
            severity=Severity.CRITICAL,
            description=(
                "JWT token uses 'alg: none' which means the signature is not verified. "
                "An attacker can forge arbitrary tokens without a secret key."
            ),
            evidence=f"Source: {source} | alg={alg} | Token: {token_preview}",
            mitre_tactic="Defense Evasion",
            mitre_technique="T1550.001 - Application Access Token",
            remediation=(
                "Reject tokens with alg:none on the server side. "
                "Explicitly whitelist allowed algorithms (e.g., RS256 or HS256)."
            ),
            cvss=9.8,
            phase="jwt",
        )
        state.add_finding(f)
        findings.append(f)

    # 2. Weak HS256 secret
    weak_secret = check_weak_hs256(token, header)
    if weak_secret:
        f = Finding(
            title=f"JWT: Weak HS256 Secret ('{weak_secret}')",
            severity=Severity.CRITICAL,
            description=(
                f"JWT token signed with weak secret '{weak_secret}'. "
                "Attacker can forge tokens for any user."
            ),
            evidence=f"Source: {source} | Secret cracked: {weak_secret} | Token: {token_preview}",
            mitre_tactic="Credential Access",
            mitre_technique="T1550.001 - Application Access Token",
            remediation=(
                "Use a cryptographically random secret of at least 256 bits. "
                "Consider switching to RS256 (asymmetric signing)."
            ),
            cvss=9.1,
            phase="jwt",
        )
        state.add_finding(f)
        findings.append(f)

    # 3. RS256 → HS256 confusion note (INFO)
    if alg.upper() == "RS256":
        f = Finding(
            title="JWT: RS256 Algorithm — Verify HS256 Confusion Attack",
            severity=Severity.MEDIUM,
            description=(
                "JWT uses RS256. Test if server accepts HS256-signed tokens using "
                "the public key as the HMAC secret (algorithm confusion attack)."
            ),
            evidence=f"Source: {source} | alg=RS256 | Token: {token_preview}",
            mitre_tactic="Defense Evasion",
            mitre_technique="T1550.001 - Application Access Token",
            remediation=(
                "Explicitly enforce the expected algorithm on the server. "
                "Do not accept algorithm specified by the client."
            ),
            cvss=7.5,
            phase="jwt",
        )
        state.add_finding(f)
        findings.append(f)

    # 4. No expiry
    expiry_info = check_expiry(payload)
    if expiry_info.get("no_expiry"):
        f = Finding(
            title="JWT: No Expiration Claim (exp)",
            severity=Severity.MEDIUM,
            description=(
                "JWT token has no 'exp' claim, meaning it never expires. "
                "Stolen tokens remain valid indefinitely."
            ),
            evidence=f"Source: {source} | Payload keys: {list(payload.keys())} | Token: {token_preview}",
            mitre_tactic="Persistence",
            mitre_technique="T1550.001 - Application Access Token",
            remediation="Add 'exp' claim to all JWT tokens with a short TTL (e.g., 15 minutes).",
            cvss=5.3,
            phase="jwt",
        )
        state.add_finding(f)
        findings.append(f)

    # 5. Sensitive fields in payload
    sensitive = find_sensitive_payload_fields(payload)
    if sensitive:
        f = Finding(
            title=f"JWT: Sensitive Data in Payload ({', '.join(sensitive)})",
            severity=Severity.HIGH,
            description=(
                f"JWT payload contains sensitive fields: {', '.join(sensitive)}. "
                "JWT payload is base64-encoded (not encrypted) and readable by anyone."
            ),
            evidence=f"Source: {source} | Sensitive fields: {sensitive} | Token: {token_preview}",
            mitre_tactic="Collection",
            mitre_technique="T1550.001 - Application Access Token",
            remediation=(
                "Do not store sensitive data in JWT payload. "
                "Use JWE (encrypted JWT) if sensitive claims are required."
            ),
            cvss=6.5,
            phase="jwt",
        )
        state.add_finding(f)
        findings.append(f)

    return findings


async def analyze_jwt_in_response(
    url: str, headers: dict, body: str, state: EngagementState
) -> list:
    """
    Scan HTTP response headers and body for JWTs.
    headers: dict of response headers
    body: response body text
    Returns list of findings.
    """
    all_findings = []
    seen_tokens = set()

    def _check(text: str, source: str):
        for match in JWT_PATTERN.finditer(text):
            token = match.group(0)
            if token not in seen_tokens:
                seen_tokens.add(token)
                findings = analyze_token(token, source, state)
                all_findings.extend(findings)

    # Check Authorization header
    auth = headers.get("Authorization", "") or headers.get("authorization", "")
    if auth.startswith("Bearer "):
        _check(auth[7:], f"Authorization header @ {url}")

    # Check Set-Cookie headers
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            _check(val, f"Set-Cookie @ {url}")

    # Check response body
    if body:
        _check(body, f"Response body @ {url}")

    return all_findings


async def run_jwt_analysis(state: EngagementState, console=None) -> dict:
    """
    Scan all web analysis results for JWT tokens.
    Also checks web_data for stored response info.
    """
    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    total_found = 0
    total_analyzed = 0

    # Scan web_data responses stored by web.py
    for port_key, port_data in (state.web_data or {}).items():
        if not isinstance(port_data, dict):
            continue

        # Check response headers stored
        resp_headers = port_data.get("response_headers", {})
        resp_body = port_data.get("response_body", "")
        url = port_data.get("url", f"http://{state.target}:{port_key}/")

        findings = await analyze_jwt_in_response(url, resp_headers, resp_body, state)
        total_found += len(findings)
        if resp_headers or resp_body:
            total_analyzed += 1

    log(
        f"JWT analysis: {total_analyzed} endpoint(s) scanned, "
        f"{total_found} JWT issue(s) found"
    )

    data = {"scanned": total_analyzed, "issues": total_found}
    if not hasattr(state, "jwt_data"):
        state.jwt_data = {}
    state.jwt_data = data

    if total_found:
        state.add_note(f"JWT: {total_found} token security issue(s) found")

    return data
