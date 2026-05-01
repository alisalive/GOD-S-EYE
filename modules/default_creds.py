"""
Default Credentials Checker — tests discovered services for default credentials.
MITRE ATT&CK: T1078 - Valid Accounts
"""

import asyncio
import socket
from core.orchestrator import EngagementState, Finding, Severity

# (username, password) pairs per protocol
DEFAULT_CREDS = {
    "ftp": [
        ("anonymous", ""),
        ("anonymous", "anonymous"),
        ("ftp", "ftp"),
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
    ],
    "ssh": [
        ("root", "root"),
        ("root", "toor"),
        ("admin", "admin"),
        ("admin", "password"),
        ("pi", "raspberry"),
        ("ubuntu", "ubuntu"),
        ("user", "user"),
    ],
    "http": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
        ("administrator", "administrator"),
        ("admin", "1234"),
        ("admin", "admin123"),
        ("root", "root"),
    ],
    "telnet": [
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "password"),
        ("", ""),
    ],
}

SERVICE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "http",
    8080: "http",
    8443: "http",
    8888: "http",
}


def _mask(password: str) -> str:
    if not password:
        return "(empty)"
    return "****"


async def _test_ftp(host: str, port: int, username: str, password: str, timeout: float = 3.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not banner.decode(errors="ignore").startswith("220"):
            writer.close()
            return False
        writer.write(f"USER {username}\r\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.write(f"PASS {password}\r\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        return resp.decode(errors="ignore").startswith("230")
    except Exception:
        return False


async def _test_http_basic(host: str, port: int, username: str, password: str,
                            timeout: float = 3.0) -> bool:
    """Return True only when unauthenticated → 401/403 AND authenticated → 200.

    If the unauthenticated request already returns 200, the endpoint does not
    require authentication at all — skip as a false positive.
    """
    try:
        import aiohttp
        import base64
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            # Step 1: unauthenticated probe
            async with session.get(url, ssl=False, allow_redirects=False) as unauth:
                if unauth.status == 200:
                    # Server returns 200 without credentials — not a real auth wall
                    return False
                if unauth.status not in (401, 403):
                    # Unexpected status (redirect, 5xx…) — skip
                    return False

            # Step 2: authenticated attempt — only reached when unauth was 401/403
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers = {"Authorization": f"Basic {creds}"}
            async with session.get(url, headers=headers, ssl=False, allow_redirects=False) as auth:
                return auth.status == 200
    except Exception:
        return False


async def _test_ssh(host: str, port: int, username: str, password: str, timeout: float = 3.0) -> bool:
    try:
        import asyncssh
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host, port=port, username=username, password=password,
                known_hosts=None, login_timeout=timeout
            ),
            timeout=timeout + 1,
        )
        conn.close()
        return True
    except Exception:
        return False


async def _test_telnet(host: str, port: int, username: str, password: str, timeout: float = 3.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        # Read until login prompt
        data = b""
        for _ in range(10):
            try:
                chunk = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                data += chunk
                text = data.decode(errors="ignore").lower()
                if "login:" in text or "username:" in text:
                    writer.write(f"{username}\r\n".encode())
                    await writer.drain()
                    data = b""
                elif "password:" in text:
                    writer.write(f"{password}\r\n".encode())
                    await writer.drain()
                    await asyncio.sleep(1.0)
                    resp = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    writer.close()
                    resp_text = resp.decode(errors="ignore").lower()
                    return "$" in resp_text or "#" in resp_text or ">" in resp_text
            except asyncio.TimeoutError:
                break
        writer.close()
        return False
    except Exception:
        return False


async def check_service_default_creds(
    host: str, port: int, service: str, console=None
) -> list:
    """Test a single service for default credentials. Returns list of successful (user, pass) tuples."""
    found = []
    creds_list = DEFAULT_CREDS.get(service, [])

    for username, password in creds_list:
        success = False
        try:
            if service == "ftp":
                success = await _test_ftp(host, port, username, password)
            elif service == "ssh":
                success = await _test_ssh(host, port, username, password)
            elif service == "http":
                success = await _test_http_basic(host, port, username, password)
            elif service == "telnet":
                success = await _test_telnet(host, port, username, password)
        except Exception:
            pass

        if success:
            found.append((username, password))
            if console:
                console.print(
                    f"  [bold red]⚠ DEFAULT CREDS[/bold red] {service.upper()}:{port} "
                    f"→ {username}:{_mask(password)}"
                )
            break  # Stop at first success per service

    return found


async def run_default_creds_check(state: EngagementState, console=None) -> dict:
    """Check all open ports for default credentials."""
    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    open_ports = state.recon_data.get("open_ports", {})
    if not open_ports:
        log("No open ports — skipping default creds check")
        return {"checked": 0, "vulnerable": []}

    # Determine which ports to check
    targets = []
    for port_str, info in open_ports.items():
        port = int(port_str)
        service = SERVICE_PORTS.get(port)
        if not service:
            # Infer from detected service name
            svc_name = (info.get("service") or "").lower()
            if "ftp" in svc_name:
                service = "ftp"
            elif "ssh" in svc_name:
                service = "ssh"
            elif "telnet" in svc_name:
                service = "telnet"
            elif "http" in svc_name:
                service = "http"
        if service:
            targets.append((port, service))

    if not targets:
        log("No credential-testable services found")
        return {"checked": 0, "vulnerable": []}

    log(f"Testing default credentials on {len(targets)} service(s)...")

    host = state.target
    vulnerable = []

    tasks = [
        check_service_default_creds(host, port, service, console)
        for port, service in targets
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for (port, service), result in zip(targets, results):
        if isinstance(result, Exception) or not result:
            continue
        for username, password in result:
            entry = {
                "port": port,
                "service": service,
                "username": username,
                "password": _mask(password),
            }
            vulnerable.append(entry)
            state.add_finding(Finding(
                title=f"Default Credentials: {service.upper()} on port {port} ({username}:{_mask(password)})",
                severity=Severity.CRITICAL,
                description=(
                    f"Service {service.upper()} on port {port} accepts default credentials "
                    f"(username: {username}). Immediate remediation required."
                ),
                evidence=f"Successful login with {username}:{_mask(password)} on {host}:{port}",
                mitre_tactic="Initial Access",
                mitre_technique="T1078 - Valid Accounts",
                remediation=(
                    f"Change default credentials on {service.upper()} service immediately. "
                    "Enforce strong password policy and disable anonymous/default accounts."
                ),
                cvss=9.8,
                phase="default_creds",
            ))

    data = {"checked": len(targets), "vulnerable": vulnerable}
    if not hasattr(state, "default_creds_data"):
        state.default_creds_data = {}
    state.default_creds_data = data

    log(
        f"Default creds check: {len(targets)} services tested, "
        f"{len(vulnerable)} vulnerable"
    )
    state.add_note(
        f"Default creds: {len(vulnerable)} service(s) with default credentials found"
    )
    return data
