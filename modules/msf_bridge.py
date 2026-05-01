"""
Metasploit Bridge — maps findings to Metasploit modules.
Attaches msf_module field to Finding objects and provides lookup table.
"""

from core.orchestrator import EngagementState, Finding

# Pattern (lowercase substring) → MSF module path
MSF_MODULE_MAP = [
    # CVE / specific vulnerabilities
    ("ms17-010",            "exploit/windows/smb/ms17_010_eternalblue"),
    ("eternalblue",         "exploit/windows/smb/ms17_010_eternalblue"),
    ("heartbleed",          "auxiliary/scanner/ssl/openssl_heartbleed"),
    ("shellshock",          "exploit/multi/http/apache_mod_cgi_bash_env_exec"),
    ("log4shell",           "exploit/multi/http/log4shell_header_injection"),
    ("log4j",               "exploit/multi/http/log4shell_header_injection"),
    ("struts",              "exploit/multi/http/struts2_content_type_ognl"),
    ("cve-2021-44228",      "exploit/multi/http/log4shell_header_injection"),
    ("cve-2014-0160",       "auxiliary/scanner/ssl/openssl_heartbleed"),
    ("cve-2017-0144",       "exploit/windows/smb/ms17_010_eternalblue"),
    ("cve-2021-34527",      "exploit/windows/smb/ms17_010_eternalblue"),
    ("printnightmare",      "exploit/windows/dcerpc/cve_2021_1675_printspooler"),
    ("bluekeep",            "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"),
    ("cve-2019-0708",       "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"),
    # Default credentials
    ("ftp: anonymous",      "auxiliary/scanner/ftp/anonymous"),
    ("default credentials: ftp", "auxiliary/scanner/ftp/anonymous"),
    ("default credentials: ssh", "auxiliary/scanner/ssh/ssh_login"),
    ("default credentials: http", "auxiliary/scanner/http/http_login"),
    ("default credentials: telnet", "auxiliary/scanner/telnet/telnet_login"),
    # Web vulnerabilities
    ("sql injection",       "auxiliary/scanner/http/blind_sql_query"),
    ("sqli",                "auxiliary/scanner/http/blind_sql_query"),
    ("xss",                 "auxiliary/scanner/http/xss"),
    ("lfi",                 "auxiliary/scanner/http/lfi"),
    ("rfi",                 "auxiliary/scanner/http/rfi"),
    ("ssrf",                "auxiliary/scanner/http/ssrf"),
    ("rce",                 "exploit/multi/http/php_cgi_arg_injection"),
    ("directory traversal", "auxiliary/scanner/http/dir_traversal"),
    ("path traversal",      "auxiliary/scanner/http/dir_traversal"),
    # SMB
    ("smb signing",         "auxiliary/scanner/smb/smb_signing"),
    ("smb",                 "auxiliary/scanner/smb/smb_ms17_010"),
    ("ntlm relay",          "auxiliary/server/capture/smb"),
    # LDAP
    ("ldap anonymous",      "auxiliary/scanner/ldap/ldap_login"),
    ("anonymous bind",      "auxiliary/scanner/ldap/ldap_login"),
    # Authentication
    ("kerberos",            "auxiliary/scanner/kerberos/kerberos_enumusers"),
    ("as-rep",              "auxiliary/gather/kerberos_enumusers"),
    # Network services
    ("open rdp",            "auxiliary/scanner/rdp/rdp_scanner"),
    ("rdp",                 "auxiliary/scanner/rdp/rdp_scanner"),
    ("vnc",                 "auxiliary/scanner/vnc/vnc_login"),
    ("redis",               "auxiliary/scanner/redis/redis_server"),
    ("mongodb",             "auxiliary/scanner/mongodb/mongodb_login"),
    ("mysql",               "auxiliary/scanner/mysql/mysql_login"),
    ("mssql",               "auxiliary/scanner/mssql/mssql_login"),
    ("postgresql",          "auxiliary/scanner/postgres/postgres_login"),
    ("elasticsearch",       "auxiliary/scanner/elasticsearch/indices_enum"),
    ("memcached",           "auxiliary/scanner/memcached/memcached_amp"),
    # JWT
    ("jwt",                 "auxiliary/scanner/http/jwt_token_manipulation"),
    ("alg: none",           "auxiliary/scanner/http/jwt_token_manipulation"),
    # TLS/SSL
    ("weak ssl",            "auxiliary/scanner/ssl/ssl_version"),
    ("tls",                 "auxiliary/scanner/ssl/ssl_version"),
    ("self-signed",         "auxiliary/scanner/ssl/cert"),
    # Directory brute force hits
    ("exposed admin panel", "auxiliary/scanner/http/http_login"),
    ("exposed backup",      "auxiliary/scanner/http/backup_file"),
    ("exposed config",      "auxiliary/scanner/http/files_dir"),
]


def get_msf_module(finding: Finding) -> str:
    """Return MSF module path for a finding, or empty string if none found."""
    text = (finding.title + " " + finding.description).lower()
    for pattern, module in MSF_MODULE_MAP:
        if pattern in text:
            return module
    return ""


def annotate_findings_with_msf(state: EngagementState) -> dict:
    """
    Attach msf_module attribute to all Finding objects.
    Returns summary dict: {module_path: [finding_title, ...]}
    """
    summary = {}
    for finding in state.findings:
        module = get_msf_module(finding)
        finding.msf_module = module  # type: ignore[attr-defined]
        if module:
            summary.setdefault(module, []).append(finding.title)

    if not hasattr(state, "msf_data"):
        state.msf_data = {}
    state.msf_data = {"modules": summary, "total": len(summary)}
    return state.msf_data


def print_msf_table(state: EngagementState, console) -> None:
    """Print a Rich table showing finding → MSF module mappings."""
    from rich.table import Table
    from rich import box

    mapped = [
        (f, getattr(f, "msf_module", ""))
        for f in state.findings
        if getattr(f, "msf_module", "")
    ]
    if not mapped:
        console.print("  [dim]No Metasploit modules mapped[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold", padding=(0, 1))
    t.add_column("Finding", min_width=35)
    t.add_column("MSF Module", min_width=45, style="cyan")
    for finding, module in mapped:
        t.add_row(finding.title[:50], module)
    console.print(t)


def run_msf_bridge(state: EngagementState, console=None) -> dict:
    """Annotate findings and optionally display MSF table."""
    data = annotate_findings_with_msf(state)
    if console:
        mapped_count = len([f for f in state.findings if getattr(f, "msf_module", "")])
        console.print(
            f"  [dim]→[/dim] Metasploit: {mapped_count} finding(s) mapped to MSF modules"
        )
    return data
