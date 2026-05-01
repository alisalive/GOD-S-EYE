"""
Report Generator — dark cybersecurity aesthetic HTML/JSON report.
"""

import json
import os
from datetime import datetime
from core.orchestrator import EngagementState, Severity

# ── Palette ───────────────────────────────────────────────────────────────────
C = {
    "bg":         "#0a0e1a",
    "card":       "#0d1117",
    "card2":      "#0f1923",
    "border":     "#1e2d40",
    "green":      "#00ff88",
    "cyan":       "#0ea5e9",
    "critical":   "#ff4444",
    "high":       "#ff8800",
    "medium":     "#ffcc00",
    "low":        "#3b82f6",
    "info":       "#6b7280",
    "text":       "#e6edf3",
    "muted":      "#8b949e",
    "dim":        "#3d4f61",
}

SEV_COLOR = {
    "critical": C["critical"],
    "high":     C["high"],
    "medium":   C["medium"],
    "low":      C["low"],
    "info":     C["info"],
}


def _escape(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _glow(color: str, spread: int = 8) -> str:
    return f"0 0 {spread}px {color}66, 0 0 {spread*2}px {color}33"


def _sev_badge(sev: str) -> str:
    color = SEV_COLOR.get(sev, C["info"])
    return (
        f"<span style='font-family:monospace;font-size:10px;font-weight:700;"
        f"text-transform:uppercase;padding:3px 8px;border-radius:3px;"
        f"background:{color}22;color:{color};border:1px solid {color}55;"
        f"box-shadow:{_glow(color,6)};letter-spacing:1px'>{sev}</span>"
    )


# ── Sub-sections ──────────────────────────────────────────────────────────────

def _screenshot_section(screenshots: dict) -> str:
    if not screenshots:
        return ""
    items = ""
    for port, ss in screenshots.items():
        if ss.get("error") or not ss.get("base64"):
            continue
        url = _escape(ss.get("url", f"Port {port}"))
        b64 = ss["base64"]
        items += f"""
        <div style='margin:14px 0;border:1px solid {C["border"]};border-radius:6px;overflow:hidden'>
          <div style='background:{C["card2"]};color:{C["muted"]};padding:7px 14px;
                      font-size:11px;font-family:monospace;border-bottom:1px solid {C["border"]}'>
            <span style='color:{C["green"]}'>$</span> screenshot :: {url}
          </div>
          <img src='data:image/png;base64,{b64}' style='width:100%;display:block' loading='lazy' alt='Screenshot {url}'>
        </div>"""
    if not items:
        return ""
    return f'<div class="section"><h2 class="section-title">&#x25b6; Screenshots</h2>{items}</div>'


def _cve_table_section(cve_data: dict) -> str:
    cves = cve_data.get("cves", [])
    if not cves:
        return ""
    rows = ""
    for cve in cves[:30]:
        score = cve.get("cvss_score", 0)
        sev   = cve.get("severity", "LOW").lower()
        color = SEV_COLOR.get(sev, C["info"])
        cve_id  = _escape(cve.get("cve_id", ""))
        ref     = _escape(cve.get("reference_url", "#"))
        tech    = _escape(cve.get("technology", ""))
        desc    = _escape(cve.get("description", ""))[:120]
        fixed   = _escape(cve.get("fixed_version", "N/A"))
        rows += f"""
        <tr class='trow'>
          <td><a href='{ref}' target='_blank'
                 style='color:{C["cyan"]};text-decoration:none;font-family:monospace;font-size:12px'>{cve_id}</a></td>
          <td style='color:{C["muted"]};font-size:12px'>{tech}</td>
          <td>{_sev_badge(sev)} <span style='color:{C["muted"]};font-size:11px;margin-left:4px'>{score}</span></td>
          <td style='font-size:12px;color:{C["muted"]}'>{desc}</td>
          <td style='font-family:monospace;font-size:11px;color:{C["green"]}'>{fixed}</td>
        </tr>"""
    return f"""
    <div class='section'>
      <h2 class='section-title'>&#x25b6; CVE Findings <span class='count-badge'>{len(cves)}</span></h2>
      <div style='overflow-x:auto'>
        <table class='data-table'>
          <thead><tr>
            <th>CVE ID</th><th>Technology</th><th>Severity / CVSS</th>
            <th>Description</th><th>Fixed In</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>"""


def _technologies_section(technologies: list) -> str:
    if not technologies:
        return ""
    _cat_order = {"Server": 0, "Language": 1, "CMS": 2, "Framework": 3, "Library": 4}
    sorted_techs = sorted(technologies,
                          key=lambda t: (_cat_order.get(t.get("category", ""), 9),
                                         t.get("name", "").lower()))
    _conf_color = {
        "high":   C["green"],
        "medium": C["medium"],
        "low":    C["muted"],
    }
    rows = ""
    for t in sorted_techs:
        name     = _escape(t.get("name", ""))
        version  = _escape(t.get("version", ""))
        conf     = t.get("confidence", "low")
        category = _escape(t.get("category", ""))
        evidence = _escape(t.get("evidence", ""))
        color    = _conf_color.get(conf, C["muted"])
        ver_badge = (
            f"<span style='font-family:monospace;font-size:10px;padding:1px 6px;"
            f"border-radius:3px;background:{C['cyan']}22;color:{C['cyan']};"
            f"border:1px solid {C['cyan']}33;margin-left:6px'>{version}</span>"
        ) if version else ""
        conf_badge = (
            f"<span style='font-family:monospace;font-size:10px;font-weight:700;"
            f"text-transform:uppercase;padding:2px 7px;border-radius:3px;"
            f"background:{color}22;color:{color};border:1px solid {color}44;"
            f"letter-spacing:1px'>{conf}</span>"
        )
        rows += f"""
        <tr class='trow'>
          <td style='font-weight:700;color:{C["text"]}'>{name}{ver_badge}</td>
          <td style='font-family:monospace;font-size:12px;color:{C["cyan"]}'>{category}</td>
          <td>{conf_badge}</td>
          <td style='font-size:11px;color:{C["muted"]};font-family:monospace'>{evidence}</td>
        </tr>"""
    return f"""
    <div class='section'>
      <h2 class='section-title'>&#x25b6; Detected Technologies
        <span class='count-badge'>{len(technologies)}</span>
      </h2>
      <p style='font-size:12px;color:{C["muted"]};font-family:monospace;margin-bottom:14px'>
        // CMS, frameworks, libraries and server-side stack identified via headers, body analysis and path probing
      </p>
      <div style='overflow-x:auto'>
        <table class='data-table'>
          <thead><tr>
            <th>Technology</th><th>Category</th><th>Confidence</th><th>Evidence</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>"""


def _emails_section(emails: list) -> str:
    if not emails:
        return ""
    _cyan  = C["cyan"]
    _card2 = C["card2"]
    _bdr   = C["border"]
    _muted = C["muted"]
    items = "".join(
        "<span style='font-family:monospace;font-size:12px;color:{cyan};"
        "background:{card2};border:1px solid {bdr};border-radius:3px;"
        "padding:3px 10px;margin:3px 4px;display:inline-block'>"
        "<a href='mailto:{addr}' style='color:{cyan};text-decoration:none'>"
        "{addr}</a></span>".format(
            cyan=_cyan, card2=_card2, bdr=_bdr, addr=_escape(e)
        )
        for e in emails[:60]
    )
    extra = (
        "<div style='font-size:11px;color:{muted};font-family:monospace;margin-top:8px'>"
        "// {n} more addresses not shown</div>".format(muted=_muted, n=len(emails) - 60)
    ) if len(emails) > 60 else ""
    return f"""
    <div class='section'>
      <h2 class='section-title'>&#x25b6; Harvested Emails
        <span class='count-badge'>{len(emails)}</span>
      </h2>
      <p style='font-size:12px;color:{C["muted"]};font-family:monospace;margin-bottom:14px'>
        // Email addresses discovered from homepage, /contact, /about, /robots.txt
      </p>
      <div>{items}</div>
      {extra}
    </div>"""


def _real_ip_section(real_ips: list) -> str:
    if not real_ips:
        return ""
    conf_color = {
        "confirmed": C["green"],
        "high":      C["critical"],
        "medium":    C["medium"],
        "low":       C["low"],
    }
    rows = ""
    for entry in real_ips:
        ip        = _escape(entry.get("ip", ""))
        method    = _escape(entry.get("method", ""))
        conf      = entry.get("confidence", "low")
        country   = _escape(entry.get("country", ""))
        last_seen = _escape(entry.get("last_seen", ""))
        verified  = entry.get("verified", False)
        color     = conf_color.get(conf, C["info"])
        verified_badge = (
            f"<span style='font-family:monospace;font-size:10px;padding:2px 6px;"
            f"border-radius:3px;background:{C['green']}22;color:{C['green']};"
            f"border:1px solid {C['green']}44;margin-left:6px'>&#x2714; verified</span>"
        ) if verified else ""
        rows += f"""
        <tr class='trow'>
          <td style='font-family:monospace;font-weight:700;color:{C["green"]}'>{ip}{verified_badge}</td>
          <td style='font-family:monospace;font-size:12px;color:{C["cyan"]}'>{method}</td>
          <td><span style='font-family:monospace;font-size:10px;font-weight:700;
                           text-transform:uppercase;padding:3px 8px;border-radius:3px;
                           background:{color}22;color:{color};border:1px solid {color}55;
                           letter-spacing:1px'>{conf}</span></td>
          <td style='font-size:12px;color:{C["muted"]}'>{country}</td>
          <td style='font-family:monospace;font-size:11px;color:{C["muted"]}'>{last_seen}</td>
        </tr>"""
    confirmed_count = sum(1 for e in real_ips if e.get("confidence") == "confirmed")
    badge_extra = (
        f"<span style='font-family:monospace;font-size:10px;padding:1px 7px;border-radius:10px;"
        f"background:{C['green']}22;color:{C['green']};border:1px solid {C['green']}44;"
        f"margin-left:8px'>{confirmed_count} confirmed</span>"
    ) if confirmed_count else ""
    return f"""
    <div class='section'>
      <h2 class='section-title'>&#x25b6; Real IP Discovery
        <span class='count-badge'>{len(real_ips)}</span>{badge_extra}
      </h2>
      <p style='font-size:12px;color:{C["muted"]};font-family:monospace;margin-bottom:14px'>
        // Potential origin IPs discovered behind CDN / WAF layer
      </p>
      <div style='overflow-x:auto'>
        <table class='data-table'>
          <thead><tr>
            <th>IP Address</th><th>Discovery Method</th><th>Confidence</th>
            <th>Country</th><th>Last Seen</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>"""


def _opsec_timeline_section(opsec_data: dict, mode: str) -> str:
    if mode != "redteam" or not opsec_data:
        return ""
    events = opsec_data.get("events", [])
    score  = opsec_data.get("score", 100)
    rating = opsec_data.get("rating", "N/A")
    score_color = C["green"] if score >= 70 else C["medium"] if score >= 40 else C["critical"]

    # CSS-only circular gauge via conic-gradient
    pct = max(0, min(100, score))
    gauge = f"""
    <div style='display:flex;align-items:center;gap:32px;margin-bottom:20px;flex-wrap:wrap'>
      <div style='position:relative;width:100px;height:100px'>
        <div style='width:100px;height:100px;border-radius:50%;
                    background:conic-gradient({score_color} {pct}%, {C["border"]} {pct}%);
                    display:flex;align-items:center;justify-content:center'>
          <div style='width:72px;height:72px;border-radius:50%;background:{C["card"]};
                      display:flex;flex-direction:column;align-items:center;justify-content:center'>
            <span style='font-size:20px;font-weight:700;color:{score_color};font-family:monospace'>{score}</span>
            <span style='font-size:9px;color:{C["muted"]}'>/100</span>
          </div>
        </div>
      </div>
      <div>
        <div style='font-size:22px;font-weight:700;color:{score_color};font-family:monospace'>{rating}</div>
        <div style='font-size:12px;color:{C["muted"]};margin-top:2px'>OPSEC Rating</div>
      </div>
    </div>"""

    rows = ""
    for ev in events:
        delta = ev.get("delta", 0)
        delta_str   = f"+{delta}" if delta > 0 else str(delta)
        delta_color = C["green"] if delta > 0 else C["critical"]
        rows += f"""
        <tr class='trow'>
          <td style='font-family:monospace;font-size:11px;color:{C["muted"]}'>{ev.get('timestamp', 0):.1f}s</td>
          <td style='font-size:13px'>{_escape(ev.get('label', ''))}</td>
          <td style='font-family:monospace;font-weight:700;color:{delta_color}'>{delta_str}</td>
          <td style='font-family:monospace;font-weight:700;color:{C["text"]}'>{ev.get('score_after', 0)}</td>
        </tr>"""

    return f"""
    <div class='section'>
      <h2 class='section-title'>&#x25b6; OPSEC Timeline</h2>
      {gauge}
      <div style='overflow-x:auto'>
        <table class='data-table'>
          <thead><tr><th>Time</th><th>Event</th><th>Delta</th><th>Score</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>"""


def _kill_chain_section(state: EngagementState) -> str:
    phase_map = [
        ("recon",     "Recon",        "T1046"),
        ("subdomain", "Subdomain",    "T1596"),
        ("web",       "Web Attack",   "T1190"),
        ("cve",       "CVE Exploit",  "T1190"),
        ("ad",        "AD Attack",    "T1558"),
        ("dirbrute",  "Dir Brute",    "T1083"),
        ("jwt",       "JWT Forge",    "T1550"),
        ("default_creds", "Cred Stuff","T1078"),
        ("report",    "Exfil/Report", "T1041"),
    ]
    seen = set(f.phase for f in state.findings)

    nodes = ""
    for i, (key, label, tech) in enumerate(phase_map):
        active = key in seen
        color  = C["green"] if active else C["dim"]
        glow   = f"box-shadow:{_glow(C['green'],10)};" if active else ""
        arrow  = f"<span style='color:{C['green']};margin:0 4px;font-size:16px'>&#x2192;</span>" if i < len(phase_map) - 1 else ""
        nodes += f"""
        <div style='display:inline-flex;flex-direction:column;align-items:center;gap:4px'>
          <div style='background:{color}22;border:1px solid {color};border-radius:5px;
                      padding:8px 12px;text-align:center;{glow}min-width:80px'>
            <div style='font-family:monospace;font-size:11px;font-weight:700;color:{color}'>{label}</div>
            <div style='font-size:9px;color:{C["muted"]};margin-top:2px'>{tech}</div>
          </div>
        </div>{arrow}"""

    return f"""
    <div class='section'>
      <h2 class='section-title'>&#x25b6; Kill Chain</h2>
      <div style='background:{C["card2"]};border:1px solid {C["border"]};border-radius:8px;
                  padding:20px;overflow-x:auto;white-space:nowrap'>
        {nodes}
      </div>
    </div>"""


# ── Main generator ────────────────────────────────────────────────────────────

def generate_html_report(state: EngagementState, ai_analysis: dict = None) -> str:
    counts       = state.finding_counts()
    total        = sum(counts.values())
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode_label   = "Penetration Test" if state.mode.value == "pentest" else "Red Team"

    sev_order      = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(state.findings, key=lambda f: sev_order.get(f.severity.value, 5))

    risk_color = (C["critical"] if counts.get("critical", 0) > 0
                  else C["high"]   if counts.get("high", 0) > 2
                  else C["medium"] if counts.get("high", 0) > 0
                  else C["low"])
    risk_label = ("CRITICAL" if counts.get("critical", 0) > 0
                  else "HIGH"   if counts.get("high", 0) > 2
                  else "MEDIUM" if counts.get("high", 0) > 0
                  else "LOW")

    opsec_color = C["green"] if state.opsec_score >= 70 else C["medium"] if state.opsec_score >= 40 else C["critical"]

    # Pre-compute frequently used colors to avoid nested-quote issues in f-strings
    _border = C["border"]
    _muted  = C["muted"]
    _green  = C["green"]
    _cyan   = C["cyan"]
    _card   = C["card"]
    _card2  = C["card2"]

    # ── Severity highlight bar (CRITICAL / HIGH summary) ─────────────────────
    _crit_n = counts.get("critical", 0)
    _high_n = counts.get("high", 0)
    _sev_highlight = ""
    if _crit_n or _high_n:
        _sev_parts = []
        if _crit_n:
            _sev_parts.append(
                f"<span style='font-family:monospace;font-size:13px;font-weight:700;"
                f"padding:6px 16px;border-radius:4px;background:{C['critical']}22;"
                f"color:{C['critical']};border:1px solid {C['critical']}55;"
                f"box-shadow:{_glow(C['critical'],8)}'>"
                f"&#x26a0; {_crit_n} CRITICAL</span>"
            )
        if _high_n:
            _sev_parts.append(
                f"<span style='font-family:monospace;font-size:13px;font-weight:700;"
                f"padding:6px 16px;border-radius:4px;background:{C['high']}22;"
                f"color:{C['high']};border:1px solid {C['high']}55;"
                f"box-shadow:{_glow(C['high'],8)}'>"
                f"&#x26a0; {_high_n} HIGH</span>"
            )
        _sev_highlight = (
            f"<div style='display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px'>"
            + " ".join(_sev_parts)
            + "</div>"
        )

    # ── Finding cards (grouped by severity) ──────────────────────────────────
    import re as _re_report
    findings_html = _sev_highlight
    _prev_sev = None
    for i, f in enumerate(sorted_findings, 1):
        color   = SEV_COLOR.get(f.severity.value, C["info"])

        # Severity group divider
        if f.severity.value != _prev_sev:
            _prev_sev = f.severity.value
            _grp_count = sum(1 for x in sorted_findings if x.severity.value == f.severity.value)
            _grp_color = SEV_COLOR.get(f.severity.value, C["info"])
            findings_html += (
                f"<div style='margin:20px 0 10px;padding:6px 14px;"
                f"border-left:3px solid {_grp_color};background:{_grp_color}11;"
                f"border-radius:0 4px 4px 0;display:flex;align-items:center;gap:10px'>"
                f"<span style='font-family:monospace;font-size:11px;font-weight:700;"
                f"text-transform:uppercase;color:{_grp_color};letter-spacing:1px'>"
                f"{f.severity.value}</span>"
                f"<span style='font-family:monospace;font-size:11px;color:{_muted}'>"
                f"// {_grp_count} finding{'s' if _grp_count != 1 else ''}</span>"
                f"</div>"
            )

        msf_mod = getattr(f, "msf_module", "")
        msf_badge = (
            f"<span style='font-family:monospace;font-size:10px;padding:2px 8px;border-radius:3px;"
            f"background:{C['green']}22;color:{C['green']};border:1px solid {C['green']}44;"
            f"margin-left:6px'>msf &gt; {_escape(msf_mod)}</span>"
        ) if msf_mod else ""
        cvss_badge = (
            f"<span style='font-family:monospace;font-size:10px;padding:2px 8px;border-radius:3px;"
            f"background:{C['cyan']}22;color:{C['cyan']};border:1px solid {C['cyan']}44;margin-left:6px'>"
            f"CVSS {f.cvss}</span>"
        ) if f.cvss else ""

        # CVE badge — extract CVE IDs from title + evidence
        _cve_matches = _re_report.findall(
            r'CVE-\d{4}-\d+',
            (f.title or "") + " " + (f.evidence or "")
        )
        cve_badges = "".join(
            f"<a href='https://nvd.nist.gov/vuln/detail/{cve}' target='_blank' "
            f"style='font-family:monospace;font-size:10px;padding:2px 8px;border-radius:3px;"
            f"background:{C['medium']}22;color:{C['medium']};border:1px solid {C['medium']}44;"
            f"margin-left:4px;text-decoration:none'>{cve}</a>"
            for cve in dict.fromkeys(_cve_matches)  # deduplicated, preserving order
        )

        mitre = (
            f"<span style='font-family:monospace;font-size:10px;color:{_muted}'>"
            f"{_escape(f.mitre_technique)}</span>"
        ) if f.mitre_technique else ""
        evidence_block = (
            f"<div style='background:#060a10;border:1px solid {_border};border-left:3px solid {color}44;"
            f"color:{_green};padding:10px 14px;border-radius:4px;font-family:monospace;"
            f"font-size:12px;margin:10px 0;white-space:pre-wrap;word-break:break-all;"
            f"line-height:1.6'>"
            f"<span style='color:{_muted};user-select:none'>&#x24; evidence &gt;&gt; </span>"
            f"{_escape(f.evidence)}</div>"
        ) if f.evidence else ""
        rem_block = (
            f"<div style='background:{_card2};border-left:3px solid {_green};"
            f"padding:10px 14px;margin:10px 0;border-radius:0 4px 4px 0;font-size:13px;"
            f"color:{_muted}'>"
            f"<span style='color:{_green};font-family:monospace;font-size:11px'>REMEDIATION &gt;&gt; </span>"
            f"{_escape(f.remediation)}</div>"
        ) if f.remediation else ""

        card_id = f"fc{i}"
        findings_html += f"""
        <div class='finding-card' style='border-left:3px solid {color};box-shadow:{_glow(color,4)}'>
          <div class='finding-header' onclick="toggleCard('{card_id}')"
               style='display:flex;align-items:center;gap:10px;cursor:pointer;padding:16px 20px'>
            <span class='fc-num' style='color:{C["muted"]};font-family:monospace;font-size:11px;min-width:24px'>#{i:02d}</span>
            {_sev_badge(f.severity.value)}
            <span style='flex:1;font-size:14px;font-weight:600;color:{C["text"]}'>{_escape(f.title)}</span>
            {cvss_badge}{cve_badges}{msf_badge}
            <span id='arr_{card_id}' style='color:{C["muted"]};font-size:12px;margin-left:8px;transition:transform 0.3s'>&#x25bc;</span>
          </div>
          <div id='{card_id}' style='display:none;padding:0 20px 16px'>
            <p style='margin:0 0 8px;color:{C["muted"]};font-size:13px;line-height:1.6'>{_escape(f.description)}</p>
            {evidence_block}
            {rem_block}
            <div style='margin-top:10px;font-size:11px;color:{C["dim"]};font-family:monospace'>
              phase:{_escape(f.phase)} &nbsp;&#x7c;&nbsp; {mitre} &nbsp;&#x7c;&nbsp; {f.timestamp[:19]}
            </div>
          </div>
        </div>"""

    # ── AI section ────────────────────────────────────────────────────────────
    ai_section = ""
    if ai_analysis and "analysis" in ai_analysis:
        ai_text = _escape(ai_analysis["analysis"]).replace("\n", "<br>")
        ai_section = f"""
        <div class='section'>
          <h2 class='section-title'>&#x25b6; AI Executive Summary
            <span style='font-size:11px;color:{C["muted"]};font-family:monospace;font-weight:400;margin-left:8px'>
              {_escape(str(ai_analysis.get('model','claude')))} &middot; {ai_analysis.get('tokens_used','?')} tokens
            </span>
          </h2>
          <div style='background:{C["card2"]};border:1px solid {C["border"]};border-left:3px solid {C["cyan"]};
                      border-radius:0 6px 6px 0;padding:20px 24px;font-size:14px;line-height:1.8;
                      color:{C["muted"]}'>
            {ai_text}
          </div>
        </div>"""

    # ── Open ports ────────────────────────────────────────────────────────────
    ports_html = ""
    if state.recon_data.get("open_ports"):
        rows = ""
        for port, info in sorted(state.recon_data["open_ports"].items()):
            banner = _escape((info.get("banner", "") or "—")[:80])
            rows += f"""
            <tr class='trow'>
              <td style='font-family:monospace;font-weight:700;color:{C["green"]}'>{port}</td>
              <td style='color:{C["cyan"]};font-family:monospace;font-size:12px'>{_escape(info['service'])}</td>
              <td style='font-family:monospace;font-size:11px;color:{C["muted"]}'>{banner}</td>
            </tr>"""
        ports_html = f"""
        <div class='section'>
          <h2 class='section-title'>&#x25b6; Open Ports</h2>
          <div style='overflow-x:auto'>
            <table class='data-table'>
              <thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>"""

    # ── AD attack plan ────────────────────────────────────────────────────────
    ad_section = ""
    if state.ad_data.get("ad_detected") and state.ad_data.get("attack_plan"):
        plan_items = ""
        for step in state.ad_data["attack_plan"]:
            chain = state.ad_data.get("attack_chains", {}).get(step["chain"], {})
            cmds  = "".join(
                f"<div style='padding:2px 0'>"
                f"<span style='color:{_muted};user-select:none'>$ </span>"
                f"<span style='color:{_green}'>{_escape(c)}</span></div>"
                for c in chain.get("commands", [])
            )
            plan_items += f"""
            <div style='border:1px solid {C["border"]};border-left:3px solid {C["cyan"]};
                        border-radius:0 6px 6px 0;padding:14px 18px;margin:10px 0;
                        background:{C["card2"]}'>
              <div style='display:flex;align-items:center;gap:10px;margin-bottom:8px'>
                <span style='font-family:monospace;font-size:11px;color:{C["cyan"]}'>STEP {step['step']}</span>
                <span style='font-weight:700;color:{C["text"]}'>{_escape(step['name'])}</span>
                <span style='font-family:monospace;font-size:10px;color:{C["muted"]};
                             background:{C["card"]};border:1px solid {C["border"]};
                             padding:2px 6px;border-radius:3px'>{_escape(chain.get('technique',''))}</span>
              </div>
              <p style='margin:0 0 8px;font-size:13px;color:{C["muted"]}'>{_escape(step.get('reason',''))}</p>
              {f'<div style="background:#060a10;border:1px solid {_border};border-radius:4px;padding:10px 14px;font-family:monospace;font-size:12px;line-height:1.8">{cmds}</div>' if cmds else ''}
            </div>"""
        ad_section = f"""
        <div class='section'>
          <h2 class='section-title'>&#x25b6; AD Attack Chain</h2>
          <p style='color:{C["muted"]};font-size:12px;font-family:monospace;
                    margin-bottom:14px'>// Replace {{domain}} {{user}} {{pass}} {{dc_ip}} with real values</p>
          {plan_items}
        </div>"""

    # ── Screenshots / CVE / OPSEC / Kill chain / Real IP / Tech / Emails ────
    screenshots    = state.recon_data.get("screenshots", {})
    screenshot_html = _screenshot_section(screenshots)
    cve_data        = getattr(state, "cve_data", {})
    cve_html        = _cve_table_section(cve_data)
    opsec_data      = getattr(state, "opsec_tracker_data", {})
    opsec_html      = _opsec_timeline_section(opsec_data, state.mode.value)
    kill_chain_html = _kill_chain_section(state)
    real_ip_html    = _real_ip_section(state.recon_data.get("real_ips", []))
    tech_html       = _technologies_section(state.recon_data.get("technologies", []))
    emails_html     = _emails_section(state.recon_data.get("emails", []))

    # ── Stat bars (CSS animated) ──────────────────────────────────────────────
    def stat_bar(label, count, color, delay_ms=0):
        pct = int((count / max(total, 1)) * 100)
        return f"""
        <div style='margin:10px 0'>
          <div style='display:flex;justify-content:space-between;margin-bottom:5px'>
            <span style='font-family:monospace;font-size:11px;font-weight:700;
                         text-transform:uppercase;color:{color};letter-spacing:1px'>{label}</span>
            <span style='font-family:monospace;font-size:12px;color:{C["muted"]}'>{count}</span>
          </div>
          <div style='background:{C["border"]};border-radius:2px;height:4px;overflow:hidden'>
            <div class='anim-bar' style='background:linear-gradient(90deg,{color},{color}88);
                         height:4px;border-radius:2px;width:0;
                         box-shadow:0 0 8px {color}88;
                         animation:growBar 1s ease {delay_ms}ms forwards'
                 data-w='{pct}'></div>
          </div>
        </div>"""

    # ── Engagement notes ──────────────────────────────────────────────────────
    _dim = C["dim"]
    notes_html = "".join(
        f"<div style='font-size:12px;font-family:monospace;color:{_muted};padding:3px 0;"
        f"border-bottom:1px solid {_border}'>"
        f"<span style='color:{_green};user-select:none'>&gt; </span>{_escape(n)}</div>"
        for n in state.notes
    ) or f"<div style='color:{_dim};font-size:12px;font-family:monospace'>// no notes</div>"

    # ── Subdomains summary ────────────────────────────────────────────────────
    sub_found = state.recon_data.get("subdomains", {}).get("found", [])
    subdomain_html = ""
    if sub_found:
        items = "".join(
            f"<span style='font-family:monospace;font-size:11px;color:{C['cyan']};"
            f"background:{C['card2']};border:1px solid {C['border']};border-radius:3px;"
            f"padding:2px 8px;margin:3px 2px;display:inline-block'>{_escape(s)}</span>"
            for s in sub_found[:50]
        )
        subdomain_html = f"""
        <div class='section'>
          <h2 class='section-title'>&#x25b6; Subdomains
            <span class='count-badge'>{len(sub_found)}</span>
          </h2>
          <div>{items}</div>
        </div>"""

    # ── Default creds summary ─────────────────────────────────────────────────
    default_creds_data = getattr(state, "default_creds_data", {})
    creds_html = ""
    if default_creds_data.get("vulnerable"):
        rows = "".join(
            f"<tr class='trow'>"
            f"<td style='font-family:monospace;color:{C['green']}'>{v['service'].upper()}:{v['port']}</td>"
            f"<td style='font-family:monospace;color:{C['critical']}'>{_escape(v['username'])} : {_escape(v['password'])}</td>"
            f"</tr>"
            for v in default_creds_data["vulnerable"]
        )
        creds_html = f"""
        <div class='section'>
          <h2 class='section-title' style='color:{C["critical"]}'>&#x26a0; Default Credentials Found</h2>
          <table class='data-table'>
            <thead><tr><th>Service</th><th>Credentials</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""

    # ── Dirbrute summary ──────────────────────────────────────────────────────
    dirbrute_data = getattr(state, "dirbrute_data", {})
    dirbrute_html = ""
    if dirbrute_data.get("results"):
        dir_rows = ""
        for port_key, entries in dirbrute_data["results"].items():
            for e in entries[:20]:
                status = e.get("status", 0)
                status_color = (C["critical"] if status == 200 else
                                C["medium"]   if status in (401, 403) else
                                C["muted"])
                dir_rows += (
                    f"<tr class='trow'>"
                    f"<td style='font-family:monospace;color:{_green};font-size:12px'>"
                    f"{_escape(e.get('url',''))}</td>"
                    f"<td style='font-family:monospace;font-weight:700;color:{status_color}'>{status}</td>"
                    f"<td style='font-family:monospace;font-size:11px;color:{_muted}'>"
                    f"{e.get('content_length','?')}</td>"
                    f"</tr>"
                )
        if dir_rows:
            dirbrute_html = f"""
            <div class='section'>
              <h2 class='section-title'>&#x25b6; Directory Brute-Force
                <span class='count-badge'>{dirbrute_data.get('total',0)}</span>
              </h2>
              <div style='overflow-x:auto'>
                <table class='data-table'>
                  <thead><tr><th>URL</th><th>Status</th><th>Length</th></tr></thead>
                  <tbody>{dir_rows}</tbody>
                </table>
              </div>
            </div>"""

    # ── MSF module summary ────────────────────────────────────────────────────
    msf_data = getattr(state, "msf_data", {})
    msf_html = ""
    if msf_data.get("modules"):
        msf_rows = "".join(
            f"<tr class='trow'>"
            f"<td style='font-family:monospace;font-size:11px;color:{_green}'>{_escape(mod)}</td>"
            f"<td style='font-size:12px;color:{_muted}'>{', '.join(_escape(t) for t in titles[:2])}</td>"
            f"</tr>"
            for mod, titles in msf_data["modules"].items()
        )
        msf_html = f"""
        <div class='section'>
          <h2 class='section-title'>&#x25b6; Metasploit Modules
            <span class='count-badge'>{len(msf_data['modules'])}</span>
          </h2>
          <table class='data-table'>
            <thead><tr><th>MSF Module</th><th>Finding(s)</th></tr></thead>
            <tbody>{msf_rows}</tbody>
          </table>
        </div>"""

    # ── Full HTML ─────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GOD'S EYE :: {_escape(state.target)}</title>
<style>
/* ── Reset & base ── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:{C["bg"]};color:{C["text"]};line-height:1.6;
  min-height:100vh;
}}

/* ── Header ── */
.header{{
  background:linear-gradient(135deg,#0a0e1a 0%,#0d1525 50%,#0a1628 100%);
  padding:36px 48px 32px;
  border-bottom:1px solid {C["border"]};
  position:relative;
  overflow:hidden;
}}
/* Dot grid overlay */
.header::before{{
  content:'';position:absolute;inset:0;
  background-image:radial-gradient(circle,{C["green"]}18 1px,transparent 1px);
  background-size:28px 28px;
  pointer-events:none;
}}
/* Subtle scan line */
.header::after{{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,{C["green"]}66,transparent);
  animation:scanline 4s ease-in-out infinite;
}}
@keyframes scanline{{
  0%,100%{{top:0;opacity:0}}
  10%{{opacity:1}}
  90%{{opacity:1}}
  100%{{top:100%;opacity:0}}
}}

.header-inner{{
  position:relative;z-index:1;
  display:flex;align-items:flex-start;justify-content:space-between;
  flex-wrap:wrap;gap:24px;max-width:1100px;margin:0 auto;
}}
.header-label{{
  font-family:monospace;font-size:10px;letter-spacing:3px;
  text-transform:uppercase;color:{C["muted"]};margin-bottom:8px;
}}
.header-title{{
  font-size:26px;font-weight:700;color:{C["text"]};
  display:flex;align-items:center;gap:10px;
}}
.header-title::before{{
  content:'>';color:{C["green"]};font-family:monospace;font-size:28px;
  animation:blink 1.2s step-end infinite;
}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:0}}}}
.header-target{{
  font-family:monospace;font-size:18px;color:{C["cyan"]};
  margin:6px 0;
}}
.header-meta{{
  font-size:12px;color:{C["muted"]};font-family:monospace;margin-top:4px;
}}
.risk-badge{{
  text-align:center;
  background:{C["card"]}cc;
  border:1px solid {risk_color}55;
  border-radius:8px;padding:18px 24px;min-width:130px;
  box-shadow:{_glow(risk_color,12)};
}}
.risk-level{{
  font-family:monospace;font-size:26px;font-weight:700;
  color:{risk_color};letter-spacing:2px;
  text-shadow:{_glow(risk_color,8)};
}}
.risk-label{{font-size:10px;color:{C["muted"]};letter-spacing:2px;text-transform:uppercase}}

/* ── Body ── */
.body{{max-width:1100px;margin:0 auto;padding:32px 24px}}

/* ── Summary grid ── */
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:24px 0}}
.stat-card{{
  background:{C["card"]};border:1px solid {C["border"]};
  border-radius:6px;padding:18px 20px;
  transition:border-color .2s,box-shadow .2s;
}}
.stat-card:hover{{border-color:{C["green"]}44;box-shadow:{_glow(C["green"],6)}}}
.stat-num{{font-family:monospace;font-size:32px;font-weight:700}}
.stat-lbl{{font-size:11px;color:{C["muted"]};font-family:monospace;text-transform:uppercase;letter-spacing:1px;margin-top:2px}}

/* ── Sections ── */
.section{{margin:28px 0}}
.section-title{{
  font-size:14px;font-weight:700;font-family:monospace;
  text-transform:uppercase;letter-spacing:2px;
  color:{C["cyan"]};border-bottom:1px solid {C["border"]};
  padding-bottom:10px;margin-bottom:18px;
}}
.count-badge{{
  display:inline-block;font-size:10px;padding:1px 7px;border-radius:10px;
  background:{C["green"]}22;color:{C["green"]};border:1px solid {C["green"]}44;
  margin-left:8px;font-family:monospace;vertical-align:middle;
}}

/* ── Distribution card ── */
.dist-card{{
  background:{C["card"]};border:1px solid {C["border"]};
  border-radius:6px;padding:20px 24px;margin:20px 0;
}}
@keyframes growBar{{
  from{{width:0}}
  to{{width:var(--target-w,0%)}}
}}

/* ── Finding cards ── */
.finding-card{{
  background:{C["card"]};border:1px solid {C["border"]};
  border-radius:0 6px 6px 0;margin:10px 0;
  transition:border-color .2s,box-shadow .2s;
}}
.finding-card:hover{{
  border-color:{C["border"]};
  box-shadow:0 2px 16px #00000055;
}}
.finding-header:hover .fc-num{{color:{C["green"]}!important}}

/* ── Tables ── */
.data-table{{
  width:100%;border-collapse:collapse;font-size:13px;
}}
.data-table th{{
  text-align:left;padding:10px 14px;
  background:{C["card2"]};color:{C["muted"]};
  font-family:monospace;font-size:10px;text-transform:uppercase;
  letter-spacing:1px;border-bottom:1px solid {C["border"]};
}}
.trow td{{
  padding:10px 14px;
  border-bottom:1px solid {C["border"]}88;
  vertical-align:top;
}}
.trow:last-child td{{border-bottom:none}}
.trow:hover{{background:{C["card2"]}}}

/* ── Footer ── */
.footer{{
  text-align:center;padding:32px 24px;border-top:1px solid {C["border"]};
  position:relative;overflow:hidden;margin-top:48px;
}}
.footer::before{{
  content:'';position:absolute;inset:0;
  background:repeating-linear-gradient(
    0deg,
    transparent,transparent 2px,
    {C["green"]}06 2px,{C["green"]}06 4px
  );
  animation:matrixScroll 8s linear infinite;
  pointer-events:none;
}}
@keyframes matrixScroll{{from{{background-position:0 0}}to{{background-position:0 40px}}}}
.footer-text{{
  position:relative;z-index:1;
  font-family:monospace;font-size:11px;color:{C["muted"]};letter-spacing:1px;
}}
.footer-brand{{color:{C["green"]};font-weight:700}}

/* ── Print ── */
@media print{{
  .header::after{{display:none}}
  .footer::before{{display:none}}
  body{{background:#fff!important;color:#000!important}}
  .finding-card{{page-break-inside:avoid}}
  [id^="fc"]{{display:block!important}}
}}

/* ── Responsive ── */
@media(max-width:640px){{
  .header{{padding:24px 20px}}
  .body{{padding:20px 16px}}
  .stat-grid{{grid-template-columns:1fr 1fr}}
}}
</style>
</head>
<body>

<!-- ═══ HEADER ════════════════════════════════════════════════════════════ -->
<div class="header">
  <div class="header-inner">
    <div>
      <div class="header-label">GOD'S EYE v1.0.0 :: Threat Intelligence Report</div>
      <div class="header-title">{_escape(mode_label)}</div>
      <div class="header-target">{_escape(state.target)}</div>
      <div class="header-meta">
        generated :: {generated_at} &nbsp;&middot;&nbsp;
        duration :: {state.elapsed()} &nbsp;&middot;&nbsp;
        findings :: {total} &nbsp;&middot;&nbsp;
        opsec :: <span style='color:{opsec_color}'>{state.opsec_score}/100</span>
      </div>
    </div>
    <div class="risk-badge">
      <div class="risk-label">Risk Level</div>
      <div class="risk-level">{risk_label}</div>
      <div style='font-family:monospace;font-size:11px;color:{C["muted"]};margin-top:6px'>{total} findings</div>
    </div>
  </div>
</div>

<!-- ═══ BODY ══════════════════════════════════════════════════════════════ -->
<div class="body">

  <!-- Stat cards -->
  <div class="stat-grid">
    <div class="stat-card" style='border-top:2px solid {C["critical"]}'>
      <div class="stat-num" style='color:{C["critical"]}'>{counts.get("critical",0)}</div>
      <div class="stat-lbl">Critical</div>
    </div>
    <div class="stat-card" style='border-top:2px solid {C["high"]}'>
      <div class="stat-num" style='color:{C["high"]}'>{counts.get("high",0)}</div>
      <div class="stat-lbl">High</div>
    </div>
    <div class="stat-card" style='border-top:2px solid {C["medium"]}'>
      <div class="stat-num" style='color:{C["medium"]}'>{counts.get("medium",0)}</div>
      <div class="stat-lbl">Medium</div>
    </div>
    <div class="stat-card" style='border-top:2px solid {C["low"]}'>
      <div class="stat-num" style='color:{C["low"]}'>{counts.get("low",0)}</div>
      <div class="stat-lbl">Low</div>
    </div>
    <div class="stat-card" style='border-top:2px solid {C["info"]}'>
      <div class="stat-num" style='color:{C["info"]}'>{counts.get("info",0)}</div>
      <div class="stat-lbl">Info</div>
    </div>
    <div class="stat-card" style='border-top:2px solid {C["cyan"]}'>
      <div class="stat-num" style='color:{C["cyan"]}'>{cve_data.get("total",0)}</div>
      <div class="stat-lbl">CVEs</div>
    </div>
  </div>

  <!-- Distribution bars -->
  <div class="dist-card">
    <div style='font-family:monospace;font-size:11px;color:{C["muted"]};text-transform:uppercase;
                letter-spacing:2px;margin-bottom:16px'>Finding Distribution</div>
    {stat_bar("Critical", counts.get("critical",0), C["critical"], 0)}
    {stat_bar("High",     counts.get("high",0),     C["high"],     100)}
    {stat_bar("Medium",   counts.get("medium",0),   C["medium"],   200)}
    {stat_bar("Low",      counts.get("low",0),       C["low"],      300)}
    {stat_bar("Info",     counts.get("info",0),      C["info"],     400)}
  </div>

  {ai_section}

  {kill_chain_html}

  {screenshot_html}

  {real_ip_html}

  {tech_html}

  {emails_html}

  {subdomain_html}

  {ports_html}

  {creds_html}

  {cve_html}

  {dirbrute_html}

  {msf_html}

  <!-- Findings -->
  <div class="section">
    <h2 class="section-title">&#x25b6; Findings
      <span class="count-badge">{total}</span>
    </h2>
    {''.join([findings_html]) if findings_html else
     f'<div style="color:{_muted};font-family:monospace;font-size:13px">// no findings recorded</div>'}
  </div>

  {ad_section}

  {opsec_html}

  <!-- Notes -->
  <div class="section">
    <h2 class="section-title">&#x25b6; Engagement Log</h2>
    <div style='background:{C["card"]};border:1px solid {C["border"]};border-radius:6px;
                padding:16px 20px;max-height:240px;overflow-y:auto'>
      {notes_html}
    </div>
  </div>

</div>

<!-- ═══ FOOTER ════════════════════════════════════════════════════════════ -->
<div class="footer">
  <div class="footer-text">
    <span class="footer-brand">GOD'S EYE v1.0.0 by alisalive</span>
    &nbsp;&middot;&nbsp;{generated_at}&nbsp;&middot;&nbsp;
    <span style='color:{C["muted"]}'>For authorized security testing only</span>
  </div>
</div>

<script>
// ── Toggle finding cards ──────────────────────────────────────────────────
function toggleCard(id){{
  var el  = document.getElementById(id);
  var arr = document.getElementById('arr_' + id);
  var open = el.style.display !== 'none';
  el.style.display  = open ? 'none' : 'block';
  arr.style.transform = open ? '' : 'rotate(180deg)';
}}

// ── Animate progress bars ──────────────────────────────────────────────────
document.querySelectorAll('.anim-bar').forEach(function(bar){{
  var w = bar.getAttribute('data-w');
  bar.style.setProperty('--target-w', w + '%');
  bar.style.width = w + '%';
}});

// ── Counter animation ──────────────────────────────────────────────────────
function animateCounter(el){{
  var target = parseInt(el.textContent, 10);
  if(isNaN(target) || target === 0) return;
  var start = 0, dur = 800, step = 16;
  var timer = setInterval(function(){{
    start += Math.ceil(target / (dur / step));
    if(start >= target){{ el.textContent = target; clearInterval(timer); return; }}
    el.textContent = start;
  }}, step);
}}
document.querySelectorAll('.stat-num').forEach(animateCounter);
</script>

</body>
</html>"""

    return html


def save_report(state: EngagementState, ai_analysis: dict = None,
                output_dir: str = ".") -> dict:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"report_{state.target.replace('.','_').replace('/','_').replace(':','_')}_{timestamp}"

    os.makedirs(output_dir, exist_ok=True)
    paths = {}

    html_path = os.path.join(output_dir, f"{base_name}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html_report(state, ai_analysis))
    paths["html"] = html_path

    json_path = os.path.join(output_dir, f"{base_name}.json")
    export = {
        "target":          state.target,
        "mode":            state.mode.value,
        "generated_at":    datetime.now().isoformat(),
        "elapsed":         state.elapsed(),
        "findings":        [f.to_dict() for f in state.findings],
        "finding_counts":  state.finding_counts(),
        "recon_summary": {
            "open_ports":       list(state.recon_data.get("open_ports", {}).keys()),
            "web_ports":        list(state.recon_data.get("web", {}).keys()),
            "subdomains_found": len(state.recon_data.get("subdomains", {}).get("found", [])),
        },
        "technologies":  state.recon_data.get("technologies", []),
        "emails":        state.recon_data.get("emails", []),
        "ad_detected":   state.ad_data.get("ad_detected", False),
        "cve_total":     getattr(state, "cve_data", {}).get("total", 0),
        "opsec_score":   state.opsec_score,
        "opsec_rating":  getattr(state, "opsec_tracker_data", {}).get("rating", "N/A"),
        "msf_modules":   getattr(state, "msf_data", {}).get("total", 0),
        "notes":         state.notes,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2)
    paths["json"] = json_path

    return paths
