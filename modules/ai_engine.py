"""
AI Engine — Claude API analysis engine.
"""

import json
import os
from core.orchestrator import EngagementState, Finding, Severity


def build_ai_prompt(state: EngagementState) -> str:
    findings_json = json.dumps([f.to_dict() for f in state.findings], indent=2)
    recon_summary = {
        "open_ports": list(state.recon_data.get("open_ports", {}).keys()),
        "technologies": [],
        "waf": None,
        "cves": [],
    }
    for port_data in state.recon_data.get("web", {}).values():
        recon_summary["technologies"].extend(port_data.get("technologies", []))
        if port_data.get("waf"):
            recon_summary["waf"] = port_data["waf"]
        for cve in port_data.get("cves", []):
            if cve.get("cvss_score", 0) >= 7.0:
                recon_summary["cves"].append(f"{cve['cve_id']} ({cve['technology']}, CVSS {cve['cvss_score']})")

    ad_summary = {
        "ad_detected": state.ad_data.get("ad_detected", False),
        "attack_plan": state.ad_data.get("attack_plan", []),
        "smb_signing_required": state.ad_data.get("smb_signing", {}).get("required", True),
        "anonymous_ldap": state.ad_data.get("ldap_result", {}).get("anonymous_bind", False),
    }

    opsec_data = getattr(state, "opsec_tracker_data", {})
    cve_data = getattr(state, "cve_data", {})

    mode_context = {
        "pentest": "scope-bound penetration test for a client. Focus on business risk, CVSS scores, and clear remediation steps.",
        "redteam": "red team engagement simulating APT. Focus on stealth, detection evasion, MITRE ATT&CK chain, and persistence.",
    }

    return f"""You are an expert {state.mode.value} professional analyzing findings from a security assessment.

TARGET: {state.target}
MODE: {state.mode.value} — {mode_context.get(state.mode.value, '')}
ELAPSED: {state.elapsed()}
OPSEC SCORE: {state.opsec_score}/100 ({opsec_data.get('rating', 'N/A')})

FINDINGS ({len(state.findings)} total):
{findings_json}

RECON SUMMARY:
{json.dumps(recon_summary, indent=2)}

AD ANALYSIS:
{json.dumps(ad_summary, indent=2)}

CVE SUMMARY ({cve_data.get('total', 0)} CVEs):
{json.dumps([c['cve_id'] + ' - ' + c['technology'] + ' CVSS ' + str(c.get('cvss_score','?')) for c in cve_data.get('cves', [])[:10]], indent=2)}

ENGAGEMENT NOTES:
{chr(10).join(state.notes)}

Please provide:
1. EXECUTIVE SUMMARY (3-4 sentences, business impact language)
2. ATTACK NARRATIVE (how an attacker would chain these findings, step by step)
3. TOP 3 CRITICAL ACTIONS (most urgent remediation steps with priority)
4. MITRE ATT&CK SUMMARY (which tactics/techniques were identified)
5. OPSEC RATING (for red team mode: how detectable was this engagement, 1-10)

Keep it professional, concise, and actionable. Use technical language appropriate for {state.mode.value} context."""


async def get_ai_analysis(state: EngagementState, api_key: str = None) -> dict:
    try:
        import anthropic

        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            return {"error": "No API key", "summary": _fallback_summary(state)}

        client = anthropic.Anthropic(api_key=key)
        prompt = build_ai_prompt(state)

        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            system="You are an expert penetration tester and red team operator. Provide concise, technical, and actionable security analysis. For authorized security testing only.",
            messages=[{"role": "user", "content": prompt}],
        )

        ai_text = message.content[0].text
        return {
            "analysis": ai_text,
            "tokens_used": message.usage.input_tokens + message.usage.output_tokens,
            "model": message.model,
        }

    except Exception as e:
        return {
            "error": str(e),
            "summary": _fallback_summary(state),
        }


async def generate_waf_bypass(waf_type: str, vuln_type: str) -> list:
    """Generate WAF bypass payloads using Claude AI."""
    try:
        import anthropic
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            from modules.waf_bypass import get_payloads
            return get_payloads(waf_type, vuln_type)

        client = anthropic.Anthropic(api_key=key)
        prompt = f"""Generate 10 unique {vuln_type.upper()} bypass payloads specifically crafted to evade {waf_type} WAF detection.
Use various evasion techniques: encoding variations, case manipulation, comment injection, whitespace abuse, unicode encoding.
Return only a JSON array of strings, no explanation.
Format: ["payload1", "payload2", ...]"""

        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text.strip()
        import re
        m = re.search(r'\[.*\]', text, re.DOTALL)
        if m:
            return json.loads(m.group(0))
    except Exception:
        pass

    from modules.waf_bypass import get_payloads
    return get_payloads(waf_type, vuln_type)


def _fallback_summary(state: EngagementState) -> str:
    counts = state.finding_counts()
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    risk = "CRITICAL" if critical > 0 else "HIGH" if high > 2 else "MEDIUM" if high > 0 else "LOW"

    lines = [
        f"Security assessment of {state.target} completed in {state.elapsed()}.",
        f"Overall risk: {risk}",
        f"Findings: {counts.get('critical', 0)} Critical | {counts.get('high', 0)} High | "
        f"{counts.get('medium', 0)} Medium | {counts.get('low', 0)} Low | {counts.get('info', 0)} Info",
    ]

    if state.recon_data.get("open_ports"):
        lines.append(f"Open ports: {', '.join(str(p) for p in sorted(state.recon_data['open_ports'].keys()))}")

    if state.ad_data.get("ad_detected"):
        plan = state.ad_data.get("attack_plan", [])
        lines.append(f"AD attack vectors identified: {len(plan)} attack paths")

    cve_data = getattr(state, "cve_data", {})
    if cve_data.get("total", 0) > 0:
        lines.append(f"CVEs correlated: {cve_data['total']} total")

    lines.append(f"OPSEC score: {state.opsec_score}/100")
    return "\n".join(lines)
