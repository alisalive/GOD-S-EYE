"""
Tests for modules/web.py — security headers, email harvesting, cookie analysis.
"""

import sys
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import EngagementState, Mode
from modules.web import (
    check_security_headers,
    run_web_analysis,
    SECURITY_HEADERS,
    SECURITY_HEADER_SEVERITIES,
    extract_emails,
    analyze_set_cookie_headers,
    check_sqli,
    check_xss_reflection,
    _is_port_responsive,
)


# ── Unit tests ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_security_headers_all_missing():
    """When no security headers present, all should be in missing list."""
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {}

    mock_session = MagicMock()
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_cm.__aexit__ = AsyncMock(return_value=False)
    mock_session.get.return_value = mock_cm

    result = await check_security_headers(mock_session, "http://example.com")
    assert "missing" in result
    assert len(result["missing"]) == len(SECURITY_HEADERS)


@pytest.mark.asyncio
async def test_check_security_headers_some_present():
    """Headers that are present should not appear in missing list."""
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
    }

    mock_session = MagicMock()
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_cm.__aexit__ = AsyncMock(return_value=False)
    mock_session.get.return_value = mock_cm

    result = await check_security_headers(mock_session, "http://example.com")
    missing_names = [h["header"] for h in result.get("missing", [])]
    assert "X-Frame-Options" not in missing_names
    assert "Strict-Transport-Security" not in missing_names


@pytest.mark.asyncio
async def test_run_web_analysis_no_web_services():
    """Should handle state with no web services gracefully."""
    state = EngagementState(
        target="127.0.0.1", mode=Mode.PENTEST, scope=["127.0.0.1"]
    )
    state.recon_data = {"open_ports": {}, "web": {}}

    result = await run_web_analysis(state, console=None)
    assert result == {}


# ══════════════════════════════════════════════════════════════════════════════
# extract_emails — pure function
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractEmails:
    def test_basic_email(self):
        assert "admin@example.org" in extract_emails("contact admin@example.org for help")

    def test_multiple_emails(self):
        text = "reach us at info@company.com or sales@company.com"
        result = extract_emails(text)
        assert "info@company.com" in result
        assert "sales@company.com" in result

    def test_mailto_link(self):
        html = '<a href="mailto:contact@firm.io">Email us</a>'
        result = extract_emails(html)
        assert "contact@firm.io" in result

    def test_mailto_with_query_string(self):
        html = '<a href="mailto:hr@company.net?subject=Job">Apply</a>'
        result = extract_emails(html)
        assert "hr@company.net" in result

    def test_filters_example_com(self):
        result = extract_emails("user@example.com is a placeholder")
        assert "user@example.com" not in result

    def test_filters_test_domain(self):
        result = extract_emails("ping test@test.com")
        assert not any("test.com" in e for e in result)

    def test_filters_noreply(self):
        result = extract_emails("sent from noreply@company.com")
        assert not any("noreply" in e for e in result)

    def test_filters_no_reply_hyphen(self):
        result = extract_emails("no-reply@company.com")
        assert not any("no-reply" in e for e in result)

    def test_empty_text(self):
        assert extract_emails("") == []
        assert extract_emails(None) == []

    def test_no_emails(self):
        assert extract_emails("just regular text here") == []

    def test_returns_sorted_list(self):
        text = "z@z.com a@a.com m@m.com"
        result = extract_emails(text)
        assert result == sorted(result)

    def test_deduplication(self):
        text = "info@co.com and info@co.com again"
        result = extract_emails(text)
        assert result.count("info@co.com") == 1

    def test_case_normalised_to_lowercase(self):
        result = extract_emails("Info@Company.COM")
        assert "info@company.com" in result


# ══════════════════════════════════════════════════════════════════════════════
# analyze_set_cookie_headers — pure function
# ══════════════════════════════════════════════════════════════════════════════

class TestAnalyzeSetCookieHeaders:
    def test_detects_php_from_phpsessid(self):
        techs, _ = analyze_set_cookie_headers(
            ["PHPSESSID=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "PHP" in techs

    def test_detects_django_from_sessionid(self):
        techs, _ = analyze_set_cookie_headers(
            ["sessionid=xyz; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "Django" in techs

    def test_detects_laravel_from_cookie_name(self):
        techs, _ = analyze_set_cookie_headers(
            ["laravel_session=abc; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "Laravel" in techs

    def test_detects_node_from_connect_sid(self):
        techs, _ = analyze_set_cookie_headers(
            ["connect.sid=s%3Aabc; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "Node.js" in techs

    def test_detects_java_from_jsessionid(self):
        techs, _ = analyze_set_cookie_headers(
            ["JSESSIONID=ABCD1234; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "Java/JSP" in techs

    def test_missing_httponly_flag(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; Secure; SameSite=Lax"]
        )
        titles = [f["title"] for f in findings]
        assert any("HttpOnly" in t for t in titles)

    def test_missing_secure_flag(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; HttpOnly; SameSite=Lax"]
        )
        titles = [f["title"] for f in findings]
        assert any("Secure" in t for t in titles)

    def test_missing_samesite(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; HttpOnly; Secure"]
        )
        titles = [f["title"] for f in findings]
        assert any("SameSite" in t for t in titles)

    def test_all_flags_present_no_security_issues(self):
        _, findings = analyze_set_cookie_headers(
            ["PHPSESSID=abc; Path=/; HttpOnly; Secure; SameSite=Strict"]
        )
        assert findings == []

    def test_non_session_cookie_not_flagged(self):
        """Tracking/analytics cookies should not generate security findings."""
        _, findings = analyze_set_cookie_headers(
            ["_ga=GA1.2.abc; Path=/; Expires=Wed, 01 Jan 2025 00:00:00 GMT"]
        )
        assert findings == []

    def test_empty_list(self):
        techs, findings = analyze_set_cookie_headers([])
        assert techs == []
        assert findings == []

    def test_finding_severity_httponly(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; Secure; SameSite=Lax"]
        )
        httponly_f = next(f for f in findings if "HttpOnly" in f["title"])
        assert httponly_f["severity"] == "medium"

    def test_finding_severity_samesite(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; HttpOnly; Secure"]
        )
        ss_f = next(f for f in findings if "SameSite" in f["title"])
        assert ss_f["severity"] == "low"

    def test_finding_has_required_keys(self):
        _, findings = analyze_set_cookie_headers(
            ["PHPSESSID=abc; Path=/"]
        )
        for f in findings:
            assert "title"       in f
            assert "severity"    in f
            assert "description" in f
            assert "evidence"    in f
            assert "remediation" in f


# ══════════════════════════════════════════════════════════════════════════════
# _is_port_responsive
# ══════════════════════════════════════════════════════════════════════════════

class TestIsPortResponsive:

    @pytest.mark.asyncio
    async def test_returns_true_on_http_200(self):
        """Any HTTP status < 600 → responsive."""
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__  = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get.return_value = mock_cm
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__  = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await _is_port_responsive("http://example.com")
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_connection_error(self):
        """Connection error → not responsive."""
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("connection refused")
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__  = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await _is_port_responsive("http://192.0.2.1:8080")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_true_on_http_403(self):
        """403 Forbidden is still a valid HTTP response → responsive."""
        mock_resp = AsyncMock()
        mock_resp.status = 403
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__  = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get.return_value = mock_cm
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__  = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session), \
             patch("aiohttp.TCPConnector"):
            result = await _is_port_responsive("http://example.com:8443")
        assert result is True


# ══════════════════════════════════════════════════════════════════════════════
# test_basic_sqli — differential analysis
# ══════════════════════════════════════════════════════════════════════════════

def _make_session(responses: list):
    """
    Build a mock aiohttp session where successive session.get() calls return
    the given list of (status, body_text) tuples in order.
    """
    import unittest.mock as _um

    session = _um.MagicMock()
    cms = []
    for status, body in responses:
        resp = _um.AsyncMock()
        resp.status = status
        resp.text = _um.AsyncMock(return_value=body)
        cm = _um.AsyncMock()
        cm.__aenter__ = _um.AsyncMock(return_value=resp)
        cm.__aexit__  = _um.AsyncMock(return_value=False)
        cms.append(cm)

    session.get.side_effect = cms
    return session


class TestBasicSqli:

    @pytest.mark.asyncio
    async def test_no_finding_when_behind_cloudflare(self):
        """SQLi probe must be entirely skipped for Cloudflare-protected sites."""
        session = _make_session([])          # no requests should be made
        result = await check_sqli(session, "http://example.com", waf="Cloudflare")
        assert result == []
        session.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_finding_when_behind_vercel(self):
        session = _make_session([])
        result = await check_sqli(session, "http://example.com", waf="Vercel")
        assert result == []
        session.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_finding_when_no_differential(self):
        """Same status + same size on baseline and probe → no finding, even with SQL error."""
        body = "You have an error in your SQL syntax"
        # baseline + quote — both identical size/status (only 2 requests now)
        session = _make_session([
            (200, body),   # baseline ?id=1
            (200, body),   # probe    ?id=1'
        ])
        with patch("modules.web._page_has_csrf", new=AsyncMock(return_value=False)):
            result = await check_sqli(session, "http://example.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_finding_when_status_changes_and_sql_error(self):
        """Status change + SQL error keyword → report finding."""
        normal_body = "Welcome to the site"
        error_body  = "You have an error in your SQL syntax near '1''"
        session = _make_session([
            (200, normal_body),   # baseline ?id=1
            (500, error_body),    # probe    ?id=1'   ← status differs, sql error
        ])
        with patch("modules.web._page_has_csrf", new=AsyncMock(return_value=False)):
            result = await check_sqli(session, "http://example.com")
        assert len(result) == 1
        assert result[0]["param"] == "id"
        assert result[0]["payload"] == "'"

    @pytest.mark.asyncio
    async def test_finding_when_size_changes_and_sql_error(self):
        """Body size diff > 500 bytes + SQL error keyword → report finding."""
        normal_body = "x" * 1000
        error_body  = "ORA-00907: missing right parenthesis" + ("x" * 2000)
        session = _make_session([
            (200, normal_body),   # baseline ?id=1
            (200, error_body),    # probe    ?id=1'   ← size differs, sql error
        ])
        with patch("modules.web._page_has_csrf", new=AsyncMock(return_value=False)):
            result = await check_sqli(session, "http://example.com")
        assert len(result) == 1
        assert "ora-" in result[0]["error_pattern"].lower()

    @pytest.mark.asyncio
    async def test_no_finding_when_size_changes_but_no_sql_error(self):
        """Body size diff without any SQL error keyword must not produce a finding."""
        normal_body = "x" * 1000
        large_body  = "y" * 5000          # large diff, but no SQL error text
        session = _make_session([
            (200, normal_body),   # baseline ?id=1
            (200, large_body),    # probe    ?id=1'  ← size diff, no SQL keyword
        ])
        with patch("modules.web._page_has_csrf", new=AsyncMock(return_value=False)):
            result = await check_sqli(session, "http://example.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_no_finding_when_csrf_present(self):
        """CSRF-protected pages must be skipped entirely."""
        session = _make_session([])
        with patch("modules.web._page_has_csrf", new=AsyncMock(return_value=True)):
            result = await check_sqli(session, "http://example.com")
        assert result == []
        session.get.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# Original test suite (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_run_web_analysis_with_mock_service():
    """Should process web services and populate state.web_data."""
    state = EngagementState(
        target="127.0.0.1", mode=Mode.PENTEST, scope=["127.0.0.1"]
    )
    state.recon_data = {
        "open_ports": {80: {"service": "HTTP", "banner": ""}},
        "web": {80: {"url": "http://127.0.0.1", "technologies": [], "waf": None,
                     "cves": [], "vulns": [], "status_code": 200}},
    }

    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Security-Policy": "default-src 'self'"}
        mock_resp_cm = AsyncMock()
        mock_resp_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_cm.__aexit__ = AsyncMock(return_value=False)
        mock_session.get.return_value = mock_resp_cm

        result = await run_web_analysis(state, console=None)

    assert isinstance(result, dict)


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY_HEADER_SEVERITIES — per-header severity mapping
# ══════════════════════════════════════════════════════════════════════════════

class TestSecurityHeaderSeverities:
    def test_csp_is_high(self):
        assert SECURITY_HEADER_SEVERITIES["Content-Security-Policy"] == "high"

    def test_hsts_is_high(self):
        assert SECURITY_HEADER_SEVERITIES["Strict-Transport-Security"] == "high"

    def test_xcto_is_medium(self):
        assert SECURITY_HEADER_SEVERITIES["X-Content-Type-Options"] == "medium"

    def test_xfo_is_medium(self):
        assert SECURITY_HEADER_SEVERITIES["X-Frame-Options"] == "medium"

    def test_permissions_policy_is_low(self):
        assert SECURITY_HEADER_SEVERITIES["Permissions-Policy"] == "low"

    def test_referrer_policy_is_low(self):
        assert SECURITY_HEADER_SEVERITIES["Referrer-Policy"] == "low"

    def test_xxss_is_low(self):
        assert SECURITY_HEADER_SEVERITIES["X-XSS-Protection"] == "low"

    def test_all_security_headers_have_severity(self):
        for h in SECURITY_HEADERS:
            assert h in SECURITY_HEADER_SEVERITIES, f"No severity for {h}"


class TestSecurityHeadersReturnSeverity:
    @pytest.mark.asyncio
    async def test_missing_headers_include_severity(self):
        """Each missing header entry must include a severity field."""
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {}

        mock_session = MagicMock()
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__  = AsyncMock(return_value=False)
        mock_session.get.return_value = mock_cm

        result = await check_security_headers(mock_session, "http://example.com")
        for mh in result["missing"]:
            assert "severity" in mh, f"Missing 'severity' for {mh.get('header')}"
            assert mh["severity"] in ("high", "medium", "low", "info")

    @pytest.mark.asyncio
    async def test_result_includes_raw_headers(self):
        """check_security_headers must return 'headers' dict (raw response headers)."""
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {"Server": "nginx/1.18.0"}

        mock_session = MagicMock()
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__  = AsyncMock(return_value=False)
        mock_session.get.return_value = mock_cm

        result = await check_security_headers(mock_session, "http://example.com")
        assert "headers" in result
        assert isinstance(result["headers"], dict)

    @pytest.mark.asyncio
    async def test_csp_missing_is_high(self):
        """CSP in missing list → severity high."""
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {}

        mock_session = MagicMock()
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__  = AsyncMock(return_value=False)
        mock_session.get.return_value = mock_cm

        result = await check_security_headers(mock_session, "http://example.com")
        csp_entry = next(
            (h for h in result["missing"] if h["header"] == "Content-Security-Policy"),
            None,
        )
        assert csp_entry is not None
        assert csp_entry["severity"] == "high"


# ══════════════════════════════════════════════════════════════════════════════
# Cookie security improvements — high sensitivity + long expiry
# ══════════════════════════════════════════════════════════════════════════════

class TestCookieSecurityImprovements:
    def test_jwt_cookie_without_httponly_is_high(self):
        """JWT token cookie without HttpOnly → HIGH (not medium)."""
        _, findings = analyze_set_cookie_headers(
            ["jwt_token=abc; Path=/; Secure; SameSite=Lax"]
        )
        httponly_f = next((f for f in findings if "HttpOnly" in f["title"]), None)
        assert httponly_f is not None
        assert httponly_f["severity"] == "high"

    def test_auth_cookie_without_httponly_is_high(self):
        """auth_token cookie without HttpOnly → HIGH."""
        _, findings = analyze_set_cookie_headers(
            ["auth_token=xyz; Path=/; Secure; SameSite=Lax"]
        )
        httponly_f = next((f for f in findings if "HttpOnly" in f["title"]), None)
        assert httponly_f is not None
        assert httponly_f["severity"] == "high"

    def test_regular_session_cookie_without_httponly_is_medium(self):
        """Plain sessionid (not JWT/auth/token) without HttpOnly → MEDIUM."""
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; Secure; SameSite=Lax"]
        )
        httponly_f = next((f for f in findings if "HttpOnly" in f["title"]), None)
        assert httponly_f is not None
        assert httponly_f["severity"] == "medium"

    def test_long_expiry_flagged(self):
        """Cookies with Max-Age > 1 year → LOW finding."""
        one_year_plus = 365 * 24 * 3600 + 1
        _, findings = analyze_set_cookie_headers(
            [f"sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={one_year_plus}"]
        )
        expiry_f = next((f for f in findings if "expiry" in f["title"].lower()), None)
        assert expiry_f is not None
        assert expiry_f["severity"] == "low"

    def test_short_expiry_not_flagged(self):
        """Cookies with Max-Age <= 1 year → no long-expiry finding."""
        one_year = 365 * 24 * 3600
        _, findings = analyze_set_cookie_headers(
            [f"sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={one_year}"]
        )
        assert not any("expiry" in f["title"].lower() for f in findings)


# ══════════════════════════════════════════════════════════════════════════════
# check_xss_reflection
# ══════════════════════════════════════════════════════════════════════════════

class TestXssReflection:

    @pytest.mark.asyncio
    async def test_no_finding_when_waf_detected(self):
        """XSS probe must be entirely skipped for WAF/CDN-protected sites."""
        session = _make_session([])
        result = await check_xss_reflection(session, "http://example.com", waf="Cloudflare")
        assert result == []
        session.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_finding_when_payload_reflected_unescaped(self):
        """Unescaped payload in response → reflected XSS finding."""
        body = "Results for: <script>xss</script>"
        session = _make_session([(200, body)])
        result = await check_xss_reflection(session, "http://example.com")
        assert len(result) == 1
        assert result[0]["param"] == "q"
        assert "<script>xss</script>" in result[0]["payload"]

    @pytest.mark.asyncio
    async def test_no_finding_when_payload_escaped(self):
        """HTML-escaped payload → no finding."""
        body = "Results for: &lt;script&gt;xss&lt;/script&gt;"
        session = _make_session([
            (200, body),   # q probe — escaped → no finding
            (200, body),   # search probe — escaped → no finding
        ])
        result = await check_xss_reflection(session, "http://example.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_no_finding_on_non_200(self):
        """Non-200 response → no finding."""
        session = _make_session([
            (302, ""),
            (302, ""),
        ])
        result = await check_xss_reflection(session, "http://example.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_no_finding_when_vercel_waf(self):
        """Vercel CDN → skip."""
        session = _make_session([])
        result = await check_xss_reflection(session, "http://example.com", waf="Vercel")
        assert result == []
        session.get.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# check_sqli — multi-param improvements
# ══════════════════════════════════════════════════════════════════════════════

class TestSqliMultiParam:

    @pytest.mark.asyncio
    async def test_finds_sqli_on_search_param_when_id_clean(self):
        """If 'id' param shows no SQL error but 'search' does, still reports finding."""
        normal_body = "Welcome"
        error_body  = "You have an error in your SQL syntax near '1''"
        # id baseline, id probe (no diff) → search baseline, search probe (error)
        session = _make_session([
            (200, normal_body),   # id baseline
            (200, normal_body),   # id probe — no diff
            (200, normal_body),   # search baseline
            (500, error_body),    # search probe — error
        ])
        with patch("modules.web._page_has_csrf", new=AsyncMock(return_value=False)):
            result = await check_sqli(session, "http://example.com")
        assert len(result) == 1
        assert result[0]["param"] == "search"

    @pytest.mark.asyncio
    async def test_stops_after_first_finding(self):
        """Once a finding is confirmed, no further params should be tested."""
        normal_body = "ok"
        error_body  = "Warning: mysql_fetch_array() expects parameter 1"
        session = _make_session([
            (200, normal_body),   # id baseline
            (500, error_body),    # id probe — SQL error → finding
            # search and q should NOT be called after this
        ])
        with patch("modules.web._page_has_csrf", new=AsyncMock(return_value=False)):
            result = await check_sqli(session, "http://example.com")
        assert len(result) == 1
        assert result[0]["param"] == "id"
        # Only 2 get() calls should have been made (id baseline + id probe)
        assert session.get.call_count == 2


# ══════════════════════════════════════════════════════════════════════════════
# Email false-positive regression tests (CIA.gov / @2x image filenames)
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractEmailsFalsePositives:
    def test_at2x_retina_image_not_an_email(self):
        """'threads_about@2x-something.png' must NOT be extracted as an email."""
        html = '<img src="threads_about@2x-something.png" alt="icon">'
        result = extract_emails(html)
        assert not any("@2x" in e for e in result)

    def test_at2x_pattern_variant(self):
        """'icon@2x.png' must not be matched."""
        result = extract_emails("background-image: url('icon@2x.png')")
        assert result == []

    def test_image_extension_domain_rejected(self):
        """Addresses whose domain ends in .png/.jpg/.svg are not emails."""
        for ext in (".png", ".jpg", ".gif", ".svg", ".webp"):
            addr = f"user@image{ext}"
            assert extract_emails(addr) == [], f"Should reject {addr}"

    def test_real_email_still_accepted(self):
        """Legitimate emails must still pass through after the new filters."""
        result = extract_emails("contact info@security-team.io for help")
        assert "info@security-team.io" in result

    def test_url_path_not_matched(self):
        """Strings containing '/' are not emails."""
        result = extract_emails("https://cdn.example.com/assets/logo@2x/icon.png")
        assert result == []
