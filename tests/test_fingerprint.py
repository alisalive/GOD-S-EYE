"""
Tests for modules/fingerprint.py — 50+ technology detections.

Pure functions are tested without I/O; run_fingerprint() tests use
unittest.mock.patch on _fetch_page so no real HTTP requests are made.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.fingerprint import (
    _hget,
    _cookies_from_set_cookie,
    _joomla_body_indicators,
    detect_server,
    detect_language,
    detect_cdn,
    detect_cms_from_headers,
    detect_cms_from_body,
    detect_frameworks,
    detect_frontend,
    detect_analytics,
    detect_security_tools,
    detect_ecommerce_tools,
    run_fingerprint,
)


# ══════════════════════════════════════════════════════════════════════════════
# _hget
# ══════════════════════════════════════════════════════════════════════════════

class TestHget:
    def test_exact_key(self):
        assert _hget({"Server": "nginx"}, "Server") == "nginx"

    def test_lowercase_key(self):
        assert _hget({"server": "nginx"}, "Server") == "nginx"

    def test_uppercase_key(self):
        assert _hget({"SERVER": "nginx"}, "Server") == "nginx"

    def test_missing_returns_empty(self):
        assert _hget({}, "Server") == ""

    def test_first_non_empty_wins(self):
        assert _hget({"Server": "Apache"}, "Server", "X-Powered-By") == "Apache"

    def test_falls_through_to_second(self):
        assert _hget({"X-Powered-By": "PHP/8.1"}, "Server", "X-Powered-By") == "PHP/8.1"


# ══════════════════════════════════════════════════════════════════════════════
# _cookies_from_set_cookie
# ══════════════════════════════════════════════════════════════════════════════

class TestCookiesFromSetCookie:
    def test_basic(self):
        cookies = _cookies_from_set_cookie(["PHPSESSID=abc123; Path=/; HttpOnly"])
        assert cookies.get("phpsessid") == "abc123"

    def test_multiple(self):
        cookies = _cookies_from_set_cookie([
            "laravel_session=xyz; Path=/",
            "ci_session=foo; Path=/",
        ])
        assert "laravel_session" in cookies
        assert "ci_session" in cookies

    def test_empty_list(self):
        assert _cookies_from_set_cookie([]) == {}

    def test_no_equals(self):
        cookies = _cookies_from_set_cookie(["noequal"])
        assert cookies == {}


# ══════════════════════════════════════════════════════════════════════════════
# detect_server
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectServer:
    def test_apache_with_version(self):
        r = detect_server({"Server": "Apache/2.4.54 (Ubuntu)"})
        assert r[0]["name"] == "Apache"
        assert r[0]["version"] == "2.4.54"
        assert r[0]["confidence"] == "high"

    def test_apache_no_version(self):
        r = detect_server({"Server": "Apache"})
        assert r[0]["name"] == "Apache"
        assert r[0]["version"] == ""

    def test_nginx_with_version(self):
        r = detect_server({"Server": "nginx/1.24.0"})
        assert r[0]["name"] == "Nginx"
        assert r[0]["version"] == "1.24.0"

    def test_iis_with_version(self):
        r = detect_server({"Server": "Microsoft-IIS/10.0"})
        assert r[0]["name"] == "IIS"
        assert r[0]["version"] == "10.0"

    def test_litespeed(self):
        r = detect_server({"Server": "LiteSpeed"})
        assert any(e["name"] == "LiteSpeed" for e in r)

    def test_caddy(self):
        r = detect_server({"Server": "Caddy/2.7.4"})
        assert any(e["name"] == "Caddy" for e in r)

    def test_gunicorn(self):
        r = detect_server({"Server": "gunicorn/21.2.0"})
        assert any(e["name"] == "Gunicorn" for e in r)

    def test_werkzeug(self):
        r = detect_server({"Server": "Werkzeug/2.3.4 Python/3.11.0"})
        assert any(e["name"] == "Flask/Werkzeug" for e in r)

    def test_unknown_returns_empty(self):
        assert detect_server({"Server": "CoolServer"}) == []

    def test_no_server_header(self):
        assert detect_server({}) == []

    def test_lowercase_header(self):
        r = detect_server({"server": "nginx/1.18.0"})
        assert r[0]["name"] == "Nginx"


# ══════════════════════════════════════════════════════════════════════════════
# detect_language
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectLanguage:
    def test_php_with_version(self):
        r = detect_language({"X-Powered-By": "PHP/8.2.1"})
        assert r[0]["name"] == "PHP"
        assert r[0]["version"] == "8.2.1"

    def test_php_no_version(self):
        r = detect_language({"X-Powered-By": "PHP"})
        assert r[0]["name"] == "PHP"

    def test_express(self):
        r = detect_language({"X-Powered-By": "Express"})
        assert any(e["name"] == "Node.js/Express" for e in r)

    def test_aspnet(self):
        r = detect_language({"X-Powered-By": "ASP.NET"})
        assert any(e["name"] == "ASP.NET" for e in r)

    def test_no_header(self):
        assert detect_language({}) == []


# ══════════════════════════════════════════════════════════════════════════════
# detect_cdn
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectCdn:
    def test_cloudflare_cf_ray(self):
        r = detect_cdn({"CF-Ray": "abc123-LHR"})
        assert any(e["name"] == "Cloudflare" for e in r)

    def test_cloudflare_cache_status(self):
        r = detect_cdn({"cf-cache-status": "HIT"})
        assert any(e["name"] == "Cloudflare" for e in r)

    def test_cloudfront(self):
        r = detect_cdn({"X-Amz-Cf-Id": "abc"})
        assert any(e["name"] == "AWS CloudFront" for e in r)

    def test_fastly(self):
        r = detect_cdn({"X-Fastly-Request-Id": "abc"})
        assert any(e["name"] == "Fastly" for e in r)

    def test_vercel(self):
        r = detect_cdn({"X-Vercel-Id": "iad1::abc"})
        assert any(e["name"] == "Vercel" for e in r)

    def test_netlify(self):
        r = detect_cdn({"X-Nf-Request-Id": "abc"})
        assert any(e["name"] == "Netlify" for e in r)

    def test_no_cdn(self):
        assert detect_cdn({"Content-Type": "text/html"}) == []


# ══════════════════════════════════════════════════════════════════════════════
# detect_cms_from_headers
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectCmsFromHeaders:
    def test_drupal_x_generator(self):
        r = detect_cms_from_headers({"X-Generator": "Drupal 10 (https://www.drupal.org)"})
        assert r[0]["name"] == "Drupal"
        assert r[0]["version"] == "10"

    def test_wordpress_x_generator(self):
        r = detect_cms_from_headers({"X-Generator": "WordPress 6.4.2"})
        assert r[0]["name"] == "WordPress"
        assert r[0]["version"] == "6.4.2"

    def test_typo3_x_generator(self):
        r = detect_cms_from_headers({"X-Generator": "TYPO3 11"})
        assert any(e["name"] == "TYPO3" for e in r)

    def test_drupal_cache_header(self):
        r = detect_cms_from_headers({"X-Drupal-Cache": "HIT"})
        assert any(e["name"] == "Drupal" for e in r)

    def test_bitrix_powered_cms(self):
        r = detect_cms_from_headers({"X-Powered-CMS": "Bitrix Site Manager"})
        assert any(e["name"] == "Bitrix" for e in r)

    def test_spring_boot_context(self):
        r = detect_cms_from_headers({"X-Application-Context": "application:8080"})
        assert any(e["name"] == "Spring Boot" for e in r)

    def test_no_relevant_headers(self):
        assert detect_cms_from_headers({"Content-Type": "text/html"}) == []


# ══════════════════════════════════════════════════════════════════════════════
# _joomla_body_indicators
# ══════════════════════════════════════════════════════════════════════════════

class TestJoomlaBodyIndicators:
    def test_media_system_js_scores_one(self):
        score, ev = _joomla_body_indicators(
            '<script src="/media/system/js/core.js"></script>'
        )
        assert score == 1
        assert any("media/system/js" in e for e in ev)

    def test_meta_generator_scores_one(self):
        score, ev = _joomla_body_indicators(
            '<meta name="generator" content="Joomla! 4.3">'
        )
        assert score >= 1

    def test_joomla_text_scores_one(self):
        score, _ = _joomla_body_indicators("<p>Powered by Joomla!</p>")
        assert score >= 1

    def test_two_indicators_score_two(self):
        body = ('<meta name="generator" content="Joomla! 4.3">'
                '<script src="/media/system/js/core.js"></script>')
        score, _ = _joomla_body_indicators(body)
        assert score >= 2

    def test_components_com_scores_zero(self):
        score, _ = _joomla_body_indicators(
            '<script src="/components/com_example/script.js"></script>'
        )
        assert score == 0

    def test_empty_body_zero(self):
        assert _joomla_body_indicators("")[0] == 0

    def test_plain_page_zero(self):
        assert _joomla_body_indicators("<html><body>Hello</body></html>")[0] == 0


# ══════════════════════════════════════════════════════════════════════════════
# detect_cms_from_body
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectCmsFromBody:
    _WP = """<head>
      <meta name="generator" content="WordPress 6.4.2">
      <link href="/wp-content/themes/x/style.css">
    </head>"""

    _JOOMLA = """<head><meta name="generator" content="Joomla! 4.3.3"></head>
    <body><script src="/media/system/js/core.min.js"></script></body>"""

    _DRUPAL = """<script>var drupalSettings = {};</script>
    <link href="/sites/default/files/css/style.css">"""

    def test_wordpress_detected(self):
        assert any(t["name"] == "WordPress" for t in detect_cms_from_body(self._WP))

    def test_wordpress_version(self):
        wp = next(t for t in detect_cms_from_body(self._WP) if t["name"] == "WordPress")
        assert wp["version"] == "6.4.2"

    def test_joomla_detected(self):
        assert any(t["name"] == "Joomla" for t in detect_cms_from_body(self._JOOMLA))

    def test_drupal_detected(self):
        assert any(t["name"] == "Drupal" for t in detect_cms_from_body(self._DRUPAL))

    def test_magento(self):
        body = '<script>require.config({mageInit: true, "Magento_Ui": {}})</script>'
        assert any(t["name"] == "Magento" for t in detect_cms_from_body(body))

    def test_opencart(self):
        body = '<a href="?route=common/home">Home</a>'
        assert any(t["name"] == "OpenCart" for t in detect_cms_from_body(body))

    def test_ghost(self):
        body = '<link rel="stylesheet" href="/ghost/api/themes/casper.css">'
        assert any(t["name"] == "Ghost" for t in detect_cms_from_body(body))

    def test_bitrix(self):
        body = '<script src="/bitrix/js/main/core.js"></script>'
        assert any(t["name"] == "Bitrix" for t in detect_cms_from_body(body))

    def test_typo3(self):
        body = '<link href="/typo3temp/assets/compressed/style.css">'
        assert any(t["name"] == "TYPO3" for t in detect_cms_from_body(body))

    def test_shopify_ecommerce(self):
        body = '<script src="https://cdn.shopify.com/s/files/1/theme.js"></script>'
        assert any(t["name"] == "Shopify" for t in detect_cms_from_body(body))

    def test_woocommerce_with_wp(self):
        body = self._WP + '<div class="woocommerce-cart">...</div>'
        names = [t["name"] for t in detect_cms_from_body(body)]
        assert "WordPress" in names
        assert "WooCommerce" in names

    def test_joomla_single_indicator_not_reported(self):
        body = '<script src="/media/system/js/core.js"></script>'
        assert not any(t["name"] == "Joomla" for t in detect_cms_from_body(body))

    def test_joomla_components_com_not_reported(self):
        body = '<script src="/components/com_example/app.js"></script>'
        assert not any(t["name"] == "Joomla" for t in detect_cms_from_body(body))

    def test_empty_body(self):
        assert detect_cms_from_body("") == []
        assert detect_cms_from_body(None) == []

    def test_generic_generator(self):
        body = '<meta name="generator" content="MyCustomCMS 2.0">'
        assert any("MyCustomCMS" in t["name"] for t in detect_cms_from_body(body))


# ══════════════════════════════════════════════════════════════════════════════
# detect_frameworks
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectFrameworks:
    def test_laravel_cookie(self):
        r = detect_frameworks({}, "", {"laravel_session": "abc"})
        assert any(t["name"] == "Laravel" for t in r)

    def test_laravel_body(self):
        r = detect_frameworks({}, "laravel_session in page", {})
        assert any(t["name"] == "Laravel" for t in r)

    def test_django_csrf(self):
        r = detect_frameworks({}, '<input name="csrfmiddlewaretoken" value="x">', {})
        assert any(t["name"] == "Django" for t in r)

    def test_aspnet_header(self):
        """X-AspNet-Version header alone is sufficient."""
        r = detect_frameworks({"X-AspNet-Version": "4.0.30319"}, "", {})
        assert any(t["name"] == "ASP.NET" for t in r)

    def test_aspnet_axd_resource(self):
        """WebResource.axd in body is an ASP.NET-exclusive signal."""
        r = detect_frameworks({}, '<script src="/WebResource.axd?d=xyz"></script>', {})
        assert any(t["name"] == "ASP.NET" for t in r)

    def test_aspnet_viewstate_plus_aspx(self):
        """__VIEWSTATE + .aspx reference together are sufficient."""
        body = '<input name="__VIEWSTATE" value="x"><a href="/page.aspx">link</a>'
        r = detect_frameworks({}, body, {})
        assert any(t["name"] == "ASP.NET" for t in r)

    def test_aspnet_viewstate_alone_no_fp(self):
        """__VIEWSTATE alone (without .aspx or headers) must NOT trigger ASP.NET."""
        r = detect_frameworks({}, '<input type="hidden" name="__VIEWSTATE" value="x">', {})
        assert not any(t["name"] == "ASP.NET" for t in r)

    def test_codeigniter_cookie(self):
        r = detect_frameworks({}, "", {"ci_session": "xyz"})
        assert any(t["name"] == "CodeIgniter" for t in r)

    def test_symfony_header(self):
        r = detect_frameworks({"X-Debug-Token": "abc"}, "", {})
        assert any(t["name"] == "Symfony" for t in r)

    def test_cakephp_cookie(self):
        r = detect_frameworks({}, "", {"cakephp": "xyz"})
        assert any(t["name"] == "CakePHP" for t in r)

    def test_rails_session_cookie(self):
        r = detect_frameworks({}, "", {"_session_id": "abc"})
        assert any(t["name"] == "Ruby on Rails" for t in r)

    def test_empty_all(self):
        assert detect_frameworks({}, "", {}) == []


# ══════════════════════════════════════════════════════════════════════════════
# detect_frontend
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectFrontend:
    def test_nextjs(self):
        body = '<script id="__NEXT_DATA__">{}</script>'
        assert any(t["name"] == "Next.js" for t in detect_frontend(body))

    def test_nextjs_static_path(self):
        body = '<script src="/_next/static/chunks/main.js"></script>'
        assert any(t["name"] == "Next.js" for t in detect_frontend(body))

    def test_nuxtjs(self):
        body = 'window.__NUXT__ = {}'
        assert any(t["name"] == "Nuxt.js" for t in detect_frontend(body))

    def test_gatsby(self):
        body = '<link rel="prefetch" href="/page-data/index/page-data.json">'
        assert any(t["name"] == "Gatsby" for t in detect_frontend(body))

    def test_vuejs(self):
        body = '<div id="app" __vue_app__></div>'
        assert any(t["name"] == "Vue.js" for t in detect_frontend(body))

    def test_angular_version(self):
        body = '<app-root ng-version="17.3.1"></app-root>'
        ang = next((t for t in detect_frontend(body) if t["name"] == "Angular"), None)
        assert ang is not None
        assert ang["version"] == "17.3.1"

    def test_svelte(self):
        body = '<div class="svelte-abc123">Hello</div>'
        assert any(t["name"] == "Svelte" for t in detect_frontend(body))

    def test_jquery_version(self):
        body = '<script src="/js/jquery-3.7.1.min.js"></script>'
        jq = next((t for t in detect_frontend(body) if t["name"] == "jQuery"), None)
        assert jq is not None
        assert jq["version"] == "3.7.1"

    def test_bootstrap_version(self):
        body = '<link href="/css/bootstrap-5.3.2.min.css">'
        bs = next((t for t in detect_frontend(body) if t["name"] == "Bootstrap"), None)
        assert bs is not None
        assert bs["version"] == "5.3.2"

    def test_tailwind(self):
        body = '<link href="/css/tailwind.min.css" rel="stylesheet">'
        assert any(t["name"] == "Tailwind CSS" for t in detect_frontend(body))

    def test_lodash(self):
        body = '<script src="/js/lodash.min.js"></script>'
        assert any(t["name"] == "Lodash" for t in detect_frontend(body))

    def test_momentjs(self):
        body = '<script src="/js/moment.min.js"></script>'
        assert any(t["name"] == "Moment.js" for t in detect_frontend(body))

    def test_d3(self):
        body = '<script src="/js/d3.v7.min.js"></script>'
        d3 = next((t for t in detect_frontend(body) if t["name"] == "D3.js"), None)
        assert d3 is not None
        assert d3["version"] == "7"

    def test_empty_body(self):
        assert detect_frontend("") == []
        assert detect_frontend(None) == []


# ══════════════════════════════════════════════════════════════════════════════
# detect_analytics
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectAnalytics:
    def test_google_analytics_gtag(self):
        body = "gtag('config', 'G-ABC123');"
        assert any(t["name"] == "Google Analytics" for t in detect_analytics(body))

    def test_google_analytics_ua(self):
        body = "ga('create', 'UA-12345-1');"
        assert any(t["name"] == "Google Analytics" for t in detect_analytics(body))

    def test_gtm(self):
        body = "GTM-WXYZ123"
        assert any(t["name"] == "Google Tag Manager" for t in detect_analytics(body))

    def test_facebook_pixel(self):
        body = "fbq('init', '123456');"
        assert any(t["name"] == "Facebook Pixel" for t in detect_analytics(body))

    def test_hotjar(self):
        body = "var hjid = 123456;"
        assert any(t["name"] == "Hotjar" for t in detect_analytics(body))

    def test_mixpanel(self):
        body = '<script src="https://cdn.mixpanel.com/lib.js"></script>'
        assert any(t["name"] == "Mixpanel" for t in detect_analytics(body))

    def test_segment(self):
        body = 'analytics.load("xyz");'
        # The regex needs cdn.segment.com or segment.com/analytics.js
        body2 = 'cdn.segment.com/analytics.js'
        assert any(t["name"] == "Segment" for t in detect_analytics(body2))

    def test_cloudflare_analytics(self):
        body = 'cfBeacon = {token: "abc"};'
        assert any(t["name"] == "Cloudflare Analytics" for t in detect_analytics(body))

    def test_empty_body(self):
        assert detect_analytics("") == []


# ══════════════════════════════════════════════════════════════════════════════
# detect_security_tools
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectSecurityTools:
    def test_recaptcha(self):
        body = '<script src="https://www.google.com/recaptcha/api.js"></script>'
        assert any(t["name"] == "Google reCAPTCHA" for t in detect_security_tools(body))

    def test_hcaptcha(self):
        body = '<script src="https://hcaptcha.com/1/api.js"></script>'
        assert any(t["name"] == "hCaptcha" for t in detect_security_tools(body))

    def test_turnstile(self):
        body = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
        assert any(t["name"] == "Cloudflare Turnstile" for t in detect_security_tools(body))

    def test_empty(self):
        assert detect_security_tools("") == []


# ══════════════════════════════════════════════════════════════════════════════
# detect_ecommerce_tools
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectEcommerce:
    def test_stripe(self):
        body = '<script src="https://js.stripe.com/v3/"></script>'
        assert any(t["name"] == "Stripe" for t in detect_ecommerce_tools(body))

    def test_paypal(self):
        body = '<script src="https://www.paypal.com/sdk/js?client-id=x"></script>'
        assert any(t["name"] == "PayPal" for t in detect_ecommerce_tools(body))

    def test_empty(self):
        assert detect_ecommerce_tools("") == []


# ══════════════════════════════════════════════════════════════════════════════
# run_fingerprint — integration tests (mocked I/O)
# ══════════════════════════════════════════════════════════════════════════════

_WORDPRESS_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta name="generator" content="WordPress 6.4.2">
  <link rel="stylesheet" href="/wp-content/themes/theme/style.css?ver=6.4.2">
</head>
<body>
  <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
  <script>gtag('config', 'G-TEST123');</script>
</body>
</html>"""

_APACHE_HEADERS = {"Server": "Apache/2.4.54 (Ubuntu)", "X-Powered-By": "PHP/8.2.0"}


@pytest.mark.asyncio
async def test_run_fingerprint_wordpress_from_body():
    async def fake_fetch(url, timeout=10):
        if "/wp-login.php" in url or "/sites/default/" in url or "/administrator/" in url:
            return 404, {}, "", []
        return 200, _APACHE_HEADERS, _WORDPRESS_HTML, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    names = [t["name"] for t in result["technologies"]]
    assert "WordPress" in names
    assert "Apache" in names
    assert "PHP" in names
    assert "Google Analytics" in names


@pytest.mark.asyncio
async def test_run_fingerprint_version_extraction():
    async def fake_fetch(url, timeout=10):
        return 200, _APACHE_HEADERS, _WORDPRESS_HTML, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    wp = next((t for t in result["technologies"] if t["name"] == "WordPress"), None)
    assert wp is not None
    assert wp["version"] == "6.4.2"


@pytest.mark.asyncio
async def test_run_fingerprint_deduplicates():
    """WordPress from body AND probe → only one entry."""
    async def fake_fetch(url, timeout=10):
        if "/wp-login.php" in url:
            return 200, {}, "<form action='/wp-login.php'>WordPress Login</form>", []
        return 200, {}, _WORDPRESS_HTML, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    assert sum(1 for t in result["technologies"] if t["name"] == "WordPress") == 1


@pytest.mark.asyncio
async def test_run_fingerprint_failed_fetch_returns_empty():
    async def fake_fetch(url, timeout=10):
        return 0, {}, "", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://unreachable.example")

    assert result["technologies"] == []


@pytest.mark.asyncio
async def test_run_fingerprint_result_schema():
    async def fake_fetch(url, timeout=10):
        return 200, {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1"}, _WORDPRESS_HTML, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    for t in result["technologies"]:
        assert "name"       in t and isinstance(t["name"], str)
        assert "version"    in t and isinstance(t["version"], str)
        assert "confidence" in t and t["confidence"] in ("high", "medium", "low")
        assert "category"   in t and isinstance(t["category"], str)
        assert "evidence"   in t and isinstance(t["evidence"], str)


@pytest.mark.asyncio
async def test_run_fingerprint_cloudflare_cdn():
    async def fake_fetch(url, timeout=10):
        return 200, {"CF-Ray": "abc-LHR", "cf-cache-status": "HIT"}, "<html></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    assert any(t["name"] == "Cloudflare" for t in result["technologies"])


@pytest.mark.asyncio
async def test_run_fingerprint_multiple_categories():
    """One page can detect Server + CDN + Analytics + Framework simultaneously."""
    body = """<html>
    <script>gtag('config', 'G-XYZ');</script>
    <script src="/_next/static/main.js"></script>
    <script src="https://www.google.com/recaptcha/api.js"></script>
    </html>"""
    headers = {"CF-Ray": "abc", "Server": "nginx/1.25.0"}

    async def fake_fetch(url, timeout=10):
        return 200, headers, body, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    cats = {t["category"] for t in result["technologies"]}
    assert "Server" in cats
    assert "CDN" in cats
    assert "Analytics" in cats
    assert "Framework" in cats
    assert "Security" in cats


@pytest.mark.asyncio
async def test_run_fingerprint_returns_base_url():
    async def fake_fetch(url, timeout=10):
        return 0, {}, "", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://target.example.com")

    assert result["base_url"] == "https://target.example.com"


@pytest.mark.asyncio
async def test_run_fingerprint_wordpress_probe_body_confirmation():
    """wp-login.php 403 with no WP keywords → WordPress NOT reported."""
    async def fake_fetch(url, timeout=10):
        if "/wp-login.php" in url:
            return 403, {}, "<html><body><h1>403 Forbidden</h1></body></html>", []
        if "/sites/default/" in url or "/administrator/" in url:
            return 404, {}, "", []
        return 200, {}, "<html><body><p>CDN landing page</p></body></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://openai.com")

    assert not any(t["name"] == "WordPress" for t in result["technologies"])


@pytest.mark.asyncio
async def test_run_fingerprint_drupal_probe_body_confirmation():
    """/sites/default/ 403 with no Drupal keywords → Drupal NOT reported."""
    async def fake_fetch(url, timeout=10):
        if "/sites/default/" in url:
            return 403, {}, "<html><body>403 Forbidden</body></html>", []
        if "/wp-login.php" in url or "/administrator/" in url:
            return 404, {}, "", []
        return 200, {}, "<html><body>Welcome</body></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    assert not any(t["name"] == "Drupal" for t in result["technologies"])


@pytest.mark.asyncio
async def test_run_fingerprint_wordpress_probe_positive():
    """wp-login.php 200 with /wp-content/ asset link → WordPress reported."""
    # Real WP login pages always load CSS/JS from /wp-content/ or /wp-includes/.
    wp_login_body = (
        "<html><head>"
        '<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">'
        "</head><body>"
        '<form action="https://example.com/wp-login.php" method="post">'
        "</form></body></html>"
    )

    async def fake_fetch(url, timeout=10):
        if "/wp-login.php" in url:
            return 200, {}, wp_login_body, []
        if "/sites/default/" in url or "/administrator/" in url:
            return 404, {}, "", []
        return 200, {}, "<html><body>Home</body></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    assert any(t["name"] == "WordPress" for t in result["technologies"])


@pytest.mark.asyncio
async def test_run_fingerprint_joomla_not_reported_on_403_alone():
    async def fake_fetch(url, timeout=10):
        if "/administrator/" in url:
            return 403, {}, "Forbidden", []
        return 200, {}, "<html><body>No Joomla here</body></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    assert not any(t["name"] == "Joomla" for t in result["technologies"])


@pytest.mark.asyncio
async def test_run_fingerprint_joomla_one_body_plus_admin_200():
    """1 body indicator + /administrator/ 200 with Joomla content → detected."""
    one_indicator = '<script src="/media/system/js/core.js"></script>'
    admin_body = "<html><title>Joomla! Administrator</title></html>"

    async def fake_fetch(url, timeout=10):
        if "/administrator/" in url:
            return 200, {}, admin_body, []
        if "/wp-login.php" in url or "/sites/default/" in url:
            return 404, {}, "", []
        return 200, {}, one_indicator, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    joomla = next((t for t in result["technologies"] if t["name"] == "Joomla"), None)
    assert joomla is not None
    assert joomla["confidence"] == "high"


@pytest.mark.asyncio
async def test_run_fingerprint_bitrix_not_joomla():
    """Bitrix site with /components/com_ paths must NOT trigger Joomla."""
    bitrix_body = (
        '<script src="/bitrix/js/main/core.js"></script>'
        '<script src="/components/com_example/script.js"></script>'
    )

    async def fake_fetch(url, timeout=10):
        if "/administrator/" in url:
            return 404, {}, "", []
        return 200, {}, bitrix_body, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://bitrix-site.example")

    assert not any(t["name"] == "Joomla" for t in result["technologies"])
    assert any(t["name"] == "Bitrix" for t in result["technologies"])


# ══════════════════════════════════════════════════════════════════════════════
# False-positive regression tests (Pinterest/Canva scenarios)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_wordpress_not_detected_when_404_echoes_url():
    """
    Sites like Pinterest return a 404 page that echoes the requested URL
    ('/wp-login.php not found').  The word 'wp-login.php' appears in the body
    but that must NOT trigger WordPress detection any more.
    """
    async def fake_fetch(url, timeout=10):
        if "/wp-login.php" in url:
            # 404 page that echoes the URL — common on CDN sites
            return 404, {}, (
                "<html><body><h1>404 Not Found</h1>"
                "<p>The page /wp-login.php could not be found.</p>"
                "</body></html>"
            ), []
        if "/sites/default/" in url or "/administrator/" in url:
            return 404, {}, "", []
        return 200, {}, "<html><body>Pinterest home</body></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://www.pinterest.com")

    assert not any(t["name"] == "WordPress" for t in result["technologies"])


@pytest.mark.asyncio
async def test_wordpress_not_detected_when_403_contains_word_wordpress():
    """
    Some generic 403 pages contain the word 'WordPress' in a comment or
    footer. That alone must NOT be enough to confirm WordPress.
    """
    async def fake_fetch(url, timeout=10):
        if "/wp-login.php" in url:
            return 403, {}, (
                "<html><body><h1>Access Denied</h1>"
                "<!-- Powered by WordPress -->"
                "</body></html>"
            ), []
        if "/sites/default/" in url or "/administrator/" in url:
            return 404, {}, "", []
        return 200, {}, "<html><body>Home</body></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://www.canva.com")

    assert not any(t["name"] == "WordPress" for t in result["technologies"])


@pytest.mark.asyncio
async def test_wordpress_detected_via_meta_generator():
    """Meta generator tag on wp-login.php response confirms WordPress."""
    async def fake_fetch(url, timeout=10):
        if "/wp-login.php" in url:
            return 200, {}, (
                '<html><head>'
                '<meta name="generator" content="WordPress 6.5.2">'
                '</head><body>Login</body></html>'
            ), []
        if "/sites/default/" in url or "/administrator/" in url:
            return 404, {}, "", []
        return 200, {}, "<html><body>Home</body></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    assert any(t["name"] == "WordPress" for t in result["technologies"])


@pytest.mark.asyncio
async def test_drupal_not_detected_when_403_echoes_path():
    """
    Generic 403 pages that echo '/sites/default/' in their body must NOT
    trigger Drupal detection — the URL echo is not a Drupal signal.
    """
    async def fake_fetch(url, timeout=10):
        if "/sites/default/" in url:
            return 403, {}, (
                "<html><body><h1>403 Forbidden</h1>"
                "<p>Access to /sites/default/ is denied.</p>"
                "</body></html>"
            ), []
        if "/wp-login.php" in url or "/administrator/" in url:
            return 404, {}, "", []
        return 200, {}, "<html><body>Canva home</body></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://www.canva.com")

    assert not any(t["name"] == "Drupal" for t in result["technologies"])


@pytest.mark.asyncio
async def test_drupal_detected_when_body_has_drupal_settings():
    """drupalSettings in probe body → Drupal correctly confirmed."""
    async def fake_fetch(url, timeout=10):
        if "/sites/default/" in url:
            return 403, {}, (
                "<html><body>"
                "<script>var drupalSettings = {};</script>"
                "</body></html>"
            ), []
        if "/wp-login.php" in url or "/administrator/" in url:
            return 404, {}, "", []
        return 200, {}, "<html><body>Welcome</body></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    assert any(t["name"] == "Drupal" for t in result["technologies"])
