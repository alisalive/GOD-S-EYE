"""
Technology / Version Fingerprinting — 50+ technologies detected.

Architecture for speed and accuracy:
  1. Single homepage fetch  — headers + body (no duplicate requests)
  2. All header checks run against the cached response
  3. Body parsed ONCE; all regex patterns applied in a single pass
  4. Targeted path probing only where body/header evidence warrants it
  5. All path probes run concurrently via asyncio.gather

Detection categories: Server, Language, CDN/Hosting, CMS, E-commerce,
  Framework, Frontend, Library, Analytics, Security

All network I/O is routed through _fetch_page() so tests can patch it
without spinning up a real HTTP server.
"""

import re
import asyncio

# ── Module-level I/O primitive (patchable in tests) ──────────────────────────

async def _fetch_page(url: str, timeout: int = 10) -> tuple:
    """
    Async GET; returns (status, headers_dict, body_str, set_cookie_list).
    Returns (0, {}, '', []) on any failure.
    """
    try:
        import aiohttp
        import ssl as ssl_lib
        ctx = ssl_lib.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_lib.CERT_NONE
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ctx),
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
        ) as s:
            async with s.get(url, allow_redirects=True) as resp:
                body = await resp.text(errors="ignore")
                headers = dict(resp.headers)
                try:
                    set_cookies = list(resp.headers.getall("Set-Cookie", []))
                except (AttributeError, TypeError):
                    set_cookies = []
                return resp.status, headers, body, set_cookies
    except Exception:
        return 0, {}, "", []


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hget(headers: dict, *keys: str) -> str:
    """Case-insensitive multi-key header lookup; returns first non-empty value."""
    for key in keys:
        for k in (key, key.lower(), key.upper()):
            v = headers.get(k, "")
            if v:
                return v
    return ""


def _cookies_from_set_cookie(set_cookie_list: list) -> dict:
    """Parse raw Set-Cookie header strings → {name_lower: raw_value}."""
    cookies: dict = {}
    for raw in set_cookie_list:
        if not raw:
            continue
        name_part = raw.split(";")[0].strip()
        if "=" in name_part:
            name, val = name_part.split("=", 1)
            cookies[name.strip().lower()] = val.strip()
    return cookies


# ── Pure detection functions (zero I/O — safe to call from tests) ────────────

def detect_server(headers: dict) -> list:
    """Detect web server from the Server header."""
    results = []
    server = _hget(headers, "Server")
    if not server:
        return results

    _patterns = [
        (r"Apache(?:/([\d.]+\w*))?",          "Apache",        "Server"),
        (r"nginx(?:/([\d.]+\w*))?",            "Nginx",         "Server"),
        (r"Microsoft-IIS(?:/([\d.]+\w*))?",    "IIS",           "Server"),
        (r"LiteSpeed(?:/([\d.]+\w*))?",        "LiteSpeed",     "Server"),
        (r"Caddy(?:/([\d.]+))?",               "Caddy",         "Server"),
        (r"gunicorn(?:/([\d.]+))?",            "Gunicorn",      "Server"),
        (r"uWSGI(?:/([\d.]+))?",               "uWSGI",         "Server"),
        (r"TornadoServer(?:/([\d.]+))?",       "Tornado",       "Server"),
        (r"Werkzeug(?:/([\d.]+))?",            "Flask/Werkzeug", "Framework"),
    ]
    for pattern, name, category in _patterns:
        m = re.search(pattern, server, re.IGNORECASE)
        if m:
            version = (m.group(1) or "") if m.lastindex else ""
            results.append({"name": name, "version": version,
                            "confidence": "high", "category": category,
                            "evidence": f"Server: {server}"})
    return results


def detect_language(headers: dict) -> list:
    """Detect backend language/runtime from X-Powered-By and related headers."""
    results = []
    powered_by = _hget(headers, "X-Powered-By")
    if not powered_by:
        return results

    if m := re.search(r"PHP(?:/([\d.]+))?", powered_by, re.IGNORECASE):
        results.append({"name": "PHP", "version": m.group(1) or "",
                        "confidence": "high", "category": "Language",
                        "evidence": f"X-Powered-By: {powered_by}"})
    if re.search(r"\bExpress\b", powered_by, re.IGNORECASE):
        results.append({"name": "Node.js/Express", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": f"X-Powered-By: {powered_by}"})
    if re.search(r"ASP\.NET", powered_by, re.IGNORECASE):
        mv = re.search(r"([\d.]+)", powered_by)
        results.append({"name": "ASP.NET", "version": mv.group(1) if mv else "",
                        "confidence": "high", "category": "Framework",
                        "evidence": f"X-Powered-By: {powered_by}"})
    return results


def detect_cdn(headers: dict) -> list:
    """Detect CDN and hosting providers from HTTP response headers."""
    results = []

    # Cloudflare
    if _hget(headers, "CF-Ray") or _hget(headers, "cf-cache-status"):
        results.append({"name": "Cloudflare", "version": "",
                        "confidence": "high", "category": "CDN",
                        "evidence": "CF-Ray or cf-cache-status header present"})

    # AWS CloudFront
    if _hget(headers, "X-Amz-Cf-Id"):
        results.append({"name": "AWS CloudFront", "version": "",
                        "confidence": "high", "category": "CDN",
                        "evidence": "X-Amz-Cf-Id header"})

    # Fastly
    if _hget(headers, "X-Fastly-Request-Id") or _hget(headers, "Fastly-Debug-Digest"):
        results.append({"name": "Fastly", "version": "",
                        "confidence": "high", "category": "CDN",
                        "evidence": "X-Fastly-Request-Id header"})

    # Akamai
    if (_hget(headers, "X-Akamai-Request-ID") or
            _hget(headers, "Akamai-Cache-Status") or
            _hget(headers, "X-Check-Cacheable")):
        results.append({"name": "Akamai", "version": "",
                        "confidence": "high", "category": "CDN",
                        "evidence": "Akamai-specific header"})

    # Vercel
    if _hget(headers, "X-Vercel-Id") or _hget(headers, "X-Vercel-Cache"):
        results.append({"name": "Vercel", "version": "",
                        "confidence": "high", "category": "CDN/Hosting",
                        "evidence": "X-Vercel-Id header"})

    # Netlify
    if _hget(headers, "X-Nf-Request-Id"):
        results.append({"name": "Netlify", "version": "",
                        "confidence": "high", "category": "CDN/Hosting",
                        "evidence": "X-Nf-Request-Id header"})

    # Heroku
    via = _hget(headers, "Via")
    if "heroku" in via.lower():
        results.append({"name": "Heroku", "version": "",
                        "confidence": "medium", "category": "CDN/Hosting",
                        "evidence": f"Via: {via}"})

    return results


def detect_cms_from_headers(headers: dict) -> list:
    """Detect CMS from X-Generator, X-Drupal-*, X-Powered-CMS, etc."""
    results = []

    xgen = _hget(headers, "X-Generator")
    if xgen:
        for cms, pattern in [
            ("Drupal",    r"Drupal\s*([\d.]+)?"),
            ("WordPress", r"WordPress\s*([\d.]+)?"),
            ("TYPO3",     r"TYPO3\s*([\d.]+)?"),
            ("Joomla",    r"Joomla!?\s*([\d.]+)?"),
        ]:
            if m := re.search(pattern, xgen, re.IGNORECASE):
                results.append({"name": cms, "version": m.group(1) or "",
                                "confidence": "high", "category": "CMS",
                                "evidence": f"X-Generator: {xgen}"})
                break

    # Drupal cache headers
    if _hget(headers, "X-Drupal-Cache") or _hget(headers, "X-Drupal-Dynamic-Cache"):
        results.append({"name": "Drupal", "version": "",
                        "confidence": "high", "category": "CMS",
                        "evidence": "X-Drupal-Cache header present"})

    # Bitrix
    powered_cms = _hget(headers, "X-Powered-CMS")
    if "bitrix" in powered_cms.lower():
        results.append({"name": "Bitrix", "version": "",
                        "confidence": "high", "category": "CMS",
                        "evidence": f"X-Powered-CMS: {powered_cms}"})

    # Spring Boot
    if _hget(headers, "X-Application-Context"):
        results.append({"name": "Spring Boot", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "X-Application-Context header"})

    # Ruby on Rails (X-Runtime is a float in seconds — very specific)
    xrt = _hget(headers, "X-Runtime")
    if xrt and re.match(r"^\d+\.\d{4,}$", xrt):
        results.append({"name": "Ruby on Rails", "version": "",
                        "confidence": "medium", "category": "Framework",
                        "evidence": f"X-Runtime: {xrt} (Rails response timing)"})

    return results


def _joomla_body_indicators(body: str) -> tuple:
    """
    Score Joomla-specific body signals (0–4 points).

    Signals:
      1. /media/system/js/ asset path
      2. <meta name="generator"> contains "Joomla"
      3. Literal "Joomla!" text
      4. Joomla component paths (com_content, com_users) alongside /templates/

    Returns (score: int, evidence: list[str]).
    Score ≥ 2 required to report — prevents false positives on Bitrix/Laravel.
    """
    score, evidence = 0, []

    if re.search(r"/media/system/js/", body, re.IGNORECASE):
        score += 1
        evidence.append("/media/system/js/ asset path")

    if (re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*Joomla',
                  body, re.IGNORECASE)
            or re.search(
                r'content=["\'][^"\']*Joomla[^"\']*["\'][^>]+name=["\']generator["\']',
                body, re.IGNORECASE)):
        score += 1
        evidence.append("meta generator: Joomla")

    if re.search(r"\bJoomla!", body):
        score += 1
        evidence.append('"Joomla!" text in body')

    if (re.search(r"/templates/[a-z0-9_-]+/", body, re.IGNORECASE)
            and re.search(r"com_content|com_users", body, re.IGNORECASE)):
        score += 1
        evidence.append("Joomla component + template paths")

    return score, evidence


def detect_cms_from_body(body: str) -> list:
    """Detect CMS platforms from HTML body asset paths and markers."""
    results = []
    if not body:
        return results

    # ── WordPress ──────────────────────────────────────────────────────────────
    if re.search(r"/wp-includes/|/wp-content/|/wp-json/", body, re.IGNORECASE):
        version = ""
        if m := re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*WordPress\s*([\d.]+)',
            body, re.IGNORECASE,
        ):
            version = m.group(1)
        results.append({"name": "WordPress", "version": version,
                        "confidence": "high", "category": "CMS",
                        "evidence": "/wp-content/ or /wp-includes/ in HTML"})
        # WooCommerce lives inside WordPress
        if re.search(r"\bwoocommerce\b|wc-add-to-cart", body, re.IGNORECASE):
            results.append({"name": "WooCommerce", "version": "",
                            "confidence": "high", "category": "E-commerce",
                            "evidence": "WooCommerce class/reference in body"})

    # ── Joomla (multi-indicator, ≥2 required) ─────────────────────────────────
    _jscore, _jev = _joomla_body_indicators(body)
    if _jscore >= 2:
        version = ""
        if m := re.search(r'content=["\'][^"\']*Joomla!\s*([\d.]+)', body, re.IGNORECASE):
            version = m.group(1)
        results.append({"name": "Joomla", "version": version,
                        "confidence": "high", "category": "CMS",
                        "evidence": "; ".join(_jev)})

    # ── Drupal ─────────────────────────────────────────────────────────────────
    if re.search(r"/sites/default/files/|drupalSettings|Drupal\.settings|/modules/system/",
                 body, re.IGNORECASE):
        results.append({"name": "Drupal", "version": "",
                        "confidence": "medium", "category": "CMS",
                        "evidence": "/sites/default/ or drupalSettings in body"})

    # ── Magento ────────────────────────────────────────────────────────────────
    if re.search(r"Mage\.Cookies|Magento_Ui|/static/frontend/|mageInit|window\.checkout",
                 body, re.IGNORECASE):
        version = ""
        if m := re.search(r"Magento[/\s]+([\d.]+)", body, re.IGNORECASE):
            version = m.group(1)
        results.append({"name": "Magento", "version": version,
                        "confidence": "high", "category": "CMS",
                        "evidence": "Magento-specific JS/path in body"})

    # ── PrestaShop ─────────────────────────────────────────────────────────────
    if re.search(r"prestashop|class=['\"][^'\"]*prestashop", body, re.IGNORECASE):
        results.append({"name": "PrestaShop", "version": "",
                        "confidence": "medium", "category": "CMS",
                        "evidence": "PrestaShop class/reference in body"})

    # ── OpenCart ───────────────────────────────────────────────────────────────
    if re.search(r"catalog/view/theme|route=common/home|\bOpenCart\b", body, re.IGNORECASE):
        results.append({"name": "OpenCart", "version": "",
                        "confidence": "high", "category": "CMS",
                        "evidence": "OpenCart path/reference in body"})

    # ── Ghost ──────────────────────────────────────────────────────────────────
    if re.search(r"/ghost/api/|ghost-blog|ghost-theme|data-ghost", body, re.IGNORECASE):
        results.append({"name": "Ghost", "version": "",
                        "confidence": "high", "category": "CMS",
                        "evidence": "Ghost CMS reference in body"})

    # ── Bitrix ─────────────────────────────────────────────────────────────────
    if re.search(r"bitrix/|BX\.|bitrix_sessid|1C-Bitrix", body, re.IGNORECASE):
        results.append({"name": "Bitrix", "version": "",
                        "confidence": "high", "category": "CMS",
                        "evidence": "Bitrix reference in body"})

    # ── TYPO3 ──────────────────────────────────────────────────────────────────
    if re.search(r"typo3temp/|typo3conf/|TYPO3\.CMS", body, re.IGNORECASE):
        results.append({"name": "TYPO3", "version": "",
                        "confidence": "high", "category": "CMS",
                        "evidence": "TYPO3 path/reference in body"})

    # ── Concrete CMS ───────────────────────────────────────────────────────────
    if re.search(r"CCM_DISPATCHER_FILENAME|concrete5|/concrete/", body, re.IGNORECASE):
        results.append({"name": "Concrete CMS", "version": "",
                        "confidence": "high", "category": "CMS",
                        "evidence": "Concrete CMS reference in body"})

    # ── MODx ───────────────────────────────────────────────────────────────────
    if re.search(r"assets/components/|modx_|MODx\b", body, re.IGNORECASE):
        results.append({"name": "MODx", "version": "",
                        "confidence": "medium", "category": "CMS",
                        "evidence": "MODx reference in body"})

    # ── Shopify ────────────────────────────────────────────────────────────────
    if re.search(r"cdn\.shopify\.com|Shopify\.theme|shopify_pay", body, re.IGNORECASE):
        results.append({"name": "Shopify", "version": "",
                        "confidence": "high", "category": "E-commerce",
                        "evidence": "Shopify CDN/theme reference in body"})

    # ── Strapi ─────────────────────────────────────────────────────────────────
    if re.search(r"/uploads/strapi|strapi\.io", body, re.IGNORECASE):
        results.append({"name": "Strapi", "version": "",
                        "confidence": "medium", "category": "CMS",
                        "evidence": "Strapi reference in body"})

    # ── Generic meta generator (fallback) ─────────────────────────────────────
    if m := re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        body, re.IGNORECASE,
    ):
        gen = m.group(1).strip()
        _already = {"wordpress", "joomla", "drupal", "magento", "prestashop",
                    "opencart", "ghost", "bitrix", "typo3", "modx", "strapi",
                    "concrete", "shopify"}
        if not any(k in gen.lower() for k in _already) and 2 < len(gen) < 80:
            results.append({"name": gen, "version": "",
                            "confidence": "medium", "category": "CMS",
                            "evidence": f"meta generator: {gen}"})

    return results


def detect_frameworks(headers: dict, body: str, cookies: dict) -> list:
    """Detect server-side frameworks from headers, body, and parsed cookies."""
    results = []

    # Laravel
    if "laravel_session" in cookies or re.search(
        r"laravel_session|laravel\.js|Laravel\s+Framework", body, re.IGNORECASE
    ):
        results.append({"name": "Laravel", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "laravel_session cookie or Laravel reference"})

    # Django
    if re.search(r"csrfmiddlewaretoken", body, re.IGNORECASE):
        results.append({"name": "Django", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "csrfmiddlewaretoken in body"})

    # Flask (eyJ… = base64-encoded JSON session cookie)
    if re.search(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+", body):
        results.append({"name": "Flask", "version": "",
                        "confidence": "medium", "category": "Framework",
                        "evidence": "Flask-style signed session token in body"})

    # Ruby on Rails (session cookie)
    if any(k.startswith("_session") for k in cookies) or "_rails" in cookies:
        results.append({"name": "Ruby on Rails", "version": "",
                        "confidence": "medium", "category": "Framework",
                        "evidence": "Rails session cookie"})

    # ASP.NET — require at least one strong signal; __VIEWSTATE alone is not
    # sufficient because other frameworks (e.g. Bitrix) use similar hidden fields.
    _aspnet_headers = (
        "ASP.NET" in _hget(headers, "X-Powered-By").upper()
        or bool(_hget(headers, "X-AspNet-Version"))
        or bool(_hget(headers, "X-AspNetMvc-Version"))
    )
    _aspnet_body_strong = bool(
        re.search(r"WebResource\.axd|ScriptResource\.axd", body, re.IGNORECASE)
    )
    _aspnet_viewstate = bool(
        re.search(r"__VIEWSTATE|__EVENTVALIDATION", body, re.IGNORECASE)
    )
    _aspnet_aspx = bool(
        re.search(r"\.aspx", body, re.IGNORECASE)
    )
    # Report ASP.NET only when a header confirms it, or when body has a
    # .axd resource (ASP.NET-exclusive), or __VIEWSTATE is accompanied by
    # an .aspx reference (VIEWSTATE alone is not unique to ASP.NET).
    if _aspnet_headers or _aspnet_body_strong or (_aspnet_viewstate and _aspnet_aspx):
        _aspnet_ev_parts = []
        if _aspnet_headers:
            _aspnet_ev_parts.append("ASP.NET header")
        if _aspnet_body_strong:
            _aspnet_ev_parts.append("WebResource/ScriptResource.axd")
        if _aspnet_viewstate and _aspnet_aspx:
            _aspnet_ev_parts.append("__VIEWSTATE + .aspx in body")
        results.append({"name": "ASP.NET", "version": _hget(headers, "X-AspNet-Version"),
                        "confidence": "high" if _aspnet_headers or _aspnet_body_strong else "medium",
                        "category": "Framework",
                        "evidence": "; ".join(_aspnet_ev_parts)})

    # CodeIgniter
    if "ci_session" in cookies or re.search(r"\bCodeIgniter\b", body):
        results.append({"name": "CodeIgniter", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "ci_session cookie or CodeIgniter reference"})

    # Symfony
    if _hget(headers, "X-Debug-Token") or any(
        k.startswith("sf2_") or k.startswith("sftoken") for k in cookies
    ):
        results.append({"name": "Symfony", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "X-Debug-Token header or sf2_ cookie"})

    # CakePHP
    if any(k.startswith("cake") for k in cookies) or re.search(
        r"cakephp|CakePHP", body, re.IGNORECASE
    ):
        results.append({"name": "CakePHP", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "CakePHP cookie or reference"})

    # Yii Framework
    if re.search(r"YII_CSRF_TOKEN|yii\.js|Yii\s+Framework", body, re.IGNORECASE):
        results.append({"name": "Yii", "version": "",
                        "confidence": "medium", "category": "Framework",
                        "evidence": "Yii reference in body"})

    return results


def detect_frontend(body: str) -> list:
    """Detect JavaScript frameworks and UI libraries from HTML body."""
    results = []
    if not body:
        return results

    # ── Meta-frameworks (SSR/SSG — check before bare React/Vue) ──────────────
    if re.search(r"__NEXT_DATA__|/_next/static/", body, re.IGNORECASE):
        results.append({"name": "Next.js", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "__NEXT_DATA__ or /_next/static/"})
    elif re.search(r"__NUXT__|/_nuxt/", body, re.IGNORECASE):
        results.append({"name": "Nuxt.js", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "__NUXT__ or /_nuxt/ in body"})
    elif re.search(r'gatsby-|/page-data/', body, re.IGNORECASE):
        results.append({"name": "Gatsby", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "gatsby- path reference in body"})
    elif re.search(r"data-react-root|__react_fiber|react-root|_reactFiber|ReactDOM",
                   body, re.IGNORECASE):
        results.append({"name": "React", "version": "",
                        "confidence": "medium", "category": "Framework",
                        "evidence": "React root marker in body"})

    # Vue.js
    if re.search(r"__vue_app__|vue\.min\.js|vue\.global\.js|@vue/", body, re.IGNORECASE):
        results.append({"name": "Vue.js", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "__vue_app__ or Vue.js script"})

    # Angular (ng-version attribute is definitive)
    if m := re.search(r'ng-version=["\']?([\d.]+)', body, re.IGNORECASE):
        results.append({"name": "Angular", "version": m.group(1),
                        "confidence": "high", "category": "Framework",
                        "evidence": f"ng-version={m.group(1)}"})
    elif re.search(r"angular(?:\.min)?\.js|/angular/core|\bng-app\b", body, re.IGNORECASE):
        results.append({"name": "Angular", "version": "",
                        "confidence": "medium", "category": "Framework",
                        "evidence": "angular.js or ng-app reference"})

    # Svelte (hashed class attribute is the fingerprint)
    if re.search(r'class="[^"]*svelte-[a-z0-9]+|__SVELTE__|svelte/internal', body, re.IGNORECASE):
        results.append({"name": "Svelte", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "Svelte hashed class or reference"})

    # ── Libraries ─────────────────────────────────────────────────────────────

    # jQuery (versioned filename → high; generic → medium)
    if m := re.search(r'["\'/]jquery[/\-]([\d.]+)(?:\.min)?\.js', body, re.IGNORECASE):
        results.append({"name": "jQuery", "version": m.group(1),
                        "confidence": "high", "category": "Library",
                        "evidence": f"jquery-{m.group(1)}.js in asset path"})
    elif re.search(r'jquery(?:\.min)?\.js', body, re.IGNORECASE):
        results.append({"name": "jQuery", "version": "",
                        "confidence": "medium", "category": "Library",
                        "evidence": "jQuery script reference"})

    # Bootstrap (versioned filename → high; generic → medium)
    if m := re.search(r'bootstrap[/\-]([\d.]+)(?:\.min)?\.(?:css|js)', body, re.IGNORECASE):
        results.append({"name": "Bootstrap", "version": m.group(1),
                        "confidence": "high", "category": "Library",
                        "evidence": f"bootstrap-{m.group(1)} asset"})
    elif re.search(r'bootstrap(?:\.min)?\.(?:css|js)', body, re.IGNORECASE):
        results.append({"name": "Bootstrap", "version": "",
                        "confidence": "medium", "category": "Library",
                        "evidence": "Bootstrap CSS/JS reference"})

    # Tailwind CSS
    if re.search(r'tailwind(?:css)?(?:\.min)?\.css|@tailwindcss', body, re.IGNORECASE):
        results.append({"name": "Tailwind CSS", "version": "",
                        "confidence": "high", "category": "Library",
                        "evidence": "Tailwind CSS stylesheet reference"})

    # Lodash
    if re.search(r'lodash(?:\.min)?\.js|lodash@[\d.]', body, re.IGNORECASE):
        results.append({"name": "Lodash", "version": "",
                        "confidence": "medium", "category": "Library",
                        "evidence": "Lodash script reference"})

    # Moment.js
    if re.search(r'moment(?:\.min)?\.js|moment@[\d.]', body, re.IGNORECASE):
        results.append({"name": "Moment.js", "version": "",
                        "confidence": "medium", "category": "Library",
                        "evidence": "Moment.js script reference"})

    # D3.js (versioned → high)
    if m := re.search(r'd3(?:\.v([\d]+))?(?:\.min)?\.js', body, re.IGNORECASE):
        results.append({"name": "D3.js", "version": m.group(1) or "",
                        "confidence": "high", "category": "Library",
                        "evidence": "D3.js script reference"})

    # Font Awesome
    if m := re.search(r'font-awesome/([\d.]+)|fontawesome', body, re.IGNORECASE):
        results.append({"name": "Font Awesome", "version": m.group(1) if m.lastindex and m.group(1) else "",
                        "confidence": "medium", "category": "Library",
                        "evidence": "Font Awesome reference"})

    return results


def detect_analytics(body: str) -> list:
    """Detect analytics and tracking scripts from body."""
    results = []
    if not body:
        return results

    if re.search(r"gtag\(|ga\(|UA-\d+-\d+|G-[A-Z0-9]+", body):
        results.append({"name": "Google Analytics", "version": "",
                        "confidence": "high", "category": "Analytics",
                        "evidence": "gtag()/ga() or tracking ID in body"})

    if re.search(r"GTM-[A-Z0-9]+|googletagmanager\.com/gtm", body):
        results.append({"name": "Google Tag Manager", "version": "",
                        "confidence": "high", "category": "Analytics",
                        "evidence": "GTM container ID in body"})

    if re.search(r"fbq\(|facebook\.com/tr\?|connect\.facebook\.net.*fbevents",
                 body, re.IGNORECASE):
        results.append({"name": "Facebook Pixel", "version": "",
                        "confidence": "high", "category": "Analytics",
                        "evidence": "fbq() or Facebook Pixel in body"})

    if re.search(r"hjid|hotjar\.com/|_hjSettings", body, re.IGNORECASE):
        results.append({"name": "Hotjar", "version": "",
                        "confidence": "high", "category": "Analytics",
                        "evidence": "Hotjar tracking code in body"})

    if re.search(r"mixpanel\.com/lib|mixpanel\.init|api\.mixpanel\.com", body, re.IGNORECASE):
        results.append({"name": "Mixpanel", "version": "",
                        "confidence": "high", "category": "Analytics",
                        "evidence": "Mixpanel SDK in body"})

    if re.search(r"cdn\.segment\.com|analytics\.load\(|segment\.com/analytics\.js",
                 body, re.IGNORECASE):
        results.append({"name": "Segment", "version": "",
                        "confidence": "high", "category": "Analytics",
                        "evidence": "Segment analytics in body"})

    if re.search(r"cfBeacon|cloudflareinsights\.com", body, re.IGNORECASE):
        results.append({"name": "Cloudflare Analytics", "version": "",
                        "confidence": "high", "category": "Analytics",
                        "evidence": "Cloudflare Web Analytics beacon"})

    return results


def detect_security_tools(body: str) -> list:
    """Detect CAPTCHA and other security tools from body."""
    results = []
    if not body:
        return results

    if re.search(r"www\.google\.com/recaptcha|grecaptcha\.", body, re.IGNORECASE):
        results.append({"name": "Google reCAPTCHA", "version": "",
                        "confidence": "high", "category": "Security",
                        "evidence": "reCAPTCHA script in body"})

    if re.search(r"hcaptcha\.com|h-captcha", body, re.IGNORECASE):
        results.append({"name": "hCaptcha", "version": "",
                        "confidence": "high", "category": "Security",
                        "evidence": "hCaptcha in body"})

    if re.search(r"challenges\.cloudflare\.com/turnstile", body, re.IGNORECASE):
        results.append({"name": "Cloudflare Turnstile", "version": "",
                        "confidence": "high", "category": "Security",
                        "evidence": "Cloudflare Turnstile in body"})

    return results


def detect_ecommerce_tools(body: str) -> list:
    """Detect payment and e-commerce tools from body."""
    results = []
    if not body:
        return results

    if re.search(r"js\.stripe\.com|Stripe\(", body, re.IGNORECASE):
        results.append({"name": "Stripe", "version": "",
                        "confidence": "high", "category": "E-commerce",
                        "evidence": "Stripe JS in body"})

    if re.search(r"paypal\.com/sdk/js|paypalobjects\.com|PayPal\.Buttons",
                 body, re.IGNORECASE):
        results.append({"name": "PayPal", "version": "",
                        "confidence": "high", "category": "E-commerce",
                        "evidence": "PayPal SDK in body"})

    return results


# ── CMS body-confirmation keywords (used by targeted path probes) ─────────────

_CMS_BODY_CONFIRM: dict = {
    # Require path-based asset references — generic 404/403 pages never contain
    # these.  "wp-login.php" and "WordPress" removed: they appear verbatim in
    # many error pages that echo the requested URL back to the browser.
    "WordPress": ["/wp-content/", "/wp-includes/"],
    # "Drupal" standalone and "/sites/default/" removed: the former is too
    # generic and the latter always appears on 404/403 pages that echo the URL.
    "Drupal":    ["drupalSettings", "Drupal.settings"],
}


# ── Concurrent path probe helper ──────────────────────────────────────────────

async def _probe(base_url: str, path: str) -> tuple:
    """Probe a single path; returns (path, status, headers, body)."""
    url = base_url.rstrip("/") + path
    status, headers, body, _ = await _fetch_page(url, timeout=6)
    return path, status, headers, body


# ── Main async entry point ────────────────────────────────────────────────────

async def run_fingerprint(base_url: str, console=None) -> dict:
    """
    Detect technologies for a single base_url.

    Strategy (optimised for speed):
      1. ONE homepage fetch — parse headers + body simultaneously
      2. All pure detectors run against the cached data (zero extra requests)
      3. Targeted concurrent path probes only where evidence warrants them:
           • /wp-login.php  — when WordPress not already confirmed
           • /sites/default/ — when Drupal not already confirmed
           • /administrator/ — when Joomla body score is exactly 1

    Returns:
        {"base_url": str, "technologies": [{name, version, confidence, category, evidence}, ...]}
    """

    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    technologies: list = []
    seen: set = set()

    def _add(entry: dict):
        key = entry["name"].lower()
        if key not in seen:
            seen.add(key)
            technologies.append(entry)

    log(f"Fingerprinting {base_url} …")

    # ── Step 1: Single homepage fetch ─────────────────────────────────────────
    status, headers, body, set_cookies = await _fetch_page(base_url, timeout=10)
    if not status:
        return {"base_url": base_url, "technologies": []}

    cookies = _cookies_from_set_cookie(set_cookies)

    # ── Step 2: All pure detectors against the cached response ─────────────────
    for t in detect_server(headers):              _add(t)
    for t in detect_language(headers):            _add(t)
    for t in detect_cdn(headers):                 _add(t)
    for t in detect_cms_from_headers(headers):    _add(t)
    for t in detect_cms_from_body(body):          _add(t)
    for t in detect_frameworks(headers, body, cookies): _add(t)
    for t in detect_frontend(body):               _add(t)
    for t in detect_analytics(body):              _add(t)
    for t in detect_security_tools(body):         _add(t)
    for t in detect_ecommerce_tools(body):        _add(t)

    # ── Step 3: Targeted concurrent path probes ────────────────────────────────
    _probes: list = []
    _joomla_body_score, _joomla_body_ev = _joomla_body_indicators(body)

    if "wordpress" not in seen:
        _probes.append(_probe(base_url, "/wp-login.php"))
    if "drupal" not in seen:
        _probes.append(_probe(base_url, "/sites/default/"))
    if "joomla" not in seen and _joomla_body_score == 1:
        # One body signal: probe /administrator/ to reach score 2
        _probes.append(_probe(base_url, "/administrator/"))

    if _probes:
        _probe_results = await asyncio.gather(*_probes, return_exceptions=True)
        for result in _probe_results:
            if isinstance(result, Exception):
                continue
            path, p_status, _, p_body = result
            if p_status not in (200, 301, 302, 403):
                continue

            if "/wp-login.php" in path and "wordpress" not in seen:
                _pb = p_body or ""
                _wp_confirmed = (
                    # Asset-path evidence — genuine WP pages load CSS/JS from these
                    any(kw in _pb for kw in _CMS_BODY_CONFIRM["WordPress"])
                    # Meta generator tag: <meta name="generator" content="WordPress …">
                    or re.search(
                        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*WordPress',
                        _pb, re.IGNORECASE,
                    )
                )
                if _wp_confirmed:
                    _add({"name": "WordPress", "version": "",
                          "confidence": "high", "category": "CMS",
                          "evidence": f"HTTP {p_status} on /wp-login.php (body confirmed)"})

            elif "/sites/default/" in path and "drupal" not in seen:
                confirm = _CMS_BODY_CONFIRM["Drupal"]
                if any(kw.lower() in (p_body or "").lower() for kw in confirm):
                    _add({"name": "Drupal", "version": "",
                          "confidence": "high", "category": "CMS",
                          "evidence": f"HTTP {p_status} on /sites/default/ (body confirmed)"})

            elif "/administrator/" in path and "joomla" not in seen:
                if (p_status == 200
                        and re.search(r"administrator|joomla", p_body or "", re.IGNORECASE)):
                    _ev = _joomla_body_ev + ["HTTP 200 on /administrator/ with Joomla content"]
                    _add({"name": "Joomla", "version": "",
                          "confidence": "high", "category": "CMS",
                          "evidence": "; ".join(_ev)})

    return {"base_url": base_url, "technologies": technologies}
