"""
Screenshot Module — Playwright-based web screenshots, base64-embedded in reports.
"""

import asyncio
import base64
import os
from pathlib import Path
from core.orchestrator import EngagementState, Finding, Severity

SCREENSHOT_DIR = "reports/screenshots"


async def take_screenshot(url: str, output_path: str, timeout: int = 15000) -> dict:
    """Take a screenshot of a URL. Returns dict with path, base64, error."""
    result = {"url": url, "path": None, "base64": None, "error": None}
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--ignore-certificate-errors"]
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )
            page = await context.new_page()

            try:
                await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                await page.wait_for_timeout(2000)
                await page.screenshot(path=output_path, full_page=False)

                with open(output_path, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode("utf-8")

                result["path"] = output_path
                result["base64"] = b64
            except Exception as e:
                result["error"] = str(e)
            finally:
                await context.close()
                await browser.close()

    except ImportError:
        result["error"] = "playwright not installed — run: pip install playwright && playwright install chromium"
    except Exception as e:
        result["error"] = str(e)

    return result


async def run_screenshots(state: EngagementState, console=None,
                           output_dir: str = None) -> dict:
    """Screenshot all open web ports."""
    screenshot_dir = output_dir or SCREENSHOT_DIR
    Path(screenshot_dir).mkdir(parents=True, exist_ok=True)

    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    web_services = state.recon_data.get("web", {})
    if not web_services:
        log("No web services found for screenshots")
        return {}

    screenshots = {}
    tasks = []
    urls = []

    for port, winfo in web_services.items():
        url = winfo.get("url", "")
        if not url:
            continue
        safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")[:50]
        out_path = os.path.join(screenshot_dir, f"screenshot_{safe_name}.png")
        tasks.append(take_screenshot(url, out_path))
        urls.append((port, url))

    if not tasks:
        return {}

    log(f"Taking {len(tasks)} screenshot(s)...")
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for (port, url), result in zip(urls, results):
        if isinstance(result, Exception):
            screenshots[str(port)] = {"url": url, "error": str(result)}
            log(f"  Screenshot failed for {url}: {result}")
        elif result.get("error"):
            screenshots[str(port)] = {"url": url, "error": result["error"]}
            log(f"  Screenshot error for {url}: {result['error']}")
        else:
            screenshots[str(port)] = result
            log(f"  [green]✓[/green] Screenshot saved: {result['path']}")

    state.recon_data["screenshots"] = screenshots
    state.add_note(f"Screenshots: {sum(1 for s in screenshots.values() if not s.get('error'))} captured")
    return screenshots
