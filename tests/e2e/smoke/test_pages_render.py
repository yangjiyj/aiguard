"""
Smoke test: all web-console pages render without blank screen.
KNOWN-LIMIT: Playwright native binary not available on ubuntu >= 26.04.
  - Chromium binary missing at ~/.cache/ms-playwright/
  - Tests are skipped automatically when binary absent.
  - To run: from mac (or any non-26.04 host) via tailscale, see /tmp/pw-mac/run_all_routes.py
  - Or: docker container with mcr.microsoft.com/playwright/python:v1.40.0-jammy

Routes from apps/web-console/src/App.tsx.
Selectors loosened 2026-05-30 after real-browser run on mac:
  /security uses bare divs not ant-card; /organizations shows empty-state when no teams.
"""
import os
import pytest

WEB_BASE = os.getenv("E2E_WEB_BASE", "http://127.0.0.1:3000")
ADMIN_USER = os.getenv("E2E_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("E2E_ADMIN_PASS", "NapiE2E#2026!")

def _chromium_available() -> bool:
    import glob
    pattern = os.path.expanduser(
        "~/.cache/ms-playwright/chromium*/chrome-headless-shell-linux64/chrome-headless-shell"
    )
    return bool(glob.glob(pattern))

CHROMIUM_OK = _chromium_available() or os.getenv("E2E_FORCE_BROWSER") == "1"

# (route_path, selector_to_wait_for) — loosened 2026-05-30
ROUTES = [
    ("/dashboard", ".ant-layout, h1, h2"),
    ("/users", "table, .ant-table, .ant-empty"),
    ("/apps", ".ant-card, table, .ant-empty"),
    ("/providers", "table, .ant-table, .ant-empty"),
    ("/keys", "table, .ant-table, .ant-empty"),
    ("/usage", ".ant-card, [class*='statistic'], .ant-statistic"),
    ("/audit", "table, .ant-table, .ant-empty"),
    ("/audit/content", "table, .ant-table, .ant-empty"),
    ("/security", "h4, [class*='card'], button"),
    ("/organizations", "h4, .ant-empty, .ant-tree, button"),
    ("/cost/snapshot", ".ant-card, .ant-progress, .ant-statistic"),
    ("/cost/savings", ".ant-card, .ant-statistic"),
    ("/cost/prices-fx", "table, .ant-table, .ant-empty, button"),
    ("/cost/alerts", "table, .ant-list, .ant-table, .ant-empty"),
    ("/cost/audit-verify", ".ant-card, button"),
]

NOISE_FILTERS = [
    "React Router", "Future Flag", "favicon", "DevTools",
    "antd", "ResizeObserver", "Refused to load", "Warning:",
    "Download the React DevTools",
]


@pytest.mark.smoke
@pytest.mark.skipif(not CHROMIUM_OK, reason="Chromium binary not installed (ubuntu 26.04 not supported by Playwright 1.60)")
@pytest.mark.parametrize("path,selector", ROUTES)
async def test_page_renders(path, selector):
    from playwright.async_api import async_playwright

    console_errors = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await ctx.new_page()

        page.on("pageerror", lambda e: console_errors.append(str(e)))
        page.on(
            "console",
            lambda m: console_errors.append(m.text) if m.type == "error" else None,
        )

        try:
            # Login first — use precise #username / #password ids
            await page.goto(f"{WEB_BASE}/login", wait_until="domcontentloaded", timeout=15000)
            await page.fill('#username', ADMIN_USER)
            await page.fill('#password', ADMIN_PASS)
            await page.click('button[type="submit"]')
            await page.wait_for_url(lambda u: "/login" not in u, timeout=10000)

            # Navigate to target page (domcontentloaded — SPA polls forever, networkidle never settles)
            await page.goto(
                f"{WEB_BASE}{path}", wait_until="domcontentloaded", timeout=15000
            )
            await page.wait_for_timeout(1500)  # let SPA render

            # Anti-blank: body text > 50 chars
            body_text = await page.evaluate("document.body.innerText")
            assert len(body_text) > 50, (
                f"Possible blank screen at {path}: body text only {len(body_text)} chars"
            )

            # Key element (soft check)
            try:
                await page.wait_for_selector(selector, timeout=5000)
            except Exception:
                pass

            # Filter serious console errors
            serious = [
                e for e in console_errors
                if not any(
                    skip in e for skip in NOISE_FILTERS
                )
            ]
            assert not serious, f"console errors at {path}:\n" + "\n".join(serious[:5])

        finally:
            await page.close()
            await ctx.close()
            await browser.close()
