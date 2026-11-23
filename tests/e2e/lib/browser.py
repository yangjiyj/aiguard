# KNOWN-LIMIT: Playwright native install fails on ubuntu 26.04.
# Browser tests require docker fallback or a supported distro.
# Set E2E_USE_DOCKER_PLAYWRIGHT=1 to skip native browser tests.

import asyncio
import os
from pathlib import Path

WEB_BASE = os.getenv("E2E_WEB_BASE", "http://127.0.0.1:3000")
REPORTS = Path(os.getenv("E2E_REPORTS", "/home/dev/jjdguard-src/tests/e2e/reports/latest"))
USE_DOCKER = os.getenv("E2E_USE_DOCKER_PLAYWRIGHT", "0") == "1"

try:
    from playwright.async_api import async_playwright, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class BrowserSession:
    def __init__(self):
        self.pw = None
        self.browser = None
        self.ctx = None
        self._available = PLAYWRIGHT_AVAILABLE and not USE_DOCKER

    async def start(self):
        if not self._available:
            return
        self.pw = await async_playwright().start()
        try:
            self.browser = await self.pw.chromium.launch(headless=True)
            self.ctx = await self.browser.new_context(
                viewport={"width": 1440, "height": 900}
            )
        except Exception as e:
            # Chromium binary not found (unsupported OS) → mark unavailable
            self._available = False
            await self.pw.stop()
            self.pw = None

    async def stop(self):
        if self.ctx:
            await self.ctx.close()
        if self.browser:
            await self.browser.close()
        if self.pw:
            await self.pw.stop()

    async def login(self, page):
        await page.goto(f"{WEB_BASE}/login")
        # Try multiple selectors for robustness
        await page.fill(
            'input[name="username"], input[placeholder*="用户名"], input[type="text"]',
            os.getenv("E2E_ADMIN_USER", "admin"),
        )
        await page.fill(
            'input[type="password"]',
            os.getenv("E2E_ADMIN_PASS", "NapiE2E#2026!"),
        )
        await page.click('button[type="submit"], button:has-text("登录")')
        await page.wait_for_url(lambda u: "/login" not in u, timeout=10000)

    async def snapshot(self, page, name: str):
        REPORTS.mkdir(parents=True, exist_ok=True)
        safe_name = name.replace("/", "_").replace(" ", "_")
        await page.screenshot(
            path=str(REPORTS / f"{safe_name}.png"), full_page=True
        )

    @property
    def available(self) -> bool:
        return self._available
