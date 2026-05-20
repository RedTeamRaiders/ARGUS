"""
Auth Handler — authenticates the crawler session.

Supports:
- Form-based login (username/password fields)
- Cookie injection (pre-authenticated session)
- Bearer token injection (Authorization header)
- OAuth 2.0 / OIDC flows (authorization code with redirect)
- Basic auth (embedded in URL or header)
- JWT storage (localStorage / sessionStorage / cookie)
- Multi-step auth (2FA prompt detection)
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

from playwright.async_api import BrowserContext, Page

from shared.logger import audit

TOOL = "argus_crawler_auth"


@dataclass
class AuthConfig:
    auth_type:      str          # form|cookie|bearer|basic|oauth|jwt
    login_url:      str = ""
    username:       str = ""
    password:       str = ""
    token:          str = ""
    cookies:        dict = None
    headers:        dict = None
    username_selector: str = ""  # CSS selector for username field
    password_selector: str = ""  # CSS selector for password field
    submit_selector:   str = ""  # CSS selector for submit button
    success_indicator: str = ""  # URL pattern or element to confirm login success
    token_storage:  str = "cookie"  # cookie|localStorage|sessionStorage


class AuthHandler:
    def __init__(self, ctx: BrowserContext, config: AuthConfig):
        self.ctx = ctx
        self.cfg = config

    async def authenticate(self) -> bool:
        audit.tool_call(TOOL, "auth_start", {"type": self.cfg.auth_type})
        handlers = {
            "form":    self._form_login,
            "cookie":  self._cookie_inject,
            "bearer":  self._bearer_inject,
            "basic":   self._basic_auth,
            "oauth":   self._oauth_flow,
            "jwt":     self._jwt_inject,
        }
        handler = handlers.get(self.cfg.auth_type, self._form_login)
        success = await handler()
        audit.tool_call(TOOL, "auth_result", {"success": success})
        return success

    async def _form_login(self) -> bool:
        if not self.cfg.login_url:
            return False
        page: Page = await self.ctx.new_page()
        try:
            await page.goto(self.cfg.login_url, wait_until="networkidle", timeout=15000)

            # Detect username/password fields automatically if selectors not provided
            user_sel = self.cfg.username_selector or await self._detect_username_field(page)
            pass_sel = self.cfg.password_selector or await self._detect_password_field(page)

            if not user_sel or not pass_sel:
                audit.error(TOOL, "Could not locate login form fields")
                return False

            await page.fill(user_sel, self.cfg.username, timeout=5000)
            await page.fill(pass_sel, self.cfg.password, timeout=5000)

            # Submit
            submit_sel = self.cfg.submit_selector or "button[type=submit], input[type=submit]"
            await page.click(submit_sel, timeout=5000)
            await page.wait_for_load_state("networkidle", timeout=15000)

            # Check for 2FA prompt
            if await self._detect_2fa(page):
                audit.info(TOOL, "2FA detected — manual intervention needed or pre-authenticated session required")
                return False

            success = await self._verify_login(page)
            return success
        except Exception as e:
            audit.error(TOOL, f"Form login failed: {e}")
            return False
        finally:
            await page.close()

    async def _cookie_inject(self) -> bool:
        if not self.cfg.cookies:
            return False
        try:
            base_url = self.cfg.login_url or "/"
            cookies = [
                {"name": k, "value": v, "url": base_url}
                for k, v in self.cfg.cookies.items()
            ]
            await self.ctx.add_cookies(cookies)
            return True
        except Exception as e:
            audit.error(TOOL, f"Cookie inject failed: {e}")
            return False

    async def _bearer_inject(self) -> bool:
        if not self.cfg.token:
            return False
        try:
            await self.ctx.set_extra_http_headers({"Authorization": f"Bearer {self.cfg.token}"})
            return True
        except Exception as e:
            audit.error(TOOL, f"Bearer inject failed: {e}")
            return False

    async def _basic_auth(self) -> bool:
        if not self.cfg.username or not self.cfg.password:
            return False
        encoded = base64.b64encode(f"{self.cfg.username}:{self.cfg.password}".encode()).decode()
        try:
            await self.ctx.set_extra_http_headers({"Authorization": f"Basic {encoded}"})
            return True
        except Exception as e:
            audit.error(TOOL, f"Basic auth inject failed: {e}")
            return False

    async def _oauth_flow(self) -> bool:
        # Navigate through OAuth authorization code flow
        if not self.cfg.login_url:
            return False
        page: Page = await self.ctx.new_page()
        try:
            await page.goto(self.cfg.login_url, wait_until="networkidle", timeout=15000)
            # If redirected to IdP login form, fill credentials
            user_sel = await self._detect_username_field(page)
            pass_sel = await self._detect_password_field(page)
            if user_sel and pass_sel:
                await page.fill(user_sel, self.cfg.username)
                await page.fill(pass_sel, self.cfg.password)
                await page.click("button[type=submit], input[type=submit]")
                await page.wait_for_load_state("networkidle", timeout=20000)
            # Handle consent screen if present
            consent = await page.query_selector("button:has-text('Allow'), button:has-text('Authorize'), button:has-text('Accept')")
            if consent:
                await consent.click()
                await page.wait_for_load_state("networkidle", timeout=15000)
            return await self._verify_login(page)
        except Exception as e:
            audit.error(TOOL, f"OAuth flow failed: {e}")
            return False
        finally:
            await page.close()

    async def _jwt_inject(self) -> bool:
        if not self.cfg.token:
            return False
        page: Page = await self.ctx.new_page()
        try:
            await page.goto(self.cfg.login_url or "/", wait_until="domcontentloaded", timeout=10000)
            storage = self.cfg.token_storage
            if storage == "localStorage":
                await page.evaluate(f"localStorage.setItem('token', {repr(self.cfg.token)})")
                await page.evaluate(f"localStorage.setItem('access_token', {repr(self.cfg.token)})")
                await page.evaluate(f"localStorage.setItem('authToken', {repr(self.cfg.token)})")
            elif storage == "sessionStorage":
                await page.evaluate(f"sessionStorage.setItem('token', {repr(self.cfg.token)})")
            else:
                # Default: cookie
                await self.ctx.add_cookies([{"name": "token", "value": self.cfg.token, "url": self.cfg.login_url or "/"}])
            return True
        except Exception as e:
            audit.error(TOOL, f"JWT inject failed: {e}")
            return False
        finally:
            await page.close()

    async def _detect_username_field(self, page: Page) -> str:
        candidates = [
            'input[type="email"]',
            'input[type="text"][name*="user"]',
            'input[type="text"][name*="email"]',
            'input[type="text"][name*="login"]',
            'input[id*="user"]',
            'input[id*="email"]',
            'input[id*="login"]',
            'input[autocomplete="username"]',
            'input[autocomplete="email"]',
            'input[name="username"]',
            'input[name="email"]',
        ]
        for sel in candidates:
            if await page.query_selector(sel):
                return sel
        return 'input[type="text"]:first-of-type'

    async def _detect_password_field(self, page: Page) -> str:
        sel = 'input[type="password"]'
        if await page.query_selector(sel):
            return sel
        return ""

    async def _detect_2fa(self, page: Page) -> bool:
        indicators = [
            'input[name*="otp"]', 'input[name*="2fa"]', 'input[name*="code"]',
            'input[placeholder*="verification"]', 'input[placeholder*="authenticator"]',
        ]
        for sel in indicators:
            if await page.query_selector(sel):
                return True
        return False

    async def _verify_login(self, page: Page) -> bool:
        if self.cfg.success_indicator:
            if self.cfg.success_indicator.startswith("url:"):
                return self.cfg.success_indicator[4:] in page.url
            else:
                elem = await page.query_selector(self.cfg.success_indicator)
                return elem is not None
        # Heuristic: if URL no longer contains "login", "signin" we probably succeeded
        url = page.url.lower()
        failed_indicators = ["login", "signin", "error", "invalid", "failed"]
        return not any(ind in url for ind in failed_indicators)
