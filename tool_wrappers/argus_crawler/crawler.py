"""
ARGUS Crawler — BFS navigator using Playwright.

Crawls a web application like a human tester:
1. Browse first (no attacks) — build a complete mental model
2. Detect all input surfaces per page
3. Hand surfaces back to the agent for payload injection decisions
"""
from __future__ import annotations

import asyncio
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from shared.logger import audit

TOOL = "argus_crawler"


@dataclass
class PageNode:
    url:         str
    depth:       int
    method:      str = "GET"
    parent_url:  str = ""
    forms:       list[dict] = field(default_factory=list)
    links:       list[str] = field(default_factory=list)
    params:      list[str] = field(default_factory=list)
    title:       str = ""
    status:      int = 0
    content_type:str = ""
    screenshot:  Optional[bytes] = None


@dataclass
class CrawlResult:
    base_url:    str
    pages:       list[PageNode]
    total_forms: int
    total_inputs:int
    errors:      list[str]


class ArgusCrawler:
    def __init__(
        self,
        base_url: str,
        scope_domains: list[str] | None = None,
        max_depth: int = 3,
        max_pages: int = 100,
        headless: bool = True,
        slow_mo: int = 100,      # ms between actions — looks human
        viewport: dict | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.scope_domains = scope_domains or [self.base_domain]
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.headless = headless
        self.slow_mo = slow_mo
        self.viewport = viewport or {"width": 1280, "height": 900}
        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int, str]] = deque()  # (url, depth, parent)

    async def crawl(
        self,
        auth_cookies: dict | None = None,
        auth_headers: dict | None = None,
    ) -> CrawlResult:
        audit.tool_call(TOOL, "crawl_start", {
            "base_url": self.base_url,
            "max_depth": self.max_depth,
            "max_pages": self.max_pages,
        })

        pages: list[PageNode] = []
        errors: list[str] = []

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=self.headless, slow_mo=self.slow_mo)
            ctx: BrowserContext = await browser.new_context(
                viewport=self.viewport,
                extra_http_headers=auth_headers or {},
                record_har_path=None,  # HAR recorded per-page by evidence_collector
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
            )
            if auth_cookies:
                await ctx.add_cookies([
                    {"name": k, "value": v, "url": self.base_url}
                    for k, v in auth_cookies.items()
                ])

            self._queue.append((self.base_url, 0, ""))

            while self._queue and len(pages) < self.max_pages:
                url, depth, parent = self._queue.popleft()
                norm = self._normalize_url(url)
                if norm in self._visited or not self._in_scope(url):
                    continue
                self._visited.add(norm)

                page_node = await self._visit_page(ctx, url, depth, parent, errors)
                if page_node:
                    pages.append(page_node)
                    if depth < self.max_depth:
                        for link in page_node.links:
                            norm_link = self._normalize_url(link)
                            if norm_link not in self._visited and self._in_scope(link):
                                self._queue.append((link, depth + 1, url))

            await browser.close()

        total_forms = sum(len(p.forms) for p in pages)
        total_inputs = sum(sum(len(f.get("inputs", [])) for f in p.forms) for p in pages)

        audit.tool_call(TOOL, "crawl_complete", {
            "pages": len(pages),
            "forms": total_forms,
            "inputs": total_inputs,
            "errors": len(errors),
        })

        return CrawlResult(
            base_url=self.base_url,
            pages=pages,
            total_forms=total_forms,
            total_inputs=total_inputs,
            errors=errors,
        )

    async def _visit_page(
        self, ctx: BrowserContext, url: str, depth: int, parent: str, errors: list[str]
    ) -> Optional[PageNode]:
        page: Page = await ctx.new_page()
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=15000)
            status = resp.status if resp else 0
            content_type = resp.headers.get("content-type", "") if resp else ""

            # Skip non-HTML responses
            if content_type and "html" not in content_type and "javascript" not in content_type:
                return None

            title = await page.title()

            # Detect input surfaces
            from .form_detector import FormDetector
            detector = FormDetector(page)
            forms = await detector.detect_all()

            # Extract links
            links = await self._extract_links(page, url)

            # Extract URL params
            params = list(urlparse(url).query.split("&")) if "?" in url else []

            node = PageNode(
                url=url,
                depth=depth,
                parent_url=parent,
                forms=forms,
                links=links,
                params=params,
                title=title,
                status=status,
                content_type=content_type,
            )

            audit.tool_call(TOOL, "page_visited", {
                "url": url,
                "depth": depth,
                "status": status,
                "forms": len(forms),
                "links": len(links),
            })
            return node

        except Exception as e:
            errors.append(f"{url}: {e}")
            audit.error(TOOL, f"Failed to visit {url}: {e}")
            return None
        finally:
            await page.close()

    async def _extract_links(self, page: Page, base_url: str) -> list[str]:
        hrefs = await page.eval_on_selector_all(
            "a[href]",
            "els => els.map(el => el.href)"
        )
        links = []
        for href in hrefs:
            try:
                absolute = urljoin(base_url, href)
                parsed = urlparse(absolute)
                # Strip fragments, keep query strings
                clean = parsed._replace(fragment="").geturl()
                if clean not in links:
                    links.append(clean)
            except Exception:
                continue
        return links

    def _in_scope(self, url: str) -> bool:
        try:
            domain = urlparse(url).netloc
            return any(domain == sd or domain.endswith("." + sd) for sd in self.scope_domains)
        except Exception:
            return False

    def _normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            # Sort query params for deduplication
            from urllib.parse import parse_qsl, urlencode
            params = sorted(parse_qsl(parsed.query))
            norm = parsed._replace(
                query=urlencode(params),
                fragment="",
                scheme=parsed.scheme.lower(),
                netloc=parsed.netloc.lower(),
            ).geturl()
            return norm.rstrip("/")
        except Exception:
            return url
