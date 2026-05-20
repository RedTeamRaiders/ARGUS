"""
Execution Monitor — detects XSS payload execution via multiple signals.

Signals monitored:
1. page.on('dialog')  → alert()/confirm()/prompt() fired = confirmed XSS
2. page.on('console') → payload echoes, JS errors, onerror triggers
3. page.on('request') → OOB callbacks (blind XSS, SSRF canaries)
4. DOM MutationObserver → stored/DOM XSS deferred render
5. page.evaluate()    → cookie access, location.href change, title change
6. page.on('pageerror') → uncaught JS exceptions (may indicate partial execution)
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable, Optional

from playwright.async_api import Dialog, Page, Request


@dataclass
class ExecutionEvent:
    signal:     str       # dialog|console|oob_request|dom_mutation|eval|pageerror
    payload:    str
    evidence:   str       # what triggered — dialog message, console log, request URL, DOM change
    url:        str
    confirmed:  bool = True  # dialog = always confirmed; others need correlation
    timestamp:  float = 0.0


class ExecutionMonitor:
    def __init__(self, page: Page, canary_token: str = "argus_xss_"):
        self.page = page
        self.canary = canary_token
        self.events: list[ExecutionEvent] = []
        self._dialog_handled = asyncio.Event()
        self._oob_patterns: list[str] = []

    async def __aenter__(self):
        await self._attach_listeners()
        return self

    async def __aexit__(self, *_):
        await self._detach_listeners()

    async def _attach_listeners(self):
        self.page.on("dialog", self._on_dialog)
        self.page.on("console", self._on_console)
        self.page.on("request", self._on_request)
        self.page.on("pageerror", self._on_pageerror)
        # Inject MutationObserver for DOM XSS detection
        await self._inject_dom_observer()

    async def _detach_listeners(self):
        self.page.remove_listener("dialog", self._on_dialog)
        self.page.remove_listener("console", self._on_console)
        self.page.remove_listener("request", self._on_request)
        self.page.remove_listener("pageerror", self._on_pageerror)

    async def _on_dialog(self, dialog: Dialog):
        message = dialog.message
        self.events.append(ExecutionEvent(
            signal="dialog",
            payload=message,
            evidence=f"Dialog type={dialog.type} message={message}",
            url=self.page.url,
            confirmed=True,
        ))
        await dialog.dismiss()
        self._dialog_handled.set()

    def _on_console(self, msg):
        text = msg.text
        if self.canary in text or "xss" in text.lower():
            self.events.append(ExecutionEvent(
                signal="console",
                payload=text,
                evidence=f"Console {msg.type}: {text}",
                url=self.page.url,
                confirmed=False,
            ))

    def _on_request(self, request: Request):
        url = request.url
        for pattern in self._oob_patterns:
            if pattern in url:
                self.events.append(ExecutionEvent(
                    signal="oob_request",
                    payload=pattern,
                    evidence=f"OOB callback to: {url}",
                    url=self.page.url,
                    confirmed=True,
                ))
                break
        # Also catch canary in any request
        if self.canary in url:
            self.events.append(ExecutionEvent(
                signal="oob_request",
                payload=self.canary,
                evidence=f"Canary in request URL: {url}",
                url=self.page.url,
                confirmed=True,
            ))

    def _on_pageerror(self, error):
        msg = str(error)
        if self.canary in msg:
            self.events.append(ExecutionEvent(
                signal="pageerror",
                payload=msg,
                evidence=f"Page error with canary: {msg}",
                url=self.page.url,
                confirmed=False,
            ))

    async def _inject_dom_observer(self):
        await self.page.evaluate(f"""
        () => {{
            window._argusXssEvents = window._argusXssEvents || [];
            const observer = new MutationObserver(mutations => {{
                mutations.forEach(m => {{
                    m.addedNodes.forEach(node => {{
                        const text = node.textContent || '';
                        const html = node.innerHTML || '';
                        if (text.includes('{self.canary}') || html.includes('{self.canary}')) {{
                            window._argusXssEvents.push({{
                                type: 'dom_mutation',
                                evidence: html.substring(0, 500),
                            }});
                        }}
                    }});
                }});
            }});
            observer.observe(document.body, {{
                childList: true,
                subtree: true,
                characterData: true,
            }});
        }}
        """)

    async def poll_dom_events(self) -> list[dict]:
        try:
            return await self.page.evaluate("() => window._argusXssEvents || []")
        except Exception:
            return []

    async def check_execution(self, wait_ms: int = 1000) -> list[ExecutionEvent]:
        await self.page.wait_for_timeout(wait_ms)

        # Check DOM mutations collected by injected observer
        dom_events = await self.poll_dom_events()
        for ev in dom_events:
            self.events.append(ExecutionEvent(
                signal="dom_mutation",
                payload=self.canary,
                evidence=ev.get("evidence", ""),
                url=self.page.url,
                confirmed=False,
            ))

        # Check eval-based signals: cookie access, location change
        try:
            eval_check = await self.page.evaluate(f"""
            () => {{
                const checks = {{}};
                checks.cookie_access = document.cookie.includes('{self.canary}');
                checks.title_changed = document.title.includes('{self.canary}');
                checks.href_changed  = window.location.href.includes('{self.canary}');
                return checks;
            }}
            """)
            for check_type, triggered in eval_check.items():
                if triggered:
                    self.events.append(ExecutionEvent(
                        signal="eval",
                        payload=self.canary,
                        evidence=f"Eval signal: {check_type}",
                        url=self.page.url,
                        confirmed=False,
                    ))
        except Exception:
            pass

        return self.events

    def register_oob_callback(self, domain: str):
        self._oob_patterns.append(domain)

    @property
    def confirmed_xss(self) -> bool:
        return any(e.signal == "dialog" and e.confirmed for e in self.events)

    @property
    def potential_xss(self) -> bool:
        return len(self.events) > 0
