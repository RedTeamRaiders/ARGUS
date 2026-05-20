"""
Evidence Collector — captures proof for every confirmed finding.

Collects per-finding:
1. Screenshot (PNG) — shows alert firing or visible payload execution
2. HAR file — full HTTP log: request that injected payload + response
3. DOM snapshot — HTML state at time of execution
4. Console logs — any JS errors or payload output
5. Injected request details — URL, method, headers, body
6. Response details — status, headers, body excerpt
"""
from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from playwright.async_api import BrowserContext, Page, Request, Response

from shared.logger import audit

TOOL = "evidence_collector"


@dataclass
class Evidence:
    url:              str
    payload:          str
    signal_type:      str       # dialog|console|dom|oob|eval
    screenshot_b64:   Optional[str] = None
    screenshot_path:  Optional[str] = None
    dom_snapshot:     Optional[str] = None
    har_path:         Optional[str] = None
    injected_request: Optional[dict] = None
    response:         Optional[dict] = None
    console_logs:     list[str] = field(default_factory=list)
    extra:            dict = field(default_factory=dict)

    def to_evidence_string(self) -> str:
        parts = [
            f"URL: {self.url}",
            f"Payload: {self.payload}",
            f"Signal: {self.signal_type}",
        ]
        if self.injected_request:
            parts.append(f"Injected via: {self.injected_request.get('method')} {self.injected_request.get('url')}")
        if self.screenshot_path:
            parts.append(f"Screenshot: {self.screenshot_path}")
        if self.har_path:
            parts.append(f"HAR: {self.har_path}")
        return "\n".join(parts)


class EvidenceCollector:
    def __init__(self, output_dir: str = "/tmp/argus_evidence"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._console_logs: list[str] = []
        self._requests: list[dict] = []
        self._responses: dict[str, dict] = {}

    async def attach_to_page(self, page: Page):
        page.on("console", lambda msg: self._console_logs.append(f"{msg.type}: {msg.text}"))
        page.on("request", self._capture_request)
        page.on("response", self._capture_response)

    def _capture_request(self, request: Request):
        try:
            self._requests.append({
                "url":     request.url,
                "method":  request.method,
                "headers": dict(request.headers),
                "post_data": request.post_data,
            })
        except Exception:
            pass

    async def _capture_response(self, response: Response):
        try:
            body = ""
            if "text" in (response.headers.get("content-type", "")):
                try:
                    body = (await response.text())[:2000]
                except Exception:
                    pass
            self._responses[response.url] = {
                "status":  response.status,
                "headers": dict(response.headers),
                "body":    body,
            }
        except Exception:
            pass

    async def capture(
        self,
        page: Page,
        payload: str,
        signal_type: str,
        finding_id: str = "unknown",
    ) -> Evidence:
        url = page.url
        audit.tool_call(TOOL, "capture", {"finding_id": finding_id, "signal": signal_type, "url": url})

        # Screenshot
        screenshot_b64 = None
        screenshot_path = None
        try:
            shot_path = self.output_dir / f"{finding_id}_screenshot.png"
            await page.screenshot(path=str(shot_path), full_page=False)
            screenshot_path = str(shot_path)
            with open(shot_path, "rb") as f:
                screenshot_b64 = base64.b64encode(f.read()).decode()
        except Exception as e:
            audit.error(TOOL, f"Screenshot failed: {e}")

        # DOM snapshot
        dom_snapshot = None
        try:
            dom_snapshot = await page.content()
            dom_path = self.output_dir / f"{finding_id}_dom.html"
            dom_path.write_text(dom_snapshot[:100000])  # cap at 100KB
        except Exception:
            pass

        # Find the most relevant request (the one that injected the payload)
        injected_req = self._find_injection_request(payload)

        # Response for that request
        resp_data = None
        if injected_req:
            resp_data = self._responses.get(injected_req.get("url", ""))

        evidence = Evidence(
            url=url,
            payload=payload,
            signal_type=signal_type,
            screenshot_b64=screenshot_b64,
            screenshot_path=screenshot_path,
            dom_snapshot=dom_snapshot[:5000] if dom_snapshot else None,
            injected_request=injected_req,
            response=resp_data,
            console_logs=self._console_logs.copy(),
        )

        # Save evidence JSON
        ev_path = self.output_dir / f"{finding_id}_evidence.json"
        ev_path.write_text(json.dumps({
            "url": evidence.url,
            "payload": evidence.payload,
            "signal_type": evidence.signal_type,
            "injected_request": evidence.injected_request,
            "response_status": resp_data.get("status") if resp_data else None,
            "console_logs": evidence.console_logs,
            "screenshot_path": screenshot_path,
        }, indent=2))

        audit.tool_call(TOOL, "evidence_saved", {"path": str(self.output_dir), "finding_id": finding_id})
        return evidence

    def _find_injection_request(self, payload: str) -> Optional[dict]:
        # Find the request that contained the payload
        for req in reversed(self._requests):
            post = req.get("post_data") or ""
            url = req.get("url") or ""
            if payload[:20] in post or payload[:20] in url:
                return req
        # Return most recent POST request as fallback
        for req in reversed(self._requests):
            if req.get("method") == "POST":
                return req
        return self._requests[-1] if self._requests else None

    def clear(self):
        self._console_logs.clear()
        self._requests.clear()
        self._responses.clear()
