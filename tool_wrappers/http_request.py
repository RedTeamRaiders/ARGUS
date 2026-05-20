"""
http_request wrapper — manual HTTP GET/POST for targeted probing.
Used by the exploitation loop for login testing, parameter fuzzing, and response analysis.
Returns structured: url, status, headers, body_preview, redirect, cookies.
"""
from __future__ import annotations

import asyncio
from typing import Any

from shared.logger import audit

TOOL = "http_request"
TIMEOUT = 30


async def run(
    target: str,
    options: dict = {},
) -> dict:
    method  = options.get("method", "GET").upper()
    url     = options.get("url", target)
    data    = options.get("data", {})
    headers = options.get("headers", {})
    params  = options.get("params", {})
    allow_redirects = options.get("follow_redirects", True)

    audit.tool_call(TOOL, "request", {"method": method, "url": url})

    try:
        import httpx
        async with httpx.AsyncClient(
            follow_redirects=allow_redirects,
            timeout=TIMEOUT,
            verify=False,
        ) as client:
            if method == "POST":
                resp = await client.post(url, data=data, headers=headers, params=params)
            else:
                resp = await client.get(url, headers=headers, params=params)

        body = resp.text
        result = {
            "url":          str(resp.url),
            "status":       resp.status_code,
            "headers":      dict(resp.headers),
            "cookies":      {k: v for k, v in resp.cookies.items()},
            "body_preview": body[:2000],
            "body_length":  len(body),
            "redirect":     str(resp.headers.get("location", "")),
            "parsed":       [{
                "url":    str(resp.url),
                "status": resp.status_code,
                "body_preview": body[:500],
            }],
            "raw_output":   f"HTTP {resp.status_code} {method} {url}",
            "error":        None,
        }
        audit.tool_call(TOOL, "result", {"status": resp.status_code, "url": url})
        return result

    except Exception as e:
        audit.error(TOOL, f"http_request failed: {e}")
        return {"parsed": [], "raw_output": "", "error": str(e)}
