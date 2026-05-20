"""
LinkFinder wrapper — JavaScript endpoint extraction.
Finds hidden API endpoints, internal routes, and hardcoded tokens in JS files.
"""
from __future__ import annotations

import asyncio
import re
import shutil

from shared.logger import audit

TOOL = "linkfinder"
TIMEOUT = 60


async def run(target: str, timeout: int = TIMEOUT) -> list[dict]:
    # Try linkfinder.py first, then custom regex scan
    if shutil.which("linkfinder") or shutil.which("linkfinder.py"):
        return await _run_linkfinder(target, timeout)
    # Fallback: fetch JS files and extract endpoints via regex
    return await _regex_scan(target, timeout)


async def _run_linkfinder(target: str, timeout: int) -> list[dict]:
    binary = "linkfinder" if shutil.which("linkfinder") else "linkfinder.py"
    cmd = [binary, "-i", target, "-d", "-o", "cli"]

    audit.tool_call(TOOL, "scan", {"target": target})
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except Exception as e:
        audit.error(TOOL, f"LinkFinder failed: {e}")
        return []

    results = []
    for line in stdout.decode().splitlines():
        line = line.strip()
        if line and not line.startswith("["):
            results.append({"endpoint": line, "source": "linkfinder"})

    audit.tool_call(TOOL, "result", {"endpoints": len(results)})
    return results


async def _regex_scan(target: str, timeout: int) -> list[dict]:
    """Fetch JS files from target and extract endpoints via regex."""
    import httpx as http_client
    audit.tool_call(TOOL, "regex_scan", {"target": target})

    results = []
    endpoint_pattern = re.compile(
        r"""(?:"|')(/[a-zA-Z0-9_\-/\.]+(?:\?[^"']*)?|https?://[^"']+)(?:"|')"""
    )
    api_key_pattern = re.compile(
        r'(?:api_key|apikey|api-key|access_token|secret|password|token)["\s:=]+["\']([A-Za-z0-9_\-\.]{20,})["\']',
        re.IGNORECASE,
    )

    try:
        async with http_client.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(target)
            # Find JS file references
            js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
            js_files = [f if f.startswith("http") else f"{target.rstrip('/')}/{f.lstrip('/')}" for f in js_files[:10]]

            for js_url in js_files:
                try:
                    js_resp = await client.get(js_url)
                    for match in endpoint_pattern.finditer(js_resp.text):
                        ep = match.group(1)
                        if len(ep) > 3 and not any(x in ep for x in [".png", ".jpg", ".css", ".ico"]):
                            results.append({"endpoint": ep, "source": js_url})
                    for match in api_key_pattern.finditer(js_resp.text):
                        results.append({
                            "endpoint": f"HARDCODED_SECRET: {match.group(0)[:100]}",
                            "source": js_url,
                            "type": "secret",
                        })
                except Exception:
                    continue
    except Exception as e:
        audit.error(TOOL, f"Regex scan failed: {e}")

    audit.tool_call(TOOL, "result_regex", {"endpoints": len(results)})
    return results
