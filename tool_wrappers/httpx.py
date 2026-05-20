"""
Httpx wrapper — fast HTTP probing: status, title, tech, headers.
"""
from __future__ import annotations

import asyncio
import json
import shutil

from shared.logger import audit

TOOL = "httpx"
TIMEOUT = 60


def _is_pd_httpx() -> bool:
    """Return True if the httpx binary in PATH is ProjectDiscovery's, not Python's."""
    binary = shutil.which("httpx")
    if not binary:
        return False
    import subprocess
    try:
        out = subprocess.run(["httpx", "-version"], capture_output=True, text=True, timeout=5)
        return "projectdiscovery" in (out.stdout + out.stderr).lower()
    except Exception:
        return False


async def run(
    target: str,
    ports: str = "",
    flags: str = "",
    timeout: int = TIMEOUT,
    options: dict = {},
) -> list[dict]:
    audit.tool_call(TOOL, "probe", {"target": target})

    if _is_pd_httpx():
        return await _run_pd_httpx(target, ports, flags, timeout)
    return await _run_python_httpx(target, timeout)


async def _run_pd_httpx(target: str, ports: str, flags: str, timeout: int) -> list[dict]:
    cmd = [
        "httpx",
        "-u", target,
        "-json", "-silent", "-title",
        "-status-code", "-tech-detect",
        "-content-length", "-web-server",
        "-method", "-no-color",
    ]
    if ports:
        cmd.extend(["-ports", ports])
    if flags:
        cmd.extend(flags.split())

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, "httpx timed out")
        return []
    except Exception as e:
        audit.error(TOOL, f"httpx failed: {e}")
        return []

    results = []
    for line in stdout.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append(_parse_result(obj))
        except json.JSONDecodeError:
            continue

    audit.tool_call(TOOL, "result", {"probed": len(results)})
    return results


async def _run_python_httpx(target: str, timeout: int) -> list[dict]:
    """Fallback: use the Python httpx library for basic probing."""
    try:
        import httpx as _httpx
    except ImportError:
        audit.error(TOOL, "Neither PD httpx binary nor Python httpx library available")
        return []

    results = []
    try:
        async with _httpx.AsyncClient(follow_redirects=True, timeout=timeout,
                                      verify=False) as client:
            resp = await client.get(target)
            from bs4 import BeautifulSoup
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.title.string.strip() if soup.title else ""
            except Exception:
                title = ""
            results.append({
                "url":            str(resp.url),
                "status":         resp.status_code,
                "title":          title,
                "content_length": int(resp.headers.get("content-length", len(resp.content))),
                "web_server":     resp.headers.get("server", ""),
                "technologies":   [],
                "cdn":            "",
                "cname":          [],
                "ip":             "",
                "redirect":       str(resp.headers.get("location", "")),
                "headers":        dict(resp.headers),
            })
    except Exception as e:
        audit.error(TOOL, f"Python httpx probe failed: {e}")

    audit.tool_call(TOOL, "result", {"probed": len(results)})
    return results


def _parse_result(obj: dict) -> dict:
    return {
        "url":           obj.get("url", ""),
        "status":        obj.get("status-code", 0),
        "title":         obj.get("title", ""),
        "content_length":obj.get("content-length", 0),
        "web_server":    obj.get("webserver", ""),
        "technologies":  obj.get("tech", []),
        "cdn":           obj.get("cdn", ""),
        "cname":         obj.get("cname", []),
        "ip":            obj.get("host", ""),
        "redirect":      obj.get("location", ""),
        "headers":       obj.get("headers", {}),
    }
