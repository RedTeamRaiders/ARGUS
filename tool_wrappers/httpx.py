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


async def run(
    target: str,
    ports: str = "",
    flags: str = "",
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("httpx"):
        audit.error(TOOL, "httpx not found in PATH — install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return []

    cmd = [
        "httpx",
        "-u", target,
        "-json",
        "-silent",
        "-title",
        "-status-code",
        "-tech-detect",
        "-content-length",
        "-web-server",
        "-method",
        "-no-color",
    ]
    if ports:
        cmd.extend(["-ports", ports])
    if flags:
        cmd.extend(flags.split())

    audit.tool_call(TOOL, "probe", {"target": target})

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
