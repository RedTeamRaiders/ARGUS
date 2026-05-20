"""
Katana wrapper — fast web crawler for endpoint discovery.
"""
from __future__ import annotations

import asyncio
import json
import shutil

from shared.logger import audit

TOOL = "katana"
TIMEOUT = 120


async def run(
    target: str,
    depth: int = 3,
    js_crawl: bool = True,
    headless: bool = False,
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("katana"):
        audit.error(TOOL, "katana not found in PATH — install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return []

    cmd = [
        "katana",
        "-u", target,
        "-d", str(depth),
        "-json",
        "-silent",
        "-no-color",
        "-timeout", "10",
    ]
    if js_crawl:
        cmd.append("-js-crawl")
    if headless:
        cmd.extend(["-headless"])

    audit.tool_call(TOOL, "crawl", {"target": target, "depth": depth, "js_crawl": js_crawl})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, "Katana timed out")
        return []
    except Exception as e:
        audit.error(TOOL, f"Katana failed: {e}")
        return []

    results = []
    for line in stdout.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append({
                "url":         obj.get("request", {}).get("url", ""),
                "method":      obj.get("request", {}).get("method", "GET"),
                "endpoint":    obj.get("endpoint", ""),
                "source":      obj.get("source", ""),
                "tag":         obj.get("tag", ""),
                "attribute":   obj.get("attribute", ""),
            })
        except json.JSONDecodeError:
            if line.startswith("http"):
                results.append({"url": line, "method": "GET"})
            continue

    audit.tool_call(TOOL, "result", {"endpoints": len(results)})
    return results
