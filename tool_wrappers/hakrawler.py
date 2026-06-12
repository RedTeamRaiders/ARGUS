"""
Hakrawler wrapper — fast Go-based crawler.
Use as a quick complement to the Playwright crawler when JS rendering not needed.
"""
from __future__ import annotations

import asyncio
import shutil

from shared.logger import audit

TOOL = "hakrawler"
TIMEOUT = 90


async def run(
    target: str,
    depth: int = 2,
    include_subs: bool = True,
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("hakrawler"):
        audit.error(TOOL, "hakrawler not in PATH — install: go install github.com/hakluke/hakrawler@latest")
        return []

    cmd = ["hakrawler", "-d", str(depth), "-u"]
    if include_subs:
        cmd.append("-subs")

    audit.tool_call(TOOL, "crawl", " ".join(cmd), target=target)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=target.encode()),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        audit.error(TOOL, f"hakrawler timed out after {timeout}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"hakrawler failed: {e}")
        return []

    urls = sorted({line.strip() for line in stdout.decode().splitlines() if line.strip().startswith("http")})
    results = [{"url": u, "source": "hakrawler"} for u in urls]
    audit.tool_call(TOOL, "result", f"urls={len(results)}", target=target)
    return results
