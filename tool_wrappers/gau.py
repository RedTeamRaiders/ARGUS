"""
GAU (Get All URLs) wrapper — historical URL aggregation from Wayback Machine, AlienVault, etc.
"""
from __future__ import annotations

import asyncio
import shutil

from shared.logger import audit

TOOL = "gau"
TIMEOUT = 90


async def run(
    target: str,
    providers: str = "wayback,otx,urlscan",
    timeout: int = TIMEOUT,
) -> list[str]:
    if not shutil.which("gau"):
        # Try gau alternative
        if shutil.which("waybackurls"):
            return await _run_waybackurls(target, timeout)
        audit.error(TOOL, "gau not found — install: go install github.com/lc/gau/v2/cmd/gau@latest")
        return []

    cmd = ["gau", "--providers", providers, target]

    audit.tool_call(TOOL, "fetch", {"target": target, "providers": providers})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, "GAU timed out")
        return []
    except Exception as e:
        audit.error(TOOL, f"GAU failed: {e}")
        return []

    urls = [line.strip() for line in stdout.decode().splitlines() if line.strip().startswith("http")]
    audit.tool_call(TOOL, "result", {"urls": len(urls)})
    return urls


async def _run_waybackurls(target: str, timeout: int) -> list[str]:
    cmd = ["waybackurls", target]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        urls = [line.strip() for line in stdout.decode().splitlines() if line.strip().startswith("http")]
        audit.tool_call(TOOL, "result_waybackurls", {"urls": len(urls)})
        return urls
    except Exception as e:
        audit.error(TOOL, f"waybackurls failed: {e}")
        return []
