"""
Amass wrapper — passive (default) or active subdomain enumeration (OWASP).
Active mode performs DNS bruteforce + zone transfer — only with explicit opt-in.
"""
from __future__ import annotations

import asyncio
import shutil

from shared.logger import audit

TOOL = "amass"
TIMEOUT = 300


async def run(
    target: str,
    active: bool = False,
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("amass"):
        audit.error(TOOL, "amass not in PATH — install: go install -v github.com/owasp-amass/amass/v4/...@master")
        return []

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    cmd = ["amass", "enum", "-d", domain, "-nocolor", "-silent"]
    if not active:
        cmd.append("-passive")

    audit.tool_call(TOOL, "enum", " ".join(cmd[1:]), target=domain)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"amass timed out after {timeout}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"amass failed: {e}")
        return []

    subs = sorted({line.strip() for line in stdout.decode().splitlines() if line.strip() and "." in line})
    results = [{"subdomain": s, "source": "amass", "active": active} for s in subs]
    audit.tool_call(TOOL, "result", f"found={len(results)}", target=domain)
    return results
