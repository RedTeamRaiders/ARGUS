"""
Subfinder wrapper — passive subdomain enumeration (ProjectDiscovery).
Returns deduped list of subdomains. Safe — passive sources only.
"""
from __future__ import annotations

import asyncio
import shutil

from shared.logger import audit

TOOL = "subfinder"
TIMEOUT = 120


async def run(
    target: str,
    all_sources: bool = False,
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("subfinder"):
        audit.error(TOOL, "subfinder not in PATH — install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return []

    # Strip schemes/paths to feed bare apex
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    cmd = ["subfinder", "-d", domain, "-silent", "-nc"]
    if all_sources:
        cmd.append("-all")

    audit.tool_call(TOOL, "enum", "subfinder " + " ".join(cmd[1:]), target=domain)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"subfinder timed out after {timeout}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"subfinder failed: {e}")
        return []

    subs = sorted({line.strip() for line in stdout.decode().splitlines() if line.strip()})
    results = [{"subdomain": s, "source": "subfinder"} for s in subs]
    audit.tool_call(TOOL, "result", f"found={len(results)}", target=domain)
    return results
