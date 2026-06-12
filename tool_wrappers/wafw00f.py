"""
Wafw00f wrapper — identify the WAF (if any) protecting the target.
Output drives payload selection (Cloudflare vs Akamai vs ModSec each need different bypass).
"""
from __future__ import annotations

import asyncio
import re
import shutil

from shared.logger import audit

TOOL = "wafw00f"
TIMEOUT = 60


async def run(target: str, timeout: int = TIMEOUT) -> list[dict]:
    if not shutil.which("wafw00f"):
        audit.error(TOOL, "wafw00f not in PATH — install: pip install wafw00f")
        return []

    cmd = ["wafw00f", "-a", target]
    audit.tool_call(TOOL, "fingerprint", " ".join(cmd), target=target)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"wafw00f timed out after {timeout}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"wafw00f failed: {e}")
        return []

    text = stdout.decode()
    wafs = re.findall(r"is behind\s+(.+?)\s+WAF", text, flags=re.IGNORECASE)
    no_waf = bool(re.search(r"No WAF detected", text, flags=re.IGNORECASE))

    result = {
        "target":  target,
        "wafs":    [w.strip() for w in wafs],
        "waf_present": bool(wafs),
        "no_waf_confirmed": no_waf,
    }
    audit.tool_call(TOOL, "result", f"wafs={result['wafs']}", target=target)
    return [result]
