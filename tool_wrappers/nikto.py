"""
Nikto wrapper — web server misconfiguration / known files scanner.
Note: nikto is loud — only use after wafw00f, and reduce tuning if a WAF is present.
"""
from __future__ import annotations

import asyncio
import re
import shutil

from shared.logger import audit

TOOL = "nikto"
TIMEOUT = 600


async def run(
    target: str,
    tuning: str = "x1234567890ab",   # all except dangerous (skip cat 9 = SQLi/DoS)
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("nikto"):
        audit.error(TOOL, "nikto not in PATH — install: apt install nikto")
        return []

    cmd = [
        "nikto",
        "-host", target,
        "-Tuning", tuning,
        "-ask", "no",
        "-nointeractive",
        "-Format", "txt",
    ]
    audit.tool_call(TOOL, "scan", " ".join(cmd), target=target)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"nikto timed out after {timeout}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"nikto failed: {e}")
        return []

    results: list[dict] = []
    for line in stdout.decode().splitlines():
        line = line.strip()
        # Nikto findings look like: + /path/to/thing: description (OSVDB-XXXXX)
        if not line.startswith("+ "):
            continue
        body = line[2:]
        osvdb = re.search(r"OSVDB-(\d+)", body)
        cve   = re.search(r"(CVE-\d{4}-\d+)", body)
        results.append({
            "raw":   body,
            "osvdb": osvdb.group(1) if osvdb else "",
            "cve":   cve.group(1) if cve else "",
        })

    audit.tool_call(TOOL, "result", f"items={len(results)}", target=target)
    return results
