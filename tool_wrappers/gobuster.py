"""
Gobuster wrapper — directory/file brute force and DNS enumeration.
"""
from __future__ import annotations

import asyncio
import shutil

from shared.logger import audit

TOOL = "gobuster"
TIMEOUT = 120

DEFAULT_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
FALLBACK_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


async def run(
    target: str,
    mode: str = "dir",
    wordlist: str = "",
    extensions: str = "php,asp,aspx,jsp,html,js,json,txt,xml",
    threads: int = 20,
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("gobuster"):
        audit.error(TOOL, "gobuster not found in PATH")
        return []

    wl = wordlist or _find_wordlist()
    if not wl:
        audit.error(TOOL, "No wordlist found — install seclists or dirbuster")
        return []

    cmd = [
        "gobuster", mode,
        "-u", target,
        "-w", wl,
        "-t", str(threads),
        "-q",           # quiet — no progress bar
        "--no-error",
    ]

    if mode == "dir":
        cmd.extend(["-x", extensions])
    elif mode == "dns":
        cmd.extend(["--resolver", "8.8.8.8"])

    audit.tool_call(TOOL, "scan", {"target": target, "mode": mode, "wordlist": wl})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"Gobuster timed out after {timeout}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"Gobuster failed: {e}")
        return []

    results = _parse_output(stdout.decode(), mode)
    audit.tool_call(TOOL, "result", {"found": len(results)})
    return results


def _parse_output(output: str, mode: str) -> list[dict]:
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("/usr"):
            continue
        if mode == "dir":
            # Format: /admin (Status: 200) [Size: 1234]
            import re
            m = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line)
            if m:
                results.append({
                    "path":   m.group(1),
                    "status": int(m.group(2)),
                    "size":   int(m.group(3)),
                })
        elif mode == "dns":
            import re
            m = re.match(r"Found:\s+(\S+)", line)
            if m:
                results.append({"subdomain": m.group(1)})
    return results


def _find_wordlist() -> str:
    import os
    candidates = [
        DEFAULT_WORDLIST,
        FALLBACK_WORDLIST,
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/opt/SecLists/Discovery/Web-Content/common.txt",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return ""
