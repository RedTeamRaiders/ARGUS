"""
FFUF wrapper — fast web fuzzer for directory/endpoint discovery and parameter fuzzing.
"""
from __future__ import annotations

import asyncio
import json
import shutil

from shared.logger import audit

TOOL = "ffuf"
TIMEOUT = 90

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


async def run(
    url: str,
    wordlist: str = "",
    method: str = "GET",
    data: str = "",
    headers: dict | None = None,
    match_codes: str = "200,204,301,302,307,401,403,405",
    threads: int = 40,
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("ffuf"):
        audit.error(TOOL, "ffuf not found — install: go install github.com/ffuf/ffuf/v2@latest")
        return []

    wl = wordlist or _find_wordlist()
    if not wl:
        audit.error(TOOL, "No wordlist found")
        return []

    # URL must contain FUZZ marker
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    cmd = [
        "ffuf",
        "-u", url,
        "-w", wl,
        "-mc", match_codes,
        "-t", str(threads),
        "-of", "json",
        "-o", "-",   # output to stdout
        "-s",        # silent
        "-ac",       # auto-calibrate (reduces false positives)
    ]

    if method != "GET":
        cmd.extend(["-X", method])
    if data:
        cmd.extend(["-d", data])
    if headers:
        for k, v in (headers or {}).items():
            cmd.extend(["-H", f"{k}: {v}"])

    audit.tool_call(TOOL, "fuzz", {"url": url, "wordlist": wl})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, "FFUF timed out")
        return []
    except Exception as e:
        audit.error(TOOL, f"FFUF failed: {e}")
        return []

    try:
        raw = json.loads(stdout.decode())
        results = [_parse_result(r) for r in raw.get("results", [])]
        audit.tool_call(TOOL, "result", {"found": len(results)})
        return results
    except json.JSONDecodeError:
        return []


def _parse_result(r: dict) -> dict:
    return {
        "url":          r.get("url", ""),
        "status":       r.get("status", 0),
        "length":       r.get("length", 0),
        "words":        r.get("words", 0),
        "lines":        r.get("lines", 0),
        "input":        r.get("input", {}).get("FUZZ", ""),
    }


def _find_wordlist() -> str:
    import os
    candidates = [
        DEFAULT_WORDLIST,
        "/usr/share/wordlists/dirb/common.txt",
        "/opt/SecLists/Discovery/Web-Content/common.txt",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return ""
