"""
Feroxbuster wrapper — fast recursive content discovery (Rust).
Drop-in replacement for gobuster when you want recursive enumeration.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from shared.logger import audit

TOOL = "feroxbuster"
TIMEOUT = 600

WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


async def run(
    target: str,
    wordlist: str = "",
    depth: int = 2,
    threads: int = 30,
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("feroxbuster"):
        audit.error(TOOL, "feroxbuster not in PATH — install: cargo install feroxbuster")
        return []

    wl = wordlist or _find_wordlist()
    if not wl:
        audit.error(TOOL, "no wordlist found")
        return []

    out_file = NamedTemporaryFile("r", delete=False, suffix=".json")
    out_file.close()

    cmd = [
        "feroxbuster",
        "-u", target,
        "-w", wl,
        "-d", str(depth),
        "-t", str(threads),
        "--silent",
        "--json",
        "-o", out_file.name,
        "--rate-limit", "200",
    ]
    audit.tool_call(TOOL, "scan", " ".join(cmd[:7]), target=target)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"feroxbuster timed out after {timeout}s")
        Path(out_file.name).unlink(missing_ok=True)
        return []
    except Exception as e:
        audit.error(TOOL, f"feroxbuster failed: {e}")
        Path(out_file.name).unlink(missing_ok=True)
        return []

    results: list[dict] = []
    try:
        for line in Path(out_file.name).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") != "response":
                    continue
                results.append({
                    "url":           obj.get("url", ""),
                    "status":        obj.get("status", 0),
                    "size":          obj.get("content_length", 0),
                    "word_count":    obj.get("word_count", 0),
                    "content_type":  obj.get("headers", {}).get("content-type", ""),
                })
            except json.JSONDecodeError:
                continue
    finally:
        Path(out_file.name).unlink(missing_ok=True)

    audit.tool_call(TOOL, "result", f"endpoints={len(results)}", target=target)
    return results


def _find_wordlist() -> str:
    import os
    for c in WORDLISTS:
        if os.path.exists(c):
            return c
    return ""
