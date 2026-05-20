"""
Searchsploit wrapper — exploit-db search for CVEs and vulnerabilities.
"""
from __future__ import annotations

import asyncio
import json
import shutil

from shared.logger import audit

TOOL = "searchsploit"
TIMEOUT = 30


async def run(query: str, json_output: bool = True, timeout: int = TIMEOUT) -> list[dict]:
    if not shutil.which("searchsploit"):
        audit.error(TOOL, "searchsploit not found — install exploitdb package")
        return []

    cmd = ["searchsploit", query]
    if json_output:
        cmd.append("--json")

    audit.tool_call(TOOL, "search", {"query": query})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, "Searchsploit timed out")
        return []
    except Exception as e:
        audit.error(TOOL, f"Searchsploit failed: {e}")
        return []

    if json_output:
        try:
            raw = json.loads(stdout.decode())
            results = [_parse_result(r) for r in raw.get("RESULTS_EXPLOIT", [])]
            audit.tool_call(TOOL, "result", {"exploits": len(results)})
            return results
        except json.JSONDecodeError:
            pass

    # Text fallback
    results = _parse_text(stdout.decode())
    audit.tool_call(TOOL, "result", {"exploits": len(results)})
    return results


def _parse_result(r: dict) -> dict:
    return {
        "title":    r.get("Title", ""),
        "edb_id":   r.get("EDB-ID", ""),
        "type":     r.get("Type", ""),
        "platform": r.get("Platform", ""),
        "path":     r.get("Path", ""),
        "date":     r.get("Date", ""),
        "author":   r.get("Author", ""),
        "cve":      r.get("CVE", ""),
    }


def _parse_text(output: str) -> list[dict]:
    results = []
    for line in output.splitlines():
        if "|" in line and "Exploit Title" not in line and "---" not in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                results.append({"title": parts[0], "path": parts[-1]})
    return results
