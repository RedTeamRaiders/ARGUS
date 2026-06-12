"""
testssl.sh wrapper — SSL/TLS misconfiguration assessment.
Parses JSON output into per-finding dicts.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from shared.logger import audit

TOOL = "testssl"
TIMEOUT = 600

SEVERE = {"CRITICAL", "HIGH", "MEDIUM"}


async def run(
    target: str,
    quick: bool = True,
    timeout: int = TIMEOUT,
) -> list[dict]:
    bin_path = shutil.which("testssl.sh") or shutil.which("testssl")
    if not bin_path:
        audit.error(TOOL, "testssl.sh not in PATH — install: apt install testssl.sh")
        return []

    out_file = NamedTemporaryFile("r", delete=False, suffix=".json")
    out_file.close()

    cmd = [bin_path, "--jsonfile", out_file.name, "--color", "0", "--warnings", "off"]
    if quick:
        cmd.extend(["--fast", "--quiet"])
    cmd.append(target)

    audit.tool_call(TOOL, "scan", " ".join(cmd[:4]), target=target)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"testssl timed out after {timeout}s")
        Path(out_file.name).unlink(missing_ok=True)
        return []
    except Exception as e:
        audit.error(TOOL, f"testssl failed: {e}")
        Path(out_file.name).unlink(missing_ok=True)
        return []

    results: list[dict] = []
    try:
        data = json.loads(Path(out_file.name).read_text() or "[]")
        for item in data:
            severity = (item.get("severity") or "").upper()
            if severity not in SEVERE:
                continue
            results.append({
                "id":       item.get("id", ""),
                "severity": severity,
                "finding":  item.get("finding", ""),
                "cve":      item.get("cve", ""),
                "cwe":      item.get("cwe", ""),
            })
    except json.JSONDecodeError:
        pass
    finally:
        Path(out_file.name).unlink(missing_ok=True)

    audit.tool_call(TOOL, "result", f"severe={len(results)}", target=target)
    return results
