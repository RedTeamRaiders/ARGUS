"""
Subjack wrapper — detect subdomain takeover candidates.
Feed it the deduped subfinder/amass output.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from shared.logger import audit

TOOL = "subjack"
TIMEOUT = 180


async def run(
    subdomains: list[str],
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("subjack"):
        audit.error(TOOL, "subjack not in PATH — install: go install github.com/haccer/subjack@latest")
        return []

    if not subdomains:
        return []

    in_file  = NamedTemporaryFile("w", delete=False, suffix=".txt")
    out_file = NamedTemporaryFile("r", delete=False, suffix=".json")
    in_file.write("\n".join(s for s in subdomains if s))
    in_file.close()
    out_file.close()

    cmd = [
        "subjack",
        "-w", in_file.name,
        "-t", "50",
        "-timeout", "10",
        "-o", out_file.name,
        "-ssl",
    ]
    audit.tool_call(TOOL, "scan", f"count={len(subdomains)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"subjack timed out after {timeout}s")
        Path(in_file.name).unlink(missing_ok=True)
        Path(out_file.name).unlink(missing_ok=True)
        return []
    except Exception as e:
        audit.error(TOOL, f"subjack failed: {e}")
        Path(in_file.name).unlink(missing_ok=True)
        Path(out_file.name).unlink(missing_ok=True)
        return []

    results: list[dict] = []
    try:
        raw = Path(out_file.name).read_text() or ""
        # subjack writes one JSON object per vulnerable host
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                results.append({
                    "subdomain":  obj.get("subdomain", ""),
                    "service":    obj.get("service", ""),
                    "vulnerable": obj.get("vulnerable", True),
                })
            except json.JSONDecodeError:
                continue
    finally:
        Path(in_file.name).unlink(missing_ok=True)
        Path(out_file.name).unlink(missing_ok=True)

    audit.tool_call(TOOL, "result", f"vulnerable={len(results)}")
    return results
