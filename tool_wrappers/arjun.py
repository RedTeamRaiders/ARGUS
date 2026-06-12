"""
Arjun wrapper — HTTP parameter discovery.
Finds hidden GET/POST/JSON params via fuzzing against a known wordlist.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from shared.logger import audit

TOOL = "arjun"
TIMEOUT = 180


async def run(
    target: str,
    method: str = "GET",
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("arjun"):
        audit.error(TOOL, "arjun not in PATH — install: pip install arjun")
        return []

    out_file = NamedTemporaryFile("r", delete=False, suffix=".json")
    out_file.close()

    cmd = ["arjun", "-u", target, "-m", method, "-oJ", out_file.name, "-q"]
    audit.tool_call(TOOL, "discover", f"method={method}", target=target)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"arjun timed out after {timeout}s")
        Path(out_file.name).unlink(missing_ok=True)
        return []
    except Exception as e:
        audit.error(TOOL, f"arjun failed: {e}")
        Path(out_file.name).unlink(missing_ok=True)
        return []

    results: list[dict] = []
    try:
        data = json.loads(Path(out_file.name).read_text() or "{}")
        # Arjun JSON: {url: {"params": [...], "method": "GET", ...}}
        for url, info in data.items():
            for param in info.get("params", []):
                results.append({
                    "url":    url,
                    "param":  param,
                    "method": info.get("method", method),
                })
    except (json.JSONDecodeError, FileNotFoundError):
        pass
    finally:
        Path(out_file.name).unlink(missing_ok=True)

    audit.tool_call(TOOL, "result", f"params={len(results)}", target=target)
    return results
