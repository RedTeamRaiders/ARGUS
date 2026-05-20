"""
Dalfox wrapper — dedicated XSS scanner.
Used after manual canary-confirmation of reflecting parameters.
"""
from __future__ import annotations

import asyncio
import json
import shutil

from shared.logger import audit

TOOL = "dalfox"
TIMEOUT = 120


async def run(
    target: str,
    param: str = "",
    data: str = "",
    headers: dict | None = None,
    mode: str = "url",
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("dalfox"):
        audit.error(TOOL, "dalfox not found — install: go install github.com/hahwul/dalfox/v2@latest")
        return []

    cmd = [
        "dalfox",
        mode,
        target,
        "--json",
        "--silence",
        "--no-color",
        "--timeout", "10",
        "--delay", "200",  # 200ms between requests (human-like)
    ]

    if param:
        cmd.extend(["--data", param])
    if data:
        cmd.extend(["-d", data])
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

    audit.tool_call(TOOL, "scan", {"target": target, "param": param, "mode": mode})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, "Dalfox timed out")
        return []
    except Exception as e:
        audit.error(TOOL, f"Dalfox failed: {e}")
        return []

    results = []
    for line in stdout.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append(_parse_result(obj))
        except json.JSONDecodeError:
            # Non-JSON line (dalfox sometimes outputs plain text)
            if "POC" in line or "confirmed" in line.lower():
                results.append({"tool": "dalfox", "raw": line, "confirmed": True})
            continue

    audit.tool_call(TOOL, "result", {"xss_found": len(results)})
    return results


def _parse_result(obj: dict) -> dict:
    return {
        "tool":      "dalfox",
        "type":      obj.get("type", ""),
        "injected_param": obj.get("injected_param", ""),
        "poc":       obj.get("poc", ""),
        "evidence":  obj.get("evidence", ""),
        "cwe":       "CWE-79",
        "confirmed": obj.get("type", "") in ("R", "V"),  # R=reflected, V=verified
    }
