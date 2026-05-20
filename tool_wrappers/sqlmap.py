"""
Sqlmap wrapper — SQL injection testing.
IMPORTANT: Only run after Claude confirms a parameter is injectable via manual testing.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil

from shared.logger import audit

TOOL = "sqlmap"
TIMEOUT = 180


async def run(
    target: str,
    param: str = "",
    data: str = "",
    cookies: str = "",
    headers: dict | None = None,
    level: int = 1,
    risk: int = 1,
    technique: str = "BEUSTQ",
    timeout: int = TIMEOUT,
) -> dict:
    if not shutil.which("sqlmap"):
        audit.error(TOOL, "sqlmap not found in PATH")
        return {}

    cmd = [
        "sqlmap",
        "-u", target,
        "--batch",           # non-interactive
        "--json-output", "-",  # JSON to stdout (not all versions support, fallback to text parse)
        "--level", str(level),
        "--risk", str(risk),
        "--technique", technique,
        "--timeout", "10",
        "--delay", "0.5",    # 500ms between requests
        "--threads", "3",
    ]

    if param:
        cmd.extend(["-p", param])
    if data:
        cmd.extend(["--data", data])
    if cookies:
        cmd.extend(["--cookie", cookies])
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

    audit.tool_call(TOOL, "scan", {"target": target, "param": param, "level": level, "risk": risk})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"Sqlmap timed out after {timeout}s")
        return {}
    except Exception as e:
        audit.error(TOOL, f"Sqlmap failed: {e}")
        return {}

    result = _parse_output(stdout.decode() + stderr.decode())
    audit.tool_call(TOOL, "result", {"injectable": result.get("injectable", False), "db_type": result.get("db_type", "")})
    return result


def _parse_output(output: str) -> dict:
    result = {
        "injectable": False,
        "db_type": "",
        "injectable_params": [],
        "techniques": [],
        "payloads": [],
        "raw": output[:5000],
    }

    if "is vulnerable" in output or "parameter" in output and "injectable" in output:
        result["injectable"] = True

    db_match = re.search(r"back-end DBMS:\s+(.+)", output)
    if db_match:
        result["db_type"] = db_match.group(1).strip()

    param_matches = re.findall(r"Parameter: (\S+) \((.+?)\)", output)
    for param, ptype in param_matches:
        result["injectable_params"].append({"param": param, "type": ptype})

    payload_matches = re.findall(r"Payload: (.+)", output)
    result["payloads"] = payload_matches[:5]

    technique_matches = re.findall(r"Type: (.+)", output)
    result["techniques"] = list(set(technique_matches))

    return result
