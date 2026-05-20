"""
Hydra wrapper — credential brute force / spraying.
ONLY used after scope and auth confirmation. Rate-limited to avoid lockouts.
"""
from __future__ import annotations

import asyncio
import re
import shutil

from shared.logger import audit

TOOL = "hydra"
TIMEOUT = 120

# Human-like delays: 500ms between attempts by default (avoids lockout)
DEFAULT_TASKS = 4
DEFAULT_WAIT  = 0.5


async def run(
    target: str,
    service: str,
    userlist: str = "",
    passlist: str = "",
    username: str = "",
    password: str = "",
    port: int = 0,
    tasks: int = DEFAULT_TASKS,
    stop_on_success: bool = True,
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("hydra"):
        audit.error(TOOL, "hydra not found in PATH")
        return []

    cmd = ["hydra", "-t", str(tasks), "-W", str(DEFAULT_WAIT)]

    # User specification
    if userlist:
        cmd.extend(["-L", userlist])
    elif username:
        cmd.extend(["-l", username])
    else:
        audit.error(TOOL, "No username or userlist provided")
        return []

    # Password specification
    if passlist:
        cmd.extend(["-P", passlist])
    elif password:
        cmd.extend(["-p", password])
    else:
        audit.error(TOOL, "No password or passlist provided")
        return []

    if stop_on_success:
        cmd.append("-f")    # stop on first valid cred per host

    if port:
        cmd.extend(["-s", str(port)])

    cmd.extend([target, service])

    audit.tool_call(TOOL, "brute", {
        "target": target, "service": service,
        "tasks": tasks, "stop_on_success": stop_on_success,
    })

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"Hydra timed out after {timeout}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"Hydra failed: {e}")
        return []

    results = _parse_output(stdout.decode())
    audit.tool_call(TOOL, "result", {"valid_creds": len(results)})
    return results


def _parse_output(output: str) -> list[dict]:
    results = []
    for line in output.splitlines():
        # [22][ssh] host: 192.168.1.1   login: admin   password: password123
        m = re.search(
            r'\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)',
            line
        )
        if m:
            results.append({
                "port":     m.group(1),
                "service":  m.group(2),
                "host":     m.group(3),
                "username": m.group(4),
                "password": m.group(5),
            })
    return results
