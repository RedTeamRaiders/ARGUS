"""
Nmap wrapper — port/service enumeration.
Returns structured: host, port, protocol, state, service, version, scripts.
"""
from __future__ import annotations

import asyncio
import re
import shutil
from typing import Any

from shared.logger import audit

TOOL = "nmap"
TIMEOUT = 300


async def run(
    target: str,
    ports: str = "top1000",
    flags: str = "-sV -sC",
    timeout: int = TIMEOUT,
) -> dict:
    if not shutil.which("nmap"):
        audit.error(TOOL, "nmap not found in PATH")
        return {}

    cmd = ["nmap", "-oG", "-"]  # grepable output to stdout
    if ports == "top1000":
        cmd.append("--top-ports=1000")
    elif ports == "full":
        cmd.extend(["-p-"])
    elif ports:
        cmd.extend(["-p", ports])

    cmd.extend(flags.split())
    cmd.append(target)

    audit.tool_call(TOOL, "scan", {"target": target, "ports": ports, "flags": flags})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 30)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"Nmap timed out after {timeout + 30}s")
        return {}
    except Exception as e:
        audit.error(TOOL, f"Nmap failed: {e}")
        return {}

    result = _parse_grepable(stdout.decode())
    audit.tool_call(TOOL, "result", {"open_ports": len(result.get("ports", []))})
    return result


def _parse_grepable(output: str) -> dict:
    result: dict[str, Any] = {"raw": output, "ports": [], "os": ""}

    for line in output.splitlines():
        if line.startswith("#"):
            continue

        # Host line: Host: 1.2.3.4 (hostname)
        host_match = re.search(r"Host:\s+(\S+)\s*\(([^)]*)\)", line)
        if host_match:
            result["host"] = host_match.group(1)
            result["hostname"] = host_match.group(2)

        # Ports: 22/open/tcp//ssh//OpenSSH 8.9/
        ports_match = re.search(r"Ports:\s+(.+?)(?:\s+Ignored|$)", line)
        if ports_match:
            for port_str in ports_match.group(1).split(","):
                parts = port_str.strip().split("/")
                if len(parts) >= 5:
                    result["ports"].append({
                        "port":     parts[0],
                        "state":    parts[1],
                        "protocol": parts[2],
                        "service":  parts[4],
                        "version":  parts[6] if len(parts) > 6 else "",
                    })

        # OS
        os_match = re.search(r"OS:\s+(.+?)(?:\s+Seq|$)", line)
        if os_match:
            result["os"] = os_match.group(1)

    return result
