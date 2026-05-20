"""
CrackMapExec (CME) / NetExec (nxc) wrapper — SMB/LDAP/WinRM enumeration and credential testing.
"""
from __future__ import annotations

import asyncio
import re
import shutil

from shared.logger import audit

TOOL = "crackmapexec"
TIMEOUT = 60


async def run(
    target: str,
    service: str = "smb",
    username: str = "",
    password: str = "",
    hash_: str = "",
    domain: str = "",
    command: str = "",
    shares: bool = False,
    users: bool = False,
    timeout: int = TIMEOUT,
) -> dict:
    # Prefer NetExec (modern fork) over CrackMapExec
    binary = shutil.which("nxc") or shutil.which("crackmapexec") or shutil.which("cme")
    if not binary:
        audit.error(TOOL, "crackmapexec/netexec not found — install: pip install crackmapexec or nxc")
        return {}

    cmd = [binary, service, target]

    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if hash_:
        cmd.extend(["-H", hash_])
    if domain:
        cmd.extend(["-d", domain])
    if shares:
        cmd.append("--shares")
    if users:
        cmd.append("--users")
    if command:
        cmd.extend(["-x", command])

    audit.tool_call(TOOL, "run", {
        "target": target,
        "service": service,
        "user": username,
        "shares": shares,
        "users": users,
    })

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, "CME timed out")
        return {}
    except Exception as e:
        audit.error(TOOL, f"CME failed: {e}")
        return {}

    result = _parse_output(stdout.decode(), service)
    audit.tool_call(TOOL, "result", {
        "valid_creds": result.get("valid_credentials", False),
        "shares": len(result.get("shares", [])),
    })
    return result


def _parse_output(output: str, service: str) -> dict:
    result = {
        "raw":               output[:3000],
        "valid_credentials": False,
        "admin":             False,
        "shares":            [],
        "users":             [],
        "command_output":    "",
    }

    for line in output.splitlines():
        # Auth result: [+] = success, [-] = fail, [*] = anonymous
        if "[+]" in line:
            result["valid_credentials"] = True
            if "Pwn3d!" in line or "Admin" in line:
                result["admin"] = True

        # Share enumeration
        share_m = re.search(r"(\w+)\s+(READ|WRITE|READ,WRITE)\s*$", line)
        if share_m:
            result["shares"].append({
                "name":   share_m.group(1),
                "access": share_m.group(2),
            })

        # User enumeration
        if "ARGUS" not in line and re.search(r"^\s+\w+\s+\d+\s+\d{4}.*", line):
            parts = line.strip().split()
            if parts:
                result["users"].append(parts[0])

    return result
