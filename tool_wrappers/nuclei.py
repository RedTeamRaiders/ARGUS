"""
Nuclei wrapper — template-based vulnerability scanner.
Two modes: 'detect' (safe templates only) and 'exploit' (CVE/exploit templates).
"""
from __future__ import annotations

import asyncio
import json
import shutil

from shared.logger import audit

TOOL = "nuclei"
TIMEOUT = 180

DETECT_TAGS  = "detect,info,exposure,config,misconfig,default-login,panel"
EXPLOIT_TAGS = "cve,sqli,xss,ssrf,rce,lfi,rfi,xxe,ssti,auth-bypass"


async def run(
    target: str,
    mode: str = "detect",
    tags: str = "",
    templates: str = "",
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("nuclei"):
        audit.error(TOOL, "nuclei not found in PATH")
        return []

    active_tags = tags or (DETECT_TAGS if mode == "detect" else EXPLOIT_TAGS)

    cmd = [
        "nuclei",
        "-u", target,
        "-json",
        "-silent",
        "-t", "/root/nuclei-templates/",
        "-tags", active_tags,
        "-timeout", "10",
        "-retries", "1",
        "-rate-limit", "20",
    ]
    if templates:
        cmd.extend(["-t", templates])

    audit.tool_call(TOOL, "scan", {"target": target, "mode": mode, "tags": active_tags})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 60)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"Nuclei timed out")
        return []
    except Exception as e:
        audit.error(TOOL, f"Nuclei failed: {e}")
        return []

    findings = []
    for line in stdout.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            findings.append(_parse_result(obj))
        except json.JSONDecodeError:
            continue

    audit.tool_call(TOOL, "result", {"findings": len(findings)})
    return findings


def _parse_result(obj: dict) -> dict:
    info = obj.get("info", {})
    return {
        "tool":         "nuclei",
        "template_id":  obj.get("template-id", ""),
        "name":         info.get("name", ""),
        "severity":     info.get("severity", ""),
        "description":  info.get("description", ""),
        "tags":         info.get("tags", []),
        "cve":          info.get("classification", {}).get("cve-id", []),
        "cwe":          info.get("classification", {}).get("cwe-id", []),
        "url":          obj.get("matched-at", ""),
        "matcher_name": obj.get("matcher-name", ""),
        "extracted_results": obj.get("extracted-results", []),
        "curl_command": obj.get("curl-command", ""),
    }
