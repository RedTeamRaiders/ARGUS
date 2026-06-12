"""
WPScan wrapper — WordPress fingerprinting + vuln enum.
Requires WPSCAN_API_TOKEN for the vuln DB. Without it, still does plugin/user enum.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil

from shared.logger import audit

TOOL = "wpscan"
TIMEOUT = 600


async def run(
    target: str,
    enumerate: str = "vp,vt,u",   # vulnerable plugins/themes + users
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("wpscan"):
        audit.error(TOOL, "wpscan not in PATH — install: gem install wpscan")
        return []

    cmd = [
        "wpscan",
        "--url", target,
        "--enumerate", enumerate,
        "--format", "json",
        "--no-banner",
        "--random-user-agent",
        "--throttle", "200",   # 200ms between requests — anti-scanner
    ]
    api = os.getenv("WPSCAN_API_TOKEN", "")
    if api:
        cmd.extend(["--api-token", api])

    audit.tool_call(TOOL, "scan", " ".join(cmd[:6]), target=target)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"wpscan timed out after {timeout}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"wpscan failed: {e}")
        return []

    try:
        data = json.loads(stdout.decode())
    except json.JSONDecodeError:
        return [{"raw": stdout.decode()[:2000]}]

    results: list[dict] = []
    wp = data.get("version") or {}
    if wp:
        results.append({
            "type":      "wp_core",
            "version":   wp.get("number", ""),
            "vulnerabilities": wp.get("vulnerabilities", []),
        })
    for plugin, info in (data.get("plugins") or {}).items():
        results.append({
            "type":     "plugin",
            "name":     plugin,
            "version":  info.get("version", {}).get("number", ""),
            "vulnerabilities": info.get("vulnerabilities", []),
        })
    for theme, info in (data.get("themes") or {}).items():
        results.append({
            "type":     "theme",
            "name":     theme,
            "version":  info.get("version", {}).get("number", ""),
            "vulnerabilities": info.get("vulnerabilities", []),
        })
    for user in data.get("users") or {}:
        results.append({"type": "user", "username": user})

    audit.tool_call(TOOL, "result", f"items={len(results)}", target=target)
    return results
