"""
Dnsx wrapper — DNS resolution + record extraction (ProjectDiscovery).
Use to: validate which subfinder/amass hosts actually resolve, pull A/CNAME/MX/TXT.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from shared.logger import audit

TOOL = "dnsx"
TIMEOUT = 120


async def run(
    target: str | list[str],
    record_types: str = "a,cname",
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("dnsx"):
        audit.error(TOOL, "dnsx not in PATH — install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        return []

    # Accept single domain or list — write list to tempfile
    hosts = [target] if isinstance(target, str) else list(target)
    if not hosts:
        return []

    tmp = NamedTemporaryFile("w", delete=False, suffix=".txt")
    try:
        tmp.write("\n".join(h.replace("https://", "").replace("http://", "").split("/")[0] for h in hosts))
        tmp.close()

        cmd = [
            "dnsx",
            "-l", tmp.name,
            "-resp", "-json", "-silent",
            "-rt", record_types,
        ]
        audit.tool_call(TOOL, "resolve", f"records={record_types} count={len(hosts)}", target=str(hosts[0]))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            audit.error(TOOL, f"dnsx timed out after {timeout}s")
            return []
        except Exception as e:
            audit.error(TOOL, f"dnsx failed: {e}")
            return []
    finally:
        Path(tmp.name).unlink(missing_ok=True)

    results = []
    for line in stdout.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append({
                "host":  obj.get("host", ""),
                "a":     obj.get("a", []),
                "cname": obj.get("cname", []),
                "mx":    obj.get("mx", []),
                "txt":   obj.get("txt", []),
                "ns":    obj.get("ns", []),
            })
        except json.JSONDecodeError:
            continue

    audit.tool_call(TOOL, "result", f"resolved={len(results)}", target=hosts[0])
    return results
