"""
ParamSpider wrapper — extract parameter-bearing URLs from web archives.
Complements arjun: arjun fuzzes live, paramspider mines history.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from shared.logger import audit

TOOL = "paramspider"
TIMEOUT = 120


async def run(
    target: str,
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("paramspider"):
        audit.error(TOOL, "paramspider not in PATH — install: pip install paramspider")
        return []

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    with TemporaryDirectory() as tmpdir:
        cmd = ["paramspider", "-d", domain, "-o", tmpdir, "--quiet"]
        audit.tool_call(TOOL, "mine", "paramspider -d " + domain, target=domain)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            audit.error(TOOL, f"paramspider timed out after {timeout}s")
            return []
        except Exception as e:
            audit.error(TOOL, f"paramspider failed: {e}")
            return []

        results: list[dict] = []
        for f in Path(tmpdir).glob("*.txt"):
            for line in f.read_text().splitlines():
                line = line.strip()
                if not line or "?" not in line:
                    continue
                url, _, query = line.partition("?")
                for pair in query.split("&"):
                    if "=" not in pair:
                        continue
                    name = pair.split("=", 1)[0]
                    results.append({"url": url, "param": name})

    # Dedup
    seen, deduped = set(), []
    for r in results:
        key = (r["url"], r["param"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    audit.tool_call(TOOL, "result", f"params={len(deduped)}", target=domain)
    return deduped
