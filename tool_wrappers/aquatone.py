"""
Aquatone wrapper — visual recon (screenshots) of discovered hosts.
Pure evidence collection: each finding gets a screenshot path for the report.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from shared.logger import audit

TOOL = "aquatone"
TIMEOUT = 600


async def run(
    hosts: list[str],
    out_dir: str = "data/aquatone",
    timeout: int = TIMEOUT,
) -> list[dict]:
    if not shutil.which("aquatone"):
        audit.error(TOOL, "aquatone not in PATH — install: go install github.com/michenriksen/aquatone@latest")
        return []
    if not hosts:
        return []

    in_file = NamedTemporaryFile("w", delete=False, suffix=".txt")
    in_file.write("\n".join(hosts))
    in_file.close()

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    cmd = [
        "aquatone",
        "-out", str(out_path),
        "-silent",
        "-scan-timeout", "5000",
        "-http-timeout", "10000",
    ]
    audit.tool_call(TOOL, "screenshot", f"hosts={len(hosts)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=open(in_file.name, "rb"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"aquatone timed out after {timeout}s")
        Path(in_file.name).unlink(missing_ok=True)
        return []
    except Exception as e:
        audit.error(TOOL, f"aquatone failed: {e}")
        Path(in_file.name).unlink(missing_ok=True)
        return []
    finally:
        Path(in_file.name).unlink(missing_ok=True)

    results: list[dict] = []
    sessions_file = out_path / "aquatone_session.json"
    if sessions_file.exists():
        try:
            data = json.loads(sessions_file.read_text())
            for page in data.get("pages", {}).values():
                results.append({
                    "url":        page.get("url", ""),
                    "status":     page.get("status", 0),
                    "screenshot": str(out_path / page.get("screenshotPath", "")),
                    "title":      page.get("pageTitle", ""),
                })
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    audit.tool_call(TOOL, "result", f"screens={len(results)}")
    return results
