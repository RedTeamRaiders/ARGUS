"""
TruffleHog wrapper — secrets detection in source code and git history.
Returns structured findings: file, line, detector_type, secret (redacted), verified.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from shared.logger import audit

TOOL = "trufflehog"
TIMEOUT = 120


async def run(code_path: str, scan_git_history: bool = True) -> list[dict]:
    if not shutil.which("trufflehog"):
        # Try trufflehog3 (pip install trufflehog3)
        if not shutil.which("trufflehog3"):
            audit.error(TOOL, "trufflehog/trufflehog3 not found in PATH")
            return []
        return await _run_trufflehog3(code_path)

    return await _run_trufflehog_v3(code_path, scan_git_history)


async def _run_trufflehog_v3(code_path: str, scan_git_history: bool) -> list[dict]:
    """TruffleHog v3 (Go binary) — preferred, verifies secrets against APIs."""
    path = Path(code_path)

    # Determine scan target type
    is_git = (path / ".git").exists()
    if is_git and scan_git_history:
        target = f"git://file://{path.absolute()}"
    else:
        target = f"filesystem://{path.absolute()}"

    cmd = [
        "trufflehog",
        "--json",
        "--no-update",
        "--concurrency", "4",
    ]
    if is_git and scan_git_history:
        cmd.extend(["git", f"file://{path.absolute()}"])
    else:
        cmd.extend(["filesystem", str(path.absolute())])

    audit.tool_call(TOOL, "scan", {"path": code_path, "git_history": is_git and scan_git_history})

    findings = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"TruffleHog timed out after {TIMEOUT}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"TruffleHog execution failed: {e}")
        return []

    # TruffleHog v3 outputs one JSON object per line
    for line in stdout.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            findings.append(_parse_v3_result(obj))
        except json.JSONDecodeError:
            continue

    audit.tool_call(TOOL, "result", {"secrets_found": len(findings)})
    return findings


async def _run_trufflehog3(code_path: str) -> list[dict]:
    """TruffleHog3 (Python pip package) — fallback."""
    cmd = ["trufflehog3", "--json", code_path]
    audit.tool_call(TOOL, "scan_v3_fallback", {"path": code_path})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
    except Exception as e:
        audit.error(TOOL, f"TruffleHog3 failed: {e}")
        return []

    try:
        raw = json.loads(stdout.decode())
    except json.JSONDecodeError:
        return []

    findings = []
    for item in raw if isinstance(raw, list) else []:
        findings.append({
            "tool":          "trufflehog3",
            "detector_type": item.get("type", ""),
            "file":          item.get("path", ""),
            "line":          item.get("line", 0),
            "secret":        _redact(item.get("secret", "")),
            "commit":        item.get("commit", ""),
            "branch":        item.get("branch", ""),
            "verified":      False,
            "severity":      "High",
        })

    audit.tool_call(TOOL, "result", {"secrets_found": len(findings)})
    return findings


def _parse_v3_result(obj: dict) -> dict:
    source_meta = obj.get("SourceMetadata", {}).get("Data", {})
    file_info = source_meta.get("Filesystem", source_meta.get("Git", {}))

    return {
        "tool":          "trufflehog",
        "detector_type": obj.get("DetectorType", ""),
        "detector_name": obj.get("DetectorName", ""),
        "file":          file_info.get("file", ""),
        "line":          file_info.get("line", 0),
        "commit":        file_info.get("commit", ""),
        "secret":        _redact(obj.get("RawV2", obj.get("Raw", ""))),
        "redacted":      obj.get("Redacted", ""),
        "verified":      obj.get("Verified", False),
        "severity":      "Critical" if obj.get("Verified") else "High",
    }


def _redact(secret: str) -> str:
    if not secret or len(secret) < 8:
        return "***REDACTED***"
    return secret[:4] + "***REDACTED***" + secret[-4:]
