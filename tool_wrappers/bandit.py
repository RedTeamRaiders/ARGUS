"""
Bandit wrapper — Python-specific security linter.
Returns structured findings: file, line, test_id, issue_text, severity, confidence, cwe.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from shared.logger import audit

TOOL = "bandit"
TIMEOUT = 90


async def run(code_path: str, severity_filter: str = "l", confidence_filter: str = "l") -> list[dict]:
    """
    Run bandit on a Python codebase.
    severity_filter / confidence_filter: 'l' (low+), 'm' (medium+), 'h' (high only)
    """
    if not shutil.which("bandit"):
        audit.error(TOOL, "bandit not found in PATH — install: pip install bandit")
        return []

    path = Path(code_path)
    if not path.exists():
        audit.error(TOOL, f"Code path not found: {code_path}")
        return []

    cmd = [
        "bandit",
        "-r",                          # recursive
        "-f", "json",                  # JSON output
        f"-l",                         # all severity levels
        f"-i",                         # all confidence levels
        "--exclude", ".venv,venv,node_modules,tests",
        str(path),
    ]

    audit.tool_call(TOOL, "scan", {"path": code_path})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"Bandit timed out after {TIMEOUT}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"Bandit execution failed: {e}")
        return []

    if not stdout:
        return []

    try:
        raw = json.loads(stdout.decode())
    except json.JSONDecodeError:
        # Bandit sometimes writes partial JSON on error — try to recover
        text = stdout.decode()
        brace = text.rfind("}")
        if brace > 0:
            try:
                raw = json.loads(text[:brace + 1])
            except json.JSONDecodeError:
                audit.error(TOOL, "Bandit JSON parse failed")
                return []
        else:
            return []

    findings = _parse_results(raw)
    audit.tool_call(TOOL, "result", {
        "findings_count": len(findings),
        "skipped":        len(raw.get("errors", [])),
    })
    return findings


def _parse_results(raw: dict) -> list[dict]:
    results = []
    for r in raw.get("results", []):
        results.append({
            "tool":        "bandit",
            "test_id":     r.get("test_id", ""),
            "test_name":   r.get("test_name", ""),
            "file":        r.get("filename", ""),
            "line":        r.get("line_number", 0),
            "end_line":    r.get("end_col_offset", 0),
            "code":        r.get("code", ""),
            "message":     r.get("issue_text", ""),
            "severity":    r.get("issue_severity", ""),
            "confidence":  r.get("issue_confidence", ""),
            "cwe":         _format_cwe(r.get("issue_cwe", {})),
            "more_info":   r.get("more_info", ""),
        })
    return results


def _format_cwe(cwe_obj: dict | str) -> str:
    if isinstance(cwe_obj, dict):
        cwe_id = cwe_obj.get("id", "")
        return f"CWE-{cwe_id}" if cwe_id else ""
    return str(cwe_obj) if cwe_obj else ""
