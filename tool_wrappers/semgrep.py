"""
Semgrep wrapper — SAST with security rulesets.
Returns structured findings: file, line, rule_id, message, severity, cwe.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any

from shared.logger import audit

TOOL = "semgrep"
TIMEOUT = 120  # seconds — large codebases take time

# Semgrep rulesets to run (p/ prefix = registry packs)
RULESETS = [
    "p/python",
    "p/javascript",
    "p/java",
    "p/golang",
    "p/php",
    "p/ruby",
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/secrets",
    "p/security-audit",
]


async def run(code_path: str, language: str = "", extra_rulesets: list[str] | None = None) -> list[dict]:
    if not shutil.which("semgrep"):
        audit.error(TOOL, "semgrep not found in PATH")
        return []

    path = Path(code_path)
    if not path.exists():
        audit.error(TOOL, f"Code path not found: {code_path}")
        return []

    # Select rulesets — language-specific + security fundamentals
    rulesets = _select_rulesets(language)
    if extra_rulesets:
        rulesets.extend(extra_rulesets)

    cmd = [
        "semgrep",
        "--json",
        "--no-git-ignore",
        "--timeout", str(TIMEOUT),
        "--max-memory", "2000",  # MB — prevent OOM on large repos
        "--metrics=off",
    ]
    for ruleset in rulesets:
        cmd.extend(["--config", ruleset])
    cmd.append(str(path))

    audit.tool_call(TOOL, "scan", {"path": code_path, "rulesets": rulesets})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT + 30)
    except asyncio.TimeoutError:
        audit.error(TOOL, f"Semgrep timed out after {TIMEOUT + 30}s")
        return []
    except Exception as e:
        audit.error(TOOL, f"Semgrep execution failed: {e}")
        return []

    if not stdout:
        audit.error(TOOL, f"Semgrep returned no output. stderr: {stderr.decode()[:500]}")
        return []

    try:
        raw = json.loads(stdout.decode())
    except json.JSONDecodeError as e:
        audit.error(TOOL, f"Semgrep JSON parse failed: {e}")
        return []

    findings = _parse_results(raw)
    audit.tool_call(TOOL, "result", {"findings_count": len(findings), "errors": len(raw.get("errors", []))})
    return findings


def _select_rulesets(language: str) -> list[str]:
    base = ["p/owasp-top-ten", "p/cwe-top-25", "p/secrets", "p/security-audit"]
    lang_map = {
        "python":     ["p/python"],
        "javascript": ["p/javascript"],
        "typescript": ["p/javascript"],
        "java":       ["p/java"],
        "go":         ["p/golang"],
        "golang":     ["p/golang"],
        "php":        ["p/php"],
        "ruby":       ["p/ruby"],
    }
    extra = lang_map.get(language.lower(), [])
    return base + [r for r in extra if r not in base]


def _parse_results(raw: dict) -> list[dict]:
    results = []
    for r in raw.get("results", []):
        meta = r.get("extra", {})
        metadata = meta.get("metadata", {})
        results.append({
            "tool":       "semgrep",
            "rule_id":    r.get("check_id", ""),
            "file":       r.get("path", ""),
            "line":       r.get("start", {}).get("line", 0),
            "end_line":   r.get("end", {}).get("line", 0),
            "message":    meta.get("message", ""),
            "severity":   meta.get("severity", "WARNING"),
            "cwe":        _extract_cwe(metadata),
            "owasp":      metadata.get("owasp", ""),
            "references": metadata.get("references", []),
            "code":       meta.get("lines", ""),
            "fix":        meta.get("fix", ""),
            "category":   metadata.get("category", ""),
            "subcategory":metadata.get("subcategory", []),
            "confidence": metadata.get("confidence", ""),
        })
    return results


def _extract_cwe(metadata: dict) -> str:
    cwe = metadata.get("cwe", "")
    if isinstance(cwe, list):
        return cwe[0] if cwe else ""
    return str(cwe)
