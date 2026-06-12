"""
JWT-tool wrapper — analyze JWTs for alg-none, weak secret, kid injection, jku abuse.
Also runs without the binary: pure-Python JWT structure + alg analysis.
"""
from __future__ import annotations

import asyncio
import base64
import json
import shutil

from shared.logger import audit

TOOL = "jwt_tool"
TIMEOUT = 60


async def run(token: str, target: str = "", timeout: int = TIMEOUT) -> list[dict]:
    audit.tool_call(TOOL, "analyze", f"token={token[:24]}...", target=target)

    findings = [_pure_python_analysis(token)]

    if shutil.which("jwt_tool"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "jwt_tool", token, "-M", "pb",  # playbook (read-only checks)
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            findings.append({
                "tool": "jwt_tool",
                "raw":  stdout.decode()[:4000],
            })
        except Exception as e:
            audit.error(TOOL, f"jwt_tool binary failed: {e}")

    return findings


def _pure_python_analysis(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Not a 3-part JWT"}

    def _b64decode(s: str) -> dict:
        pad = "=" * (-len(s) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(s + pad))
        except Exception:
            return {}

    header  = _b64decode(parts[0])
    payload = _b64decode(parts[1])
    alg     = (header.get("alg") or "").lower()

    issues: list[str] = []
    if alg in ("none", ""):
        issues.append("CRITICAL: alg=none — signature not verified")
    if alg == "hs256" and header.get("kid"):
        issues.append("Possible kid injection vector (HS256 + kid header)")
    if alg in ("hs256", "hs384", "hs512"):
        issues.append("Symmetric algorithm — try weak-secret bruteforce")
    if header.get("jku") or header.get("x5u"):
        issues.append("jku/x5u present — SSRF-via-key-fetch possible")
    if not payload.get("exp"):
        issues.append("No exp claim — token never expires")

    return {
        "tool":    "jwt_pure_python",
        "header":  header,
        "payload": {k: payload.get(k) for k in ("sub", "iss", "aud", "exp", "iat", "role")},
        "alg":     alg,
        "issues":  issues,
    }
