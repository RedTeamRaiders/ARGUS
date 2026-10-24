"""
validation_gate.py — Part 5: reportability validation.

Distinct from shared/coverage_gate.py ("did we test everything") and from
Part 1's evidence_schema ("is the technical proof solid"). This checks
"is this finding actually worth reporting" against four explicit criteria.
Three of the four require judgment, so this is deliberately a human-
judgment-style filter delegated to Claude reasoning (via the calling
agent's `_deep_think`), not a deterministic rule set.

Runs AFTER shared/coverage_gate.py's check() and each Finding's own
evidence_schema / Finding.validate() pass — the final filter before a
finding is eligible for reporter.py's finalize step. Every finding gets
Finding.validation_status set to "VALIDATED" or "REJECTED(<reason>)".
REJECTED findings stay in session.py's finding store (nothing is deleted)
but are excluded from the rendered report.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Awaitable, Callable

from shared.reporter import Finding
from shared.session import Scope

VALIDATION_CRITERIA = """
1. Is this exploitable right now, by an attacker with no special access,
   not just theoretically possible?
2. Is the affected asset confirmed in scope?
3. Does the finding match the engagement type's accepted-impact criteria?
   (A pentest report accepts more than a bug bounty program's VRT would.)
4. Is there a simpler non-exploit explanation for the observed behavior?
""".strip()

# Criterion 3's engagement-specific bar — data only, so a new engagement
# type can be added here without touching the gate logic itself.
ENGAGEMENT_BARS = {
    "pentest": (
        "Accept findings that demonstrate a real weakness even without full "
        "exploitation (a confirmed misconfiguration, a verified but "
        "not-yet-escalated primitive) — a pentest report documents the "
        "attack surface, not only completed compromises."
    ),
    "bug_bounty": (
        "Apply a stricter bar matching typical VRT acceptance: the finding "
        "must demonstrate real, immediate security impact (data exposure, "
        "privilege escalation, account takeover, etc.). Informational "
        "findings, purely theoretical weaknesses, and self-XSS with no "
        "victim delivery path are typically REJECTED under a bug bounty "
        "program's VRT even though a pentest report would accept them."
    ),
}

Reasoner = Callable[..., Awaitable[str]]   # signature matches BaseAgent._deep_think(prompt, context="")


@dataclass
class ValidationResult:
    status: str      # "VALIDATED" or "REJECTED"
    reason: str = ""


def check_scope(finding: Finding, scope: Scope) -> bool:
    """
    Criterion 2 — cross-checked against session.py's Scope.contains(),
    the same scope object enforced by shared/auth_gate.py. Never
    reimplemented here.
    """
    target = finding.target or finding.url
    if not target:
        return False
    return scope.contains(target)


def _parse_json(text: str) -> dict:
    try:
        raw = text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw)
    except (json.JSONDecodeError, IndexError):
        m = re.search(r"(\{.*\})", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
        return {}


async def validate_finding(
    finding: Finding,
    scope: Scope,
    engagement_type: str,
    reasoner: Reasoner,
) -> ValidationResult:
    """Apply all four criteria to one finding."""
    if not check_scope(finding, scope):
        return ValidationResult(
            "REJECTED",
            f"Affected asset {finding.target or finding.url!r} is not confirmed in scope.",
        )

    bar = ENGAGEMENT_BARS.get(engagement_type, ENGAGEMENT_BARS["pentest"])
    prompt = (
        "Apply reportability validation to this finding using these criteria:\n"
        f"{VALIDATION_CRITERIA}\n\n"
        f"Engagement type: {engagement_type}\n"
        f"Acceptance bar for criterion 3: {bar}\n\n"
        f"Finding title: {finding.title}\n"
        f"Severity: {finding.severity.value}\n"
        f"Description: {finding.description}\n"
        f"Observed (tool-confirmed): {finding.observed}\n"
        f"Evidence: {finding.evidence[:1500]}\n"
        f"Confirmed: {finding.confirmed} by {finding.confirmed_by}\n\n"
        'Respond JSON only: {"validated": true/false, "reason": ""}'
    )
    verdict_text = await reasoner(prompt)
    verdict = _parse_json(verdict_text)
    if verdict.get("validated"):
        return ValidationResult("VALIDATED")
    return ValidationResult("REJECTED", verdict.get("reason") or "Did not meet reportability criteria.")


async def apply_validation_gate(
    findings: list[Finding],
    scope: Scope,
    engagement_type: str,
    reasoner: Reasoner,
) -> list[Finding]:
    """
    Run AFTER coverage_gate.check() and each finding's own validate() pass.
    Sets Finding.validation_status on every finding and returns only the
    VALIDATED ones for inclusion in the report.
    """
    validated: list[Finding] = []
    for f in findings:
        result = await validate_finding(f, scope, engagement_type, reasoner)
        f.validation_status = result.status if result.status == "VALIDATED" else f"REJECTED({result.reason})"
        if result.status == "VALIDATED":
            validated.append(f)
    return validated
