"""
evidence_hygiene.py — Part 6: scrub/flag evidence before it's persisted.

Wired into shared/reporter.py's Finding.validate() — the point every
finding already passes through immediately before session.add_finding()
in agents/base_agent.py, agents/pentest.py, and agents/bug_bounty.py. Two
distinct operations, deliberately not conflated:

  1. Scrub (automatic, safe to do unconditionally): cookie values,
     Authorization headers, and session tokens found in captured HTTP
     evidence are replaced with [REDACTED] — the header/param NAME is kept
     so the finding stays readable.
  2. Flag (never auto-redact — a human decides): evidence/response bodies
     that may contain real user PII (email addresses, SSN-shaped values,
     name-like fields) are flagged for review via Finding.pii_flagged /
     pii_flag_reason, not silently altered, so they don't land in
     reports/ unreviewed.
"""
from __future__ import annotations

import re

_HEADER_SCRUB_PATTERN = re.compile(
    r"(?im)^(Authorization|Cookie|Set-Cookie|X-Auth-Token|X-Api-Key)\s*:\s*.+$"
)
_BEARER_TOKEN_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")
_SESSION_PARAM_PATTERN = re.compile(
    r"(?i)\b(session_?id|session_?token|csrf_?token|jwt|access_?token)=([^\s&\"';]+)"
)

_EMAIL_PATTERN     = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_SSN_PATTERN       = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_NAME_HINT_PATTERN = re.compile(r'(?i)\b(first_?name|last_?name|full_?name)\s*[":=]\s*["\']?[A-Za-z]{2,}')


def scrub_http_evidence(text: str) -> str:
    """Replace cookie/auth-header/session-token VALUES with [REDACTED]; keep the names."""
    if not text:
        return text

    def _scrub_header(m: re.Match) -> str:
        return f"{m.group(1)}: [REDACTED]"

    text = _HEADER_SCRUB_PATTERN.sub(_scrub_header, text)
    text = _BEARER_TOKEN_PATTERN.sub("Bearer [REDACTED]", text)
    text = _SESSION_PARAM_PATTERN.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    return text


def flag_possible_pii(text: str) -> list[str]:
    """Never auto-redacts — returns human-readable reasons to flag, or [] if none."""
    reasons: list[str] = []
    if not text:
        return reasons
    if _EMAIL_PATTERN.search(text):
        reasons.append("possible email address")
    if _SSN_PATTERN.search(text):
        reasons.append("possible SSN-shaped value")
    if _NAME_HINT_PATTERN.search(text):
        reasons.append("possible real name field")
    return reasons


def scrub_and_flag(finding) -> None:
    """
    Mutates `finding` in place: scrubs evidence/poc/observed text, and sets
    finding.pii_flagged / finding.pii_flag_reason if a PII-shaped pattern is
    seen anywhere in its text fields. Called from Finding.validate() —
    never silently skipped, since validate() always runs before a finding
    is persisted via session.add_finding().
    """
    for field_name in ("evidence", "poc", "observed"):
        value = getattr(finding, field_name, "")
        if isinstance(value, str) and value:
            setattr(finding, field_name, scrub_http_evidence(value))

    reasons: list[str] = []
    for field_name in ("evidence", "poc", "observed", "description"):
        value = getattr(finding, field_name, "")
        if isinstance(value, str):
            reasons.extend(flag_possible_pii(value))

    if reasons:
        finding.pii_flagged = True
        finding.pii_flag_reason = "; ".join(sorted(set(reasons)))
