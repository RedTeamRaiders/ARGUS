"""
xss_verification.py — mandatory Playwright headless verification for XSS
findings (agents/CLAUDE.md critical rule 5: "XSS findings require Playwright
headless verification before reporting").

That rule was previously only honored inside bug_bounty.py's bespoke
crawl-driven _xss_pipeline, which generates AND confirms its own XSS findings
in one pass. Any OTHER agent (pentest.py, red_team.py) that materializes an
XSS finding through the generic ReAct loop (agents/base_agent.py's
_materialize_finding_with_sonnet) had no such check — the finding's
`confirmed` flag was whatever Sonnet self-reported from tool-output text,
never independently fired in a browser.

This is a standalone gate, not agent-specific, so any agent's run() can call
apply_xss_verification_gate() the same way pentest.py already calls
shared/validation_gate.py's apply_validation_gate() — see agents/pentest.py.

Scope: this can only replay REFLECTED XSS (a GET parameter echoed back),
since that's all that's reconstructable from a Finding's .url/.parameter/.poc
after the fact, with no live crawl session. Stored/DOM XSS claims can't be
replayed this way and are rejected with an explicit reason rather than
guessed at — "can't verify" must never silently become "ship it anyway".
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from shared.logger import audit
from shared.reporter import Confidence, Finding

_PAYLOAD_PATTERN = re.compile(
    r"(<script\b.*?</script\s*>|<[a-zA-Z][^>]*\son\w+\s*=.*?>|javascript:\S+)",
    re.IGNORECASE | re.DOTALL,
)


def is_xss_finding(finding: Finding) -> bool:
    """True if this finding claims an XSS vulnerability and therefore falls
    under the mandatory-Playwright-verification rule."""
    haystack = f"{finding.cwe} {finding.title} {finding.primitive}".lower()
    return "cwe-79" in haystack or "xss" in haystack


# Markers left by a pipeline that already fired the payload in a real
# browser and watched it execute — e.g. bug_bounty.py's _xss_pipeline, which
# drives its own crawl + canary + PayloadInjector + ExecutionMonitor session
# before ever creating the Finding. Those findings must NOT be re-verified
# here: this module's stateless GET-replay (finding.url + finding.parameter)
# cannot reproduce a form/POST injection, so blindly re-checking a genuinely
# confirmed finding through the wrong vector would reject a true positive.
ALREADY_VERIFIED_MARKERS = {"playwright_dialog_confirmation", "playwright_headless_verification"}


def already_playwright_verified(finding: Finding) -> bool:
    return bool(ALREADY_VERIFIED_MARKERS & set(finding.confirmed_by))


@dataclass
class VerificationResult:
    verified: bool
    reason:   str
    evidence: str = ""


def _extract_payload(finding: Finding) -> str:
    """
    Pull the actual payload string out of freeform LLM text. Sonnet writes
    `poc`/`evidence`/`observed` as prose (see base_agent.py's
    _materialize_finding_with_sonnet prompt), not a structured payload field,
    so this looks for an actual script/event-handler/javascript: pattern
    rather than assuming any particular format.
    """
    for candidate in (finding.poc, finding.evidence, finding.observed):
        if not candidate:
            continue
        m = _PAYLOAD_PATTERN.search(candidate)
        if m:
            return m.group(1)
    return ""


def _build_replay_url(finding: Finding, payload: str) -> str | None:
    """Reconstruct a GET-replayable URL with the payload set on the
    vulnerable parameter. Requires both finding.url and finding.parameter."""
    if not finding.url or not finding.parameter:
        return None
    parts = urlsplit(finding.url)
    query = dict(parse_qsl(parts.query))
    query[finding.parameter] = payload
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


async def verify_xss_finding(finding: Finding) -> VerificationResult:
    """
    Fires the finding's payload against its URL/parameter in a real headless
    browser and checks for an actual execution signal (alert/confirm/prompt
    dialog) — never trusts the LLM's self-reported `confirmed` flag for this
    vuln class.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return VerificationResult(False, "Playwright not installed — cannot verify XSS execution.")

    payload = _extract_payload(finding)
    if not payload:
        return VerificationResult(
            False,
            "No script/event-handler/javascript: payload pattern found in "
            "poc/evidence/observed — nothing concrete to replay.",
        )

    replay_url = _build_replay_url(finding, payload)
    if not replay_url:
        return VerificationResult(
            False,
            "No replayable GET URL (missing finding.url or finding.parameter) — "
            "likely stored/DOM XSS or a non-GET injection point this stateless "
            "replay can't reach.",
        )

    from tool_wrappers.argus_crawler.monitor import ExecutionMonitor

    browser = None
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()
            async with ExecutionMonitor(page) as monitor:
                await page.goto(replay_url, wait_until="networkidle", timeout=15000)
                events = await monitor.check_execution(wait_ms=1500)
            if monitor.confirmed_xss:
                dialog_event = next(e for e in events if e.signal == "dialog")
                return VerificationResult(True, "Dialog fired on payload replay.", dialog_event.evidence)
            if monitor.potential_xss:
                return VerificationResult(
                    False,
                    "Payload reflected but no dialog/execution signal fired on replay "
                    "(likely encoded or sanitized) — rejecting rather than shipping an "
                    "unconfirmed XSS.",
                )
            return VerificationResult(False, "No execution signal on replay — payload did not fire.")
    except Exception as e:
        audit.error("xss_verification", f"Replay failed for {finding.title!r}: {e}")
        return VerificationResult(False, f"Replay errored: {e}")
    finally:
        if browser is not None:
            await browser.close()


async def apply_xss_verification_gate(findings: list[Finding]) -> list[Finding]:
    """
    Call once per engagement, after the main ReAct loop(s) and before
    shared/validation_gate.py's reportability pass — an unverified XSS claim
    must never reach the "is this reportable" judgment looking plausible on
    nothing but Sonnet's self-reported `confirmed` flag.

    Every XSS-shaped finding is independently replayed in a headless browser.
    Verified findings get their confidence/confirmed_by upgraded with real
    proof; unverified ones are downgraded and dropped from the returned list
    (they were already persisted to session.py's store at creation time —
    same "rejected but not deleted" pattern as shared/validation_gate.py).
    Non-XSS findings pass through untouched — as do XSS findings that
    already carry a real browser confirmation from elsewhere (see
    already_playwright_verified() above), so this is safe to call on a
    finding set that mixes generic-ReAct-loop findings with a dedicated
    pipeline's own already-verified ones (e.g. bug_bounty.py's
    _xss_pipeline alongside its Phase 3 generic loop).
    """
    out: list[Finding] = []
    for f in findings:
        if not is_xss_finding(f) or already_playwright_verified(f):
            out.append(f)
            continue

        result = await verify_xss_finding(f)
        if result.verified:
            if "playwright_headless_verification" not in f.confirmed_by:
                f.confirmed_by.append("playwright_headless_verification")
            f.confirmed = True
            f.confidence = Confidence.HIGH
            if result.evidence:
                f.evidence = f"{f.evidence}\n\n[Playwright replay confirmation] {result.evidence}"
            out.append(f)
        else:
            audit.info("xss_verification", f"XSS finding {f.title!r} failed verification: {result.reason}")
            f.confirmed = False
            f.confidence = Confidence.LOW
            f.validation_status = f"REJECTED(unverified XSS: {result.reason})"
            # Deliberately not appended to `out` — see docstring.

    return out
