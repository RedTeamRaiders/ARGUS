"""
Unit tests for shared/xss_verification.py — the mandatory Playwright
headless verification gate for XSS findings (agents/CLAUDE.md critical
rule 5: "XSS findings require Playwright headless verification before
reporting").

Run: pytest tests/test_xss_verification.py -v
"""
from unittest.mock import AsyncMock, patch

from shared.reporter import Confidence, Finding, Severity


def _xss_finding(**overrides) -> Finding:
    defaults = dict(
        agent="pentest",
        title="Reflected XSS in q",
        severity=Severity.HIGH,
        evidence="dalfox output: <script>alert(1)</script> reflected",
        observed="payload reflected unescaped",
        inferred="",
        cwe="CWE-79",
        owasp="A03",
        poc="<script>alert(1)</script>",
        confidence=Confidence.HIGH,
        confirmed=True,
        confirmed_by=["sonnet_self_report"],
        url="https://target.test/search",
        parameter="q",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ── is_xss_finding ──────────────────────────────────────────────────────

class TestIsXssFinding:

    def test_detects_by_cwe(self):
        from shared.xss_verification import is_xss_finding
        f = _xss_finding(title="Something unrelated")
        assert is_xss_finding(f)

    def test_detects_by_title_keyword(self):
        from shared.xss_verification import is_xss_finding
        f = _xss_finding(cwe="", title="Stored XSS via comment field")
        assert is_xss_finding(f)

    def test_non_xss_finding_not_flagged(self):
        from shared.xss_verification import is_xss_finding
        f = _xss_finding(cwe="CWE-89", title="SQL Injection in id param", primitive="sqli_read")
        assert not is_xss_finding(f)


# ── already_playwright_verified ──────────────────────────────────────────
# bug_bounty.py's _xss_pipeline fires its own payloads via Playwright and
# tags its findings before this gate ever sees them. Re-running a stateless
# GET replay against a finding that was actually confirmed through a form/
# POST injection would reject a true positive — must be skipped instead.

class TestAlreadyPlaywrightVerified:

    def test_dialog_confirmation_marker_is_recognized(self):
        from shared.xss_verification import already_playwright_verified
        f = _xss_finding(confirmed_by=["playwright_dialog_confirmation"])
        assert already_playwright_verified(f)

    def test_own_gate_marker_is_recognized(self):
        from shared.xss_verification import already_playwright_verified
        f = _xss_finding(confirmed_by=["playwright_headless_verification"])
        assert already_playwright_verified(f)

    def test_llm_self_report_alone_is_not_recognized(self):
        from shared.xss_verification import already_playwright_verified
        f = _xss_finding(confirmed_by=["sonnet_self_report"])
        assert not already_playwright_verified(f)


# ── _extract_payload ────────────────────────────────────────────────────

class TestExtractPayload:

    def test_extracts_script_tag(self):
        from shared.xss_verification import _extract_payload
        f = _xss_finding(poc="Payload: <script>alert(document.domain)</script>")
        assert "<script>" in _extract_payload(f)

    def test_extracts_event_handler(self):
        from shared.xss_verification import _extract_payload
        f = _xss_finding(poc="", evidence="injected <img src=x onerror=alert(1)>")
        assert "onerror" in _extract_payload(f)

    def test_no_payload_pattern_returns_empty(self):
        from shared.xss_verification import _extract_payload
        f = _xss_finding(poc="the field reflects user input", evidence="", observed="")
        assert _extract_payload(f) == ""


# ── _build_replay_url ───────────────────────────────────────────────────

class TestBuildReplayUrl:

    def test_builds_url_with_payload_in_param(self):
        from shared.xss_verification import _build_replay_url
        f = _xss_finding(url="https://target.test/search?x=1", parameter="q")
        replay = _build_replay_url(f, "<script>alert(1)</script>")
        assert replay is not None
        assert "x=1" in replay
        assert "q=" in replay

    def test_missing_url_returns_none(self):
        from shared.xss_verification import _build_replay_url
        f = _xss_finding(url="", parameter="q")
        assert _build_replay_url(f, "<script>alert(1)</script>") is None

    def test_missing_parameter_returns_none(self):
        from shared.xss_verification import _build_replay_url
        f = _xss_finding(url="https://target.test/search", parameter="")
        assert _build_replay_url(f, "<script>alert(1)</script>") is None


# ── verify_xss_finding — reason paths that don't require a real browser ──

class TestVerifyXssFindingReasons:

    async def test_no_payload_is_rejected_with_reason(self):
        from shared.xss_verification import verify_xss_finding
        f = _xss_finding(poc="no concrete payload here", evidence="", observed="")
        result = await verify_xss_finding(f)
        assert result.verified is False
        assert "payload" in result.reason.lower()

    async def test_missing_url_is_rejected_with_reason(self):
        from shared.xss_verification import verify_xss_finding
        f = _xss_finding(url="", poc="<script>alert(1)</script>")
        result = await verify_xss_finding(f)
        assert result.verified is False
        assert "replayable" in result.reason.lower()


# ── apply_xss_verification_gate ─────────────────────────────────────────

class TestApplyXssVerificationGate:

    async def test_non_xss_findings_pass_through_untouched(self):
        from shared.xss_verification import apply_xss_verification_gate
        f = Finding(
            agent="pentest", title="SQLi", severity=Severity.HIGH,
            evidence="sqlmap: injectable", observed="", inferred="",
            cwe="CWE-89", confirmed=True, confirmed_by=["sqlmap", "manual"],
        )
        out = await apply_xss_verification_gate([f])
        assert out == [f]

    async def test_verified_xss_is_upgraded_and_kept(self):
        from shared.xss_verification import apply_xss_verification_gate, VerificationResult
        f = _xss_finding(confidence=Confidence.MEDIUM, confirmed=False, confirmed_by=[])
        with patch(
            "shared.xss_verification.verify_xss_finding",
            new=AsyncMock(return_value=VerificationResult(True, "Dialog fired.", "alert(1)")),
        ):
            out = await apply_xss_verification_gate([f])
        assert len(out) == 1
        assert out[0].confirmed is True
        assert out[0].confidence == Confidence.HIGH
        assert "playwright_headless_verification" in out[0].confirmed_by

    async def test_unverified_xss_is_dropped_from_report(self):
        from shared.xss_verification import apply_xss_verification_gate, VerificationResult
        f = _xss_finding()
        with patch(
            "shared.xss_verification.verify_xss_finding",
            new=AsyncMock(return_value=VerificationResult(False, "No execution signal.")),
        ):
            out = await apply_xss_verification_gate([f])
        assert out == []
        assert f.confirmed is False
        assert f.confidence == Confidence.LOW
        assert "REJECTED" in f.validation_status

    async def test_already_playwright_verified_finding_is_not_rechecked(self):
        # Simulates bug_bounty.py's _xss_pipeline output flowing through the
        # same gate call as its Phase 3 generic-loop findings: this finding
        # must pass through unchanged, and verify_xss_finding must never be
        # invoked for it (a stateless GET replay can't reproduce a form/POST
        # injection and would wrongly reject a true positive).
        from shared.xss_verification import apply_xss_verification_gate
        f = _xss_finding(confirmed_by=["playwright_dialog_confirmation"])
        mock_verify = AsyncMock()
        with patch("shared.xss_verification.verify_xss_finding", new=mock_verify):
            out = await apply_xss_verification_gate([f])
        assert out == [f]
        mock_verify.assert_not_called()
