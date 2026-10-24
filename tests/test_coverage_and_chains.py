"""
Unit tests for the Part 2/4/5/6 additions: coverage_gate, the OWASP
manifest loader, skill_catalog eligibility, pivot_scanner, evidence_hygiene,
and the Finding schema's chain/validation additions.

Run: pytest tests/test_coverage_and_chains.py -v
"""
from pathlib import Path

import pytest

from shared.coverage_gate import (
    CategoryRecord, CoverageGate, CoverageGateError, CoverageStatus,
)
from shared.evidence_hygiene import flag_possible_pii, scrub_http_evidence
from shared.manifests.owasp_top10 import build_manifest
from shared.pivot_scanner import scan_new_finding
from shared.reporter import Confidence, Finding, Severity
from shared.session import Scope
from shared.skill_catalog import eligible, load_catalog
from shared.validation_gate import check_scope


# ── CoverageGate ────────────────────────────────────────────────────────────

class TestCoverageGate:

    def test_check_fails_when_categories_missing(self):
        manifest = [CategoryRecord("A01:2021", ["blackbox"]), CategoryRecord("A03:2021", ["blackbox"])]
        gate = CoverageGate(manifest, engagement_modes=["blackbox"])
        with pytest.raises(CoverageGateError):
            gate.check()

    def test_check_passes_once_every_category_reported(self):
        manifest = [CategoryRecord("A01:2021", ["blackbox"]), CategoryRecord("A03:2021", ["blackbox"])]
        gate = CoverageGate(manifest, engagement_modes=["blackbox"])
        gate.report("A01:2021", CoverageStatus.TESTED_CLEAN)
        gate.report("A03:2021", CoverageStatus.CONFIRMED, finding_count=2)
        gate.check()   # should not raise

    def test_skipped_without_reason_raises(self):
        manifest = [CategoryRecord("A01:2021", ["blackbox"])]
        gate = CoverageGate(manifest, engagement_modes=["blackbox"])
        with pytest.raises(ValueError):
            gate.report("A01:2021", CoverageStatus.SKIPPED)

    def test_category_not_applicable_to_this_engagement_mode_is_ignored(self):
        manifest = [CategoryRecord("A01:2021", ["whitebox"])]
        gate = CoverageGate(manifest, engagement_modes=["blackbox"])
        gate.check()   # A01 isn't applicable to blackbox here — nothing missing

    def test_matrix_reflects_reported_status(self):
        manifest = [CategoryRecord("A01:2021", ["blackbox"])]
        gate = CoverageGate(manifest, engagement_modes=["blackbox"])
        gate.report("A01:2021", CoverageStatus.CONFIRMED, finding_count=3, mode="blackbox")
        rows = gate.matrix()
        assert rows[0]["status"] == "CONFIRMED"
        assert rows[0]["finding_count"] == 3

    def test_pending_chain_event_blocks_check(self):
        manifest = [CategoryRecord("A01:2021", ["blackbox"])]
        gate = CoverageGate(manifest, engagement_modes=["blackbox"])
        gate.report("A01:2021", CoverageStatus.TESTED_CLEAN)
        gate.register_chain_event("webshell_rce:A:B")
        with pytest.raises(CoverageGateError):
            gate.check()
        gate.report_chain_event("webshell_rce:A:B", CoverageStatus.SKIPPED, reason="didn't hold")
        gate.check()   # resolved — should not raise


# ── OWASP manifest loader ───────────────────────────────────────────────────

class TestOwaspManifest:

    def test_blackbox_only_drops_whitebox_mode(self):
        manifest = build_manifest(codebase_path="")
        assert all("whitebox" not in c.applicable_modes for c in manifest)
        assert all("blackbox" in c.applicable_modes for c in manifest)
        assert len(manifest) == 10

    def test_with_codebase_path_keeps_whitebox_mode(self):
        manifest = build_manifest(codebase_path="/some/code")
        assert all("whitebox" in c.applicable_modes for c in manifest)


# ── skill_catalog ────────────────────────────────────────────────────────────

class TestSkillCatalog:

    CATALOG_ROOT = Path(__file__).resolve().parent.parent / "skills" / "owasp_top10"

    def test_catalog_loads_all_skill_files(self):
        skills = load_catalog(self.CATALOG_ROOT)
        assert len(skills) == 30   # 14 (A03) + 2*7 (A01,A02,A04,A05,A07,A08,A10) + 2 (A06,A09)

    def test_test_mode_is_hard_gate_not_relevance_signal(self):
        skills = load_catalog(self.CATALOG_ROOT)
        blackbox_only = eligible(skills, {"blackbox"}, set())
        for s in blackbox_only:
            assert s.test_mode in ("blackbox", "both")

    def test_whitebox_requires_codebase_path(self):
        skills = load_catalog(self.CATALOG_ROOT)
        whitebox_candidates = [s for s in skills if s.test_mode == "whitebox"]
        assert whitebox_candidates   # sanity: such files exist
        # Without codebase_path satisfied, none of the whitebox-only skills are eligible
        without_requirement = eligible(skills, {"whitebox"}, set())
        assert not any(s.test_mode == "whitebox" for s in without_requirement)
        with_requirement = eligible(skills, {"whitebox"}, {"codebase_path"})
        assert any(s.test_mode == "whitebox" for s in with_requirement)

    def test_training_only_never_eligible(self):
        training_root = Path(__file__).resolve().parent.parent / "skills" / "_training"
        # juice_shop_reference.md doesn't match *SKILL.md naming, so it's never
        # even discovered by load_catalog — belt-and-suspenders with test_mode.
        assert not list(training_root.glob("*SKILL.md"))


# ── pivot_scanner ────────────────────────────────────────────────────────────

class TestPivotScanner:

    def _finding(self, title, primitive):
        return Finding(
            agent="pentest", title=title, severity=Severity.HIGH,
            evidence="e", observed="o", inferred="i", primitive=primitive,
        )

    def test_known_pair_raises_candidate_chain(self):
        f1 = self._finding("Arbitrary File Write", "arbitrary_file_write")
        f2 = self._finding("LFI in template param", "local_file_inclusion")
        candidates = scan_new_finding(f2, [f1])
        assert len(candidates) == 1
        assert candidates[0].pivot_name == "webshell_rce"

    def test_unknown_pair_raises_nothing(self):
        f1 = self._finding("Some finding", "nosqli_read")
        f2 = self._finding("Unrelated finding", "crypto_weakness_confirmed")
        assert scan_new_finding(f2, [f1]) == []

    def test_finding_without_primitive_raises_nothing(self):
        f1 = self._finding("A", "arbitrary_file_write")
        f2 = self._finding("B", "")
        assert scan_new_finding(f2, [f1]) == []


# ── evidence_hygiene ─────────────────────────────────────────────────────────

class TestEvidenceHygiene:

    def test_scrubs_auth_header_keeps_name(self):
        scrubbed = scrub_http_evidence("Authorization: Bearer abc123\nX-Other: fine")
        assert "abc123" not in scrubbed
        assert "Authorization: [REDACTED]" in scrubbed
        assert "X-Other: fine" in scrubbed

    def test_scrubs_session_param(self):
        scrubbed = scrub_http_evidence("GET /x?session_token=abcDEF123&page=2")
        assert "abcDEF123" not in scrubbed
        assert "session_token=[REDACTED]" in scrubbed

    def test_flags_email_without_redacting(self):
        text = "Contact: jane.doe@example.com"
        assert flag_possible_pii(text)
        # flagging never mutates the source text
        assert "jane.doe@example.com" in text

    def test_finding_validate_scrubs_and_flags(self):
        f = Finding(
            agent="pentest", title="Leak", severity=Severity.LOW,
            evidence="Cookie: session=supersecret\nUser email: a@b.com",
            observed="o", inferred="i",
        )
        f.validate()
        assert "supersecret" not in f.evidence
        assert f.pii_flagged is True
        assert "email" in f.pii_flag_reason


# ── Finding chain schema ─────────────────────────────────────────────────────

class TestFindingChainSchema:

    def test_chain_finding_requires_two_steps(self):
        f = Finding(
            agent="pentest", title="Chain", severity=Severity.CRITICAL,
            evidence="e", observed="o", inferred="i",
            finding_type="chain", chain_steps=["only_one"],
            chain_evidence={"final_impact": "rce", "final_poc": "x", "pivot_logic": "y"},
        )
        with pytest.raises(ValueError, match="chain_steps"):
            f.validate()

    def test_chain_finding_requires_chain_evidence_fields(self):
        f = Finding(
            agent="pentest", title="Chain", severity=Severity.CRITICAL,
            evidence="e", observed="o", inferred="i",
            finding_type="chain", chain_steps=["a", "b"], chain_evidence={},
        )
        with pytest.raises(ValueError, match="chain_evidence"):
            f.validate()

    def test_valid_chain_finding_passes(self):
        f = Finding(
            agent="pentest", title="Chain", severity=Severity.CRITICAL,
            evidence="e", observed="o", inferred="i",
            finding_type="chain", chain_steps=["a", "b"],
            chain_evidence={"final_impact": "rce", "final_poc": "x", "pivot_logic": "y"},
            confirmed=True, confirmed_by=["pivot_scanner", "opus_chain_reasoning"],
        )
        f.validate()   # should not raise


# ── validation_gate scope check ──────────────────────────────────────────────

class TestValidationGateScope:

    def test_in_scope_target_passes(self):
        f = Finding(agent="pentest", title="x", severity=Severity.LOW,
                    evidence="e", observed="o", inferred="i", target="example.com")
        assert check_scope(f, Scope(["example.com"])) is True

    def test_out_of_scope_target_fails(self):
        f = Finding(agent="pentest", title="x", severity=Severity.LOW,
                    evidence="e", observed="o", inferred="i", target="evil.com")
        assert check_scope(f, Scope(["example.com"])) is False

    def test_no_target_or_url_fails(self):
        f = Finding(agent="pentest", title="x", severity=Severity.LOW,
                    evidence="e", observed="o", inferred="i")
        assert check_scope(f, Scope(["example.com"])) is False
