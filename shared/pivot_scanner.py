"""
pivot_scanner.py — deterministic, rules-based compromise-chain detection.

NOT an LLM call. Cross-references a newly CONFIRMED finding's `primitive`
tag (shared/reporter.py's Finding.primitive, populated from a skill file's
`primitive` frontmatter field — see skills/owasp_top10/) against every
prior CONFIRMED finding's primitive for a known combinable pair.

On a match this raises a CANDIDATE_CHAIN event (a CandidateChain object)
back into the agent's ReAct loop — it never auto-creates a finding_type:
chain Finding itself. Only the agent (with Claude reasoning, see
BaseAgent._resolve_candidate_chains in agents/base_agent.py) decides whether
the pivot actually holds and builds the chain Finding with full
chain_evidence, or marks it SKIPPED(reason).

Adding a new primitive pair:
Whenever a new skill file introduces a new `primitive` tag, decide whether
it combines with any EXISTING primitive to produce a higher-impact outcome
and add that pair to PRIMITIVE_PAIRS below, with a short pivot_name and a
one-sentence description of why the combination matters. This ruleset is
expected to grow as the skill catalog grows (Part 1) — it is not a one-time
list fixed at this pass.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CandidateChain:
    """One CANDIDATE_CHAIN event — a pivot worth investigating, not yet confirmed."""
    finding_a:   str   # identifying string (title) of the earlier finding
    finding_b:   str   # identifying string (title) of the triggering finding
    pivot_name:  str
    description: str


# (primitive_a, primitive_b) -> (pivot_name, human-readable rationale).
# Matching checks both orderings — the tuple's internal order doesn't matter.
PRIMITIVE_PAIRS: dict[tuple[str, str], tuple[str, str]] = {
    ("arbitrary_file_write", "local_file_inclusion"): (
        "webshell_rce",
        "Arbitrary file write can plant a webshell at a path the LFI primitive can include/execute.",
    ),
    ("ssrf", "cloud_metadata_exposed"): (
        "credential_theft",
        "SSRF can reach the cloud metadata endpoint to extract live IAM credentials.",
    ),
    ("ssrf", "internal_service_no_auth"): (
        "internal_pivot",
        "SSRF can reach an unauthenticated internal service directly.",
    ),
    ("sqli_read", "credential_reuse_suspected"): (
        "lateral_movement",
        "Credentials extracted via SQLi may be reused against another in-scope service.",
    ),
    ("lfi_read_only", "php_filter_wrapper_available"): (
        "filter_chain_rce",
        "A read-only LFI combined with PHP filter-chain wrapper availability can be escalated to RCE.",
    ),
    ("upload_bypass", "web_root_writable"): (
        "webshell_rce",
        "An upload-filter bypass combined with a writable web root allows planting an executable webshell.",
    ),
}


def _lookup(prim_a: str, prim_b: str) -> tuple[str, str] | None:
    return PRIMITIVE_PAIRS.get((prim_a, prim_b)) or PRIMITIVE_PAIRS.get((prim_b, prim_a))


def scan_new_finding(new_finding, prior_findings: list) -> list[CandidateChain]:
    """
    Check a newly CONFIRMED finding's primitive against every prior CONFIRMED
    finding's primitive. Returns zero or more CandidateChain events.

    Call this once per new finding, right after it's appended to the
    session's finding store (see agents/base_agent.py's run() loop and
    agents/pentest.py's _exploitation_loop for the wiring).
    """
    candidates: list[CandidateChain] = []
    new_prim = getattr(new_finding, "primitive", "") or ""
    if not new_prim:
        return candidates

    for prior in prior_findings:
        if prior is new_finding:
            continue
        prior_prim = getattr(prior, "primitive", "") or ""
        if not prior_prim:
            continue
        match = _lookup(new_prim, prior_prim)
        if not match:
            continue
        pivot_name, description = match
        candidates.append(CandidateChain(
            finding_a=getattr(prior, "title", str(prior)),
            finding_b=getattr(new_finding, "title", str(new_finding)),
            pivot_name=pivot_name,
            description=description,
        ))
    return candidates


# ── Worked example (LFI + arbitrary file write → webshell RCE) ─────────────
#
# finding_1 = Finding(title="Arbitrary File Write via Zip Slip", primitive="arbitrary_file_write", ...)
# finding_2 = Finding(title="Local File Inclusion in template param", primitive="local_file_inclusion", ...)
#
# After finding_2 is confirmed and appended:
#   scan_new_finding(finding_2, [finding_1])
#   -> [CandidateChain(
#        finding_a="Arbitrary File Write via Zip Slip",
#        finding_b="Local File Inclusion in template param",
#        pivot_name="webshell_rce",
#        description="Arbitrary file write can plant a webshell at a path the "
#                     "LFI primitive can include/execute.",
#      )]
#
# The agent's _resolve_candidate_chains then asks Opus whether planting a
# webshell at the LFI-includable path and triggering it actually achieves
# RCE in this specific engagement — if confirmed, it builds a
# finding_type="chain" Finding with chain_steps=[finding_1.title, finding_2.title]
# and chain_evidence={"final_impact": "rce", "final_poc": "<webshell trigger
# request>", "pivot_logic": "<why step 1 enables step 2>"}; if not, it marks
# the event SKIPPED(reason) via coverage_gate.report_chain_event().
