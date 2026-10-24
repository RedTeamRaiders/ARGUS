"""
shared/manifests/owasp_top10.py — OWASP Top 10 (2021) manifest for coverage_gate.py.

All taxonomy-specific knowledge lives here, never in coverage_gate.py itself.
Whitebox eligibility is gated on whether a codebase_path was provided for
the engagement — a category's "whitebox" mode is dropped from the
applicable set if there's no code to review, but the category itself stays
on the manifest so a blackbox-only run still owes it a status.
"""
from __future__ import annotations

from shared.coverage_gate import CategoryRecord

OWASP_TOP10_CATEGORIES: list[CategoryRecord] = [
    CategoryRecord("A01:2021", ["blackbox", "whitebox"]),  # Broken Access Control
    CategoryRecord("A02:2021", ["blackbox", "whitebox"]),  # Cryptographic Failures
    CategoryRecord("A03:2021", ["blackbox", "whitebox"]),  # Injection
    CategoryRecord("A04:2021", ["blackbox", "whitebox"]),  # Insecure Design
    CategoryRecord("A05:2021", ["blackbox", "whitebox"]),  # Security Misconfiguration
    CategoryRecord("A06:2021", ["blackbox", "whitebox"]),  # Vulnerable and Outdated Components
    CategoryRecord("A07:2021", ["blackbox", "whitebox"]),  # Identification and Authentication Failures
    CategoryRecord("A08:2021", ["blackbox", "whitebox"]),  # Software and Data Integrity Failures
    CategoryRecord("A09:2021", ["blackbox", "whitebox"]),  # Security Logging and Monitoring Failures
    CategoryRecord("A10:2021", ["blackbox", "whitebox"]),  # Server-Side Request Forgery
]

# A03 Injection splits further by vuln class for skill selection — the gate
# itself only tracks the parent category, but base_agent.py uses this map
# to pick which skill files are candidates once A03 is in focus.
A03_VULN_CLASSES = [
    "sqli", "xss_reflected", "xss_stored", "xss_dom",
    "command_injection", "ssti", "nosqli",
]


def build_manifest(codebase_path: str = "") -> list[CategoryRecord]:
    """
    Build the OWASP Top 10 manifest for one engagement.

    whitebox mode only applies if a codebase_path was actually provided —
    this trims "whitebox" out of applicable_modes rather than dropping the
    category, so a blackbox-only run still owes CONFIRMED/TESTED_CLEAN/SKIPPED
    for every category, just not in whitebox mode.
    """
    manifest = []
    for cat in OWASP_TOP10_CATEGORIES:
        modes = list(cat.applicable_modes)
        if "whitebox" in modes and not codebase_path:
            modes.remove("whitebox")
        manifest.append(CategoryRecord(cat.category_id, modes))
    return manifest
