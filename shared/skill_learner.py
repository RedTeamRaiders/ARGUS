"""
skill_learner.py — Persistent technique learning for ARGUS agents.

When an agent confirms a finding, it logs the technique here.
Future agent runs load this file to inform their strategy.

One common file: skills/LEARNED_TECHNIQUES.md
All agents read from and write to it.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import SKILLS_DIR

TECHNIQUES_FILE = SKILLS_DIR / "LEARNED_TECHNIQUES.md"
_write_lock = threading.Lock()

CATEGORY_MAP = {
    "sqli":      "SQL Injection",
    "nosqli":    "NoSQL Injection",
    "xss":       "Cross-Site Scripting",
    "xxe":       "XML External Entity",
    "ssrf":      "Server-Side Request Forgery",
    "ssti":      "Server-Side Template Injection",
    "jwt":       "JWT Attack",
    "idor":      "Broken Access Control / IDOR",
    "lfi":       "Local File Inclusion / Path Traversal",
    "rce":       "Remote Code Execution",
    "race":      "Race Condition / TOCTOU",
    "csrf":      "Cross-Site Request Forgery",
    "auth":      "Authentication Bypass",
    "crypto":    "Cryptographic Weakness",
    "redirect":  "Open Redirect",
    "upload":    "File Upload Vulnerability",
    "dos":       "Denial of Service",
    "info":      "Information Disclosure",
    "logic":     "Business Logic",
    "config":          "Security Misconfiguration",
    "prompt_injection": "LLM Prompt Injection",
    "rag_attack":       "RAG / Vector DB Attack",
    "jailbreak":        "LLM Jailbreak",
    "guardrail_bypass": "Guardrail Bypass",
    "context_override": "Context Override",
    "other":            "Other",
}


@dataclass
class TechniqueEntry:
    """One learned technique from a successful exploitation."""
    technique:       str            # Short name, e.g. "sanitize-html 1.4.2 bypass"
    category:        str            # Key from CATEGORY_MAP, e.g. "xss"
    target_pattern:  str            # What kind of target this works on
    conditions:      str            # When/why this applies
    approach:        str            # Step-by-step — what the agent did
    payload:         str            # Key payload or code snippet
    evidence:        str            # What success looked like (response, flag, etc.)
    agent:           str            # Which agent found this
    source:          str = "engagement"  # "juiceshop", "htb", "engagement", etc.
    severity:        str = "Medium"
    tags:            list[str] = field(default_factory=list)
    timestamp:       str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.category = self.category.lower()

    def to_markdown(self) -> str:
        tag_str = " ".join(f"`{t}`" for t in self.tags) if self.tags else ""
        cat_label = CATEGORY_MAP.get(self.category, self.category.upper())
        return (
            f"\n---\n\n"
            f"## [{self.timestamp}] {self.technique}\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| **Category** | {cat_label} |\n"
            f"| **Agent** | `{self.agent}` |\n"
            f"| **Severity** | {self.severity} |\n"
            f"| **Source** | {self.source} |\n"
            f"| **Tags** | {tag_str} |\n\n"
            f"**Target Pattern:** {self.target_pattern}\n\n"
            f"**Conditions:** {self.conditions}\n\n"
            f"**Approach:**\n{self.approach}\n\n"
            f"**Payload / Key Code:**\n```\n{self.payload}\n```\n\n"
            f"**Evidence of Success:**\n```\n{self.evidence}\n```\n"
        )


def _ensure_file() -> None:
    if not TECHNIQUES_FILE.exists():
        TECHNIQUES_FILE.parent.mkdir(parents=True, exist_ok=True)
        TECHNIQUES_FILE.write_text(
            "# ARGUS Learned Techniques\n\n"
            "> Auto-generated. Agents append here when they confirm a finding.\n"
            "> Loaded at agent startup to inform strategy and technique selection.\n\n"
            "<!-- entries below -->\n"
        )


def log_technique(entry: TechniqueEntry) -> None:
    """Append a confirmed technique to the shared learning log. Thread-safe."""
    _ensure_file()
    with _write_lock:
        with TECHNIQUES_FILE.open("a") as f:
            f.write(entry.to_markdown())


def load_techniques(
    category: Optional[str] = None,
    limit: int = 50,
) -> str:
    """
    Return the learned techniques as a markdown string for inclusion in agent context.
    Optionally filter by category. Returns at most `limit` entries (most recent first).
    """
    _ensure_file()
    text = TECHNIQUES_FILE.read_text()

    # Split on the entry separator
    parts = re.split(r"\n---\n", text)
    # First part is the header — skip it
    entries = [p.strip() for p in parts[1:] if p.strip()]

    if category:
        cat_label = CATEGORY_MAP.get(category.lower(), category)
        entries = [e for e in entries if cat_label in e or category.lower() in e.lower()]

    # Most recent first
    entries = entries[-limit:][::-1]

    if not entries:
        return ""

    return (
        "## Learned Techniques (from previous engagements)\n\n"
        + "\n\n---\n\n".join(entries)
        + "\n"
    )


def technique_from_finding(
    finding,          # shared.reporter.Finding
    agent_name: str,
    approach: str,
    payload: str,
    source: str = "engagement",
) -> TechniqueEntry:
    """
    Build a TechniqueEntry from a confirmed Finding.
    Call this after a finding passes validate() in the ReAct loop.
    """
    # Map OWASP category to our internal category key
    owasp_to_category = {
        "A01": "idor", "A02": "crypto", "A03": "sqli",
        "A04": "config", "A05": "config", "A06": "config",
        "A07": "auth", "A08": "logic", "A09": "info",
        "A10": "ssrf",
    }
    category = owasp_to_category.get(getattr(finding, "owasp", ""), "other")

    # Also guess from title
    title_lower = finding.title.lower()
    for key in CATEGORY_MAP:
        if key in title_lower:
            category = key
            break

    tags = []
    if hasattr(finding, "mitre_attack") and finding.mitre_attack:
        tags.extend(finding.mitre_attack[:3])
    if hasattr(finding, "cwe") and finding.cwe:
        tags.append(finding.cwe)

    return TechniqueEntry(
        technique=finding.title,
        category=category,
        target_pattern=f"Discovered on {agent_name} engagement",
        conditions=getattr(finding, "observed", ""),
        approach=approach,
        payload=payload,
        evidence=finding.evidence[:800] if finding.evidence else "",
        agent=agent_name,
        source=source,
        severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        tags=tags,
    )
