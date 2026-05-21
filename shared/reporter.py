from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from config import TEMPLATES_DIR

_jinja = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)
_jinja_raw = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=False)


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"


class Confidence(str, Enum):
    HIGH   = "High"
    MEDIUM = "Medium"
    LOW    = "Low"


SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH:     4,
    Severity.MEDIUM:   3,
    Severity.LOW:      2,
    Severity.INFO:     1,
}


@dataclass
class Finding:
    # Identity
    agent:       str
    title:       str
    severity:    Severity

    # Evidence — MANDATORY. No finding without direct tool output proof.
    evidence:    str          # raw tool output, request/response, code snippet
    observed:    str          # tool-confirmed facts only
    inferred:    str          # Claude's reasoning (displayed separately in report)

    # Classification
    cvss_score:  float        = 0.0
    cvss_vector: str          = ""
    cwe:         str          = ""        # e.g. "CWE-89"
    cve:         str          = ""        # e.g. "CVE-2021-44228"
    mitre_attack: list[str]   = field(default_factory=list)   # ["T1190"]
    mitre_atlas:  list[str]   = field(default_factory=list)   # ["AML.T0043"]
    owasp:        str         = ""        # "A03" or "LLM01"

    # Detail
    description:  str         = ""
    poc:          str         = ""        # curl command, Python script, steps
    impact:       str         = ""
    remediation:  str         = ""

    # Confidence & confirmation
    confidence:   Confidence  = Confidence.LOW
    confirmed:    bool        = False     # True only when 2+ tools confirm
    confirmed_by: list[str]   = field(default_factory=list)   # tool names that confirmed

    # Chain context
    chain_id:       Optional[str] = None  # links findings in an attack chain
    chain_position: int           = 0     # step N in the chain

    # Metadata
    target:      str          = ""
    url:         str          = ""
    parameter:   str          = ""
    created_at:  str          = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate(self) -> None:
        """Raises ValueError if finding is missing mandatory fields."""
        if not self.evidence.strip():
            raise ValueError(f"Finding '{self.title}' has no evidence. Tool output is mandatory.")
        if not self.title.strip():
            raise ValueError("Finding title is required.")
        if self.severity in (Severity.CRITICAL, Severity.HIGH) and len(self.confirmed_by) < 2:
            if self.confirmed:
                raise ValueError(
                    f"Finding '{self.title}' is {self.severity} but confirmed by only "
                    f"{len(self.confirmed_by)} tool(s). Requires 2+."
                )
            # Downgrade unconfirmed critical/high
            self.confidence = Confidence.LOW

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"]   = self.severity.value
        d["confidence"] = self.confidence.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d["severity"]   = Severity(d["severity"])
        d["confidence"] = Confidence(d["confidence"])
        return cls(**d)

    def __lt__(self, other: "Finding") -> bool:
        return SEVERITY_ORDER[self.severity] > SEVERITY_ORDER[other.severity]


class Reporter:
    """Renders a list of Finding objects into a structured report."""

    # ── Label map used by all render methods ──────────────────────────────
    _AGENT_LABELS: dict[str, str] = {
        "pentest":       "Penetration Test Report",
        "bug_bounty":    "Bug Bounty Report",
        "red_team":      "Red Team Assessment Report",
        "ai_redteam":    "AI Red Team Assessment Report",
        "voice_redteam": "Voice Red Team Assessment Report",
        "threat_model":  "Threat Model Report",
        "code_review":   "Secure Code Review Report",
    }

    def _enrich_meta(self, meta: dict, findings: list[Finding]) -> dict:
        """Add derived fields used by all templates."""
        m = dict(meta)
        agent = m.get("agent", "unknown")
        m.setdefault("agent_label", self._AGENT_LABELS.get(agent, agent.replace("_", " ").title()))
        m.setdefault("methodology", {
            "pentest":       "PTES · OWASP Testing Guide v4.2 · MITRE ATT&CK",
            "bug_bounty":    "OWASP Testing Guide v4.2 · HackerOne Severity Rating",
            "red_team":      "MITRE ATT&CK · PTES Red Team · CBEST",
            "ai_redteam":    "OWASP LLM Top 10 · MITRE ATLAS · NIST AI RMF",
            "voice_redteam": "OWASP Top 10 · NIST Voice AI · Acoustic Attack Framework",
            "threat_model":  "STRIDE · PASTA · MITRE ATT&CK · OWASP Threat Modeling",
            "code_review":   "OWASP Code Review Guide v2 · CWE Top 25 · NIST SSDF",
        }.get(agent, "PTES · OWASP · MITRE ATT&CK"))

        # Build MITRE TTP list from all findings
        ttps: list[str] = []
        for f in findings:
            for t in (f.mitre_attack or []):
                if t not in ttps:
                    ttps.append(t)
        m["mitre_ttps"] = ttps
        m.setdefault("sections", [])
        return m

    def render_markdown(self, findings: list[Finding], meta: dict) -> str:
        """Render findings to Markdown — falls back to built-in if no agent template."""
        findings = sorted(findings)
        agent = meta.get("agent", "unknown")
        try:
            tmpl = _jinja_raw.get_template(f"{agent}_report.md.j2")
            return tmpl.render(findings=findings, findings_sorted=findings, meta=self._enrich_meta(meta, findings))
        except Exception:
            return self._builtin_markdown(findings, meta)

    def _builtin_markdown(self, findings: list[Finding], meta: dict) -> str:
        lines = [
            f"# ARGUS Report — {meta.get('agent', '').replace('_', ' ').title()}",
            f"\n**Target:** {meta.get('target', 'N/A')}",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Operator:** {meta.get('operator', 'N/A')}",
            f"\n---\n",
            f"## Summary\n",
            f"| Severity | Count |",
            f"|---|---|",
        ]
        for sev in Severity:
            count = sum(1 for f in findings if f.severity == sev)
            if count:
                lines.append(f"| {sev.value} | {count} |")

        lines.append("\n---\n## Findings\n")
        for i, f in enumerate(findings, 1):
            lines += [
                f"### {i}. {f.title}",
                f"**Severity:** {f.severity.value} | **CVSS:** {f.cvss_score} | **Confidence:** {f.confidence.value}",
                f"**CWE:** {f.cwe or 'N/A'} | **CVE:** {f.cve or 'N/A'} | **OWASP:** {f.owasp or 'N/A'}",
                f"\n**Description:**\n{f.description}",
                f"\n**Observed (tool-confirmed):**\n```\n{f.observed}\n```",
                f"\n**Evidence:**\n```\n{f.evidence}\n```",
                f"\n**PoC:**\n```\n{f.poc}\n```" if f.poc else "",
                f"\n**Impact:**\n{f.impact}",
                f"\n**Remediation:**\n{f.remediation}",
                "\n---\n",
            ]
        return "\n".join(lines)

    def render_html(self, findings: list[Finding], meta: dict) -> str:
        """Render professional HTML report (HackerOne/OSCP/OSWE style)."""
        findings_sorted = sorted(findings)
        enriched = self._enrich_meta(meta, findings_sorted)
        try:
            tmpl = _jinja.get_template("report.html.j2")
            return tmpl.render(
                findings=findings_sorted,
                findings_sorted=findings_sorted,
                meta=enriched,
            )
        except Exception as e:
            # Minimal fallback so we never return empty
            return (
                f"<html><body><h1>Report Error</h1><pre>{e}</pre>"
                f"<p>Findings: {len(findings_sorted)}</p></body></html>"
            )

    def render_pdf(self, findings: list[Finding], meta: dict, output_path: Path) -> bool:
        """
        Render HTML report and convert to PDF.
        Tries: (1) Chromium headless  (2) WeasyPrint  (3) fail gracefully.
        Returns True on success.
        """
        import shutil, subprocess, tempfile

        html_content = self.render_html(findings, meta)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Strategy 1 — Chromium headless (preferred; works on Kali/Debian)
        chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
        if chromium:
            try:
                with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as fh:
                    fh.write(html_content)
                    tmp_html = fh.name
                result = subprocess.run(
                    [
                        chromium, "--headless", "--no-sandbox",
                        "--disable-gpu", "--disable-dev-shm-usage",
                        f"--print-to-pdf={output_path}",
                        tmp_html,
                    ],
                    capture_output=True, timeout=60,
                )
                Path(tmp_html).unlink(missing_ok=True)
                if output_path.exists() and output_path.stat().st_size > 0:
                    return True
            except Exception:
                pass

        # Strategy 2 — WeasyPrint fallback
        try:
            from weasyprint import HTML  # type: ignore
            HTML(string=html_content).write_pdf(str(output_path))
            return output_path.exists()
        except Exception:
            return False

    def render_json(self, findings: list[Finding], meta: dict) -> str:
        return json.dumps({
            "meta": self._enrich_meta(meta, findings),
            "findings": [f.to_dict() for f in sorted(findings)],
        }, indent=2)

    def save(self, content: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


reporter = Reporter()
