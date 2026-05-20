"""
Code Review Agent — SAST + Semantic + CWE Mapping

Flow:
  Inputs → Attack Surface Map → Auto-scan (semgrep + bandit + trufflehog)
  → Semantic Analysis (Opus) → False-positive triage (Haiku)
  → Dependency CVE check → Chain analysis → Report
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import anthropic

from agents.base_agent import BaseAgent
from config import (
    ANTHROPIC_API_KEY, DATA_DIR, MODEL_DEEP, MODEL_PARSE, MODEL_REASON,
    PROMPTS_DIR, SKILLS_DIR,
)
from shared.auth_gate import AuthRecord
from shared.logger import audit
from shared.reporter import Confidence, Finding, Severity, reporter
from shared.session import Scope, Session

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


@dataclass
class CodeFinding:
    id:           str
    file_path:    str
    line_number:  int
    code_snippet: str
    vuln_class:   str
    cwe:          str
    title:        str
    description:  str
    attack_scenario: str
    poc:          str
    impact:       str
    remediation:  str
    severity:     str
    confidence:   str
    mitre_ttps:   list[str] = field(default_factory=list)
    owasp:        str = ""
    is_false_positive: bool = False
    fp_reason:    str = ""
    confirmed_by: list[str] = field(default_factory=list)
    chain_id:     Optional[str] = None

    def to_finding(self, agent: str, target: str) -> Finding:
        return Finding(
            agent       = agent,
            title       = self.title,
            severity    = Severity(self.severity),
            evidence    = f"File: {self.file_path}:{self.line_number}\n```\n{self.code_snippet}\n```",
            observed    = f"CWE: {self.cwe} | Class: {self.vuln_class} | File: {self.file_path}:{self.line_number}",
            inferred    = self.description,
            cvss_score  = self._severity_to_score(),
            cwe         = self.cwe,
            mitre_attack= self.mitre_ttps,
            owasp       = self.owasp,
            description = self.description,
            poc         = self.poc,
            impact      = self.impact,
            remediation = self.remediation,
            confidence  = Confidence(self.confidence),
            confirmed   = self.confidence == "HIGH",
            confirmed_by= self.confirmed_by,
            target      = target,
            chain_id    = self.chain_id,
        )

    def _severity_to_score(self) -> float:
        return {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Info": 1.0}.get(self.severity, 5.0)


class CodeReviewAgent(BaseAgent):
    name        = "code_review"
    description = "Secure code review: SAST + semantic analysis + CWE mapping"

    def __init__(self) -> None:
        super().__init__()

    async def run(
        self,
        target:    str,
        scope:     Scope,
        auth:      AuthRecord,
        session:   Session,
        code_path: str = "",
        language:  str = "",
        framework: str = "",
    ) -> list[Finding]:
        audit.info(self.name, f"Starting code review | target={target} | path={code_path} | lang={language}")

        if not code_path:
            code_path = target

        # Phase 1 — Attack surface mapping
        audit.info(self.name, "Phase 1: Attack surface mapping")
        surface = await self._map_attack_surface(code_path, language, framework)

        # Phase 2 — Automated scanning
        audit.info(self.name, "Phase 2: Automated scanning (semgrep + bandit + trufflehog)")
        auto_results = await self._run_auto_scan(code_path, language)

        # Phase 3 — Semantic analysis of auto-tool results + manual deep analysis
        audit.info(self.name, "Phase 3: Semantic analysis (Opus)")
        semantic_findings = await self._semantic_analysis(code_path, surface, auto_results, language, framework)

        # Phase 4 — False positive triage
        audit.info(self.name, "Phase 4: False positive triage (Haiku)")
        validated = await self._triage_findings(semantic_findings, code_path)

        # Phase 5 — Dependency CVE check
        audit.info(self.name, "Phase 5: Dependency CVE analysis")
        dep_findings = await self._check_dependencies(code_path, language)
        validated.extend(dep_findings)

        # Phase 6 — Chain analysis (can findings combine for higher impact?)
        audit.info(self.name, "Phase 6: Vulnerability chain analysis")
        validated = await self._analyze_chains(validated)

        # Convert to Finding objects and validate
        findings = []
        for cf in validated:
            if cf.is_false_positive:
                audit.info(self.name, f"Skipping FP: {cf.title} — {cf.fp_reason}")
                continue
            finding = cf.to_finding(self.name, target)
            try:
                finding.validate()
                findings.append(finding)
                await session.add_finding(finding.to_dict())
                audit.finding(
                    self.name, finding.title, finding.severity.value,
                    finding.cvss_score, finding.confirmed, finding.confidence.value,
                )
            except ValueError as e:
                audit.error(self.name, f"Finding rejected: {e}")

        await session.set_context("code_review_result", {
            "language":        language,
            "framework":       framework,
            "total_findings":  len(findings),
            "false_positives": sum(1 for cf in validated if cf.is_false_positive),
            "surface":         surface,
        })
        await session.close()

        audit.info(self.name, f"Code review complete | findings={len(findings)}")
        return findings

    async def _map_attack_surface(self, code_path: str, language: str, framework: str) -> dict:
        resp = client.messages.create(
            model=MODEL_REASON,
            max_tokens=2048,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Code Path\n{code_path}\n\n"
                    f"## Language\n{language or 'Unknown'}\n\n"
                    f"## Framework\n{framework or 'Unknown'}\n\n"
                    f"## Skill Reference\n{self._skill[:2000]}\n\n"
                    "Map the attack surface for this codebase. Identify all entry points, sinks, "
                    "and high-value targets for security review.\n\n"
                    "Return JSON:\n"
                    "{\n"
                    '  "entry_points": [{"name": "", "type": "http|cli|file|ipc", "location": ""}],\n'
                    '  "sinks": [{"type": "sql|shell|html|file|ssrf|crypto|deser", "location": ""}],\n'
                    '  "auth_mechanism": "",\n'
                    '  "data_sensitivity": "high|medium|low",\n'
                    '  "crown_jewels": [],\n'
                    '  "high_risk_files": []\n'
                    "}"
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_REASON, "attack_surface",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        return self._parse_json(resp.content[0].text)

    async def _run_auto_scan(self, code_path: str, language: str) -> dict:
        results = {"semgrep": [], "bandit": [], "trufflehog": []}
        try:
            import tool_wrappers.semgrep as semgrep_wrapper
            results["semgrep"] = await semgrep_wrapper.run(code_path)
        except Exception as e:
            audit.error(self.name, f"Semgrep failed: {e}")

        if language.lower() in ("python", ""):
            try:
                import tool_wrappers.bandit as bandit_wrapper
                results["bandit"] = await bandit_wrapper.run(code_path)
            except Exception as e:
                audit.error(self.name, f"Bandit failed: {e}")

        try:
            import tool_wrappers.trufflehog as trufflehog_wrapper
            results["trufflehog"] = await trufflehog_wrapper.run(code_path)
        except Exception as e:
            audit.error(self.name, f"TruffleHog failed: {e}")

        return results

    async def _semantic_analysis(
        self,
        code_path: str,
        surface: dict,
        auto_results: dict,
        language: str,
        framework: str,
    ) -> list[CodeFinding]:
        # Summarize auto-scan results for Opus context
        auto_summary = {
            "semgrep_count":    len(auto_results.get("semgrep", [])),
            "bandit_count":     len(auto_results.get("bandit", [])),
            "trufflehog_count": len(auto_results.get("trufflehog", [])),
            "semgrep_top":      auto_results.get("semgrep", [])[:10],
            "bandit_top":       auto_results.get("bandit", [])[:10],
            "secrets_found":    len(auto_results.get("trufflehog", [])) > 0,
        }

        resp = client.messages.create(
            model=MODEL_DEEP,
            max_tokens=8192,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Code Path\n{code_path}\n\n"
                    f"## Language: {language or 'Unknown'} | Framework: {framework or 'Unknown'}\n\n"
                    f"## Attack Surface\n{json.dumps(surface, indent=2)}\n\n"
                    f"## Auto-scan Results\n{json.dumps(auto_summary, indent=2)}\n\n"
                    f"## Review Methodology\n{self._skill[:4000]}\n\n"
                    "Perform deep semantic security analysis. Go beyond what automated tools found. "
                    "Focus on: data flow tracing, business logic flaws, auth bypasses, "
                    "vulnerability chains, and false positive validation of auto-tool results.\n\n"
                    "Return a JSON array of findings:\n"
                    "[\n"
                    "  {\n"
                    '    "id": "CR001",\n'
                    '    "file_path": "src/auth.py",\n'
                    '    "line_number": 42,\n'
                    '    "code_snippet": "exact code from that line",\n'
                    '    "vuln_class": "SQLi|XSS|SSRF|RCE|AuthBypass|IDOR|...",\n'
                    '    "cwe": "CWE-89",\n'
                    '    "title": "SQL Injection in user login",\n'
                    '    "description": "detailed technical description",\n'
                    '    "attack_scenario": "step by step how attacker exploits this",\n'
                    '    "poc": "specific payload or request",\n'
                    '    "impact": "what attacker gains",\n'
                    '    "remediation": "specific code fix",\n'
                    '    "severity": "Critical|High|Medium|Low|Info",\n'
                    '    "confidence": "HIGH|MEDIUM|LOW",\n'
                    '    "mitre_ttps": ["T1190"],\n'
                    '    "owasp": "A03",\n'
                    '    "confirmed_by": ["semgrep", "manual_analysis"],\n'
                    '    "chain_id": null\n'
                    "  }\n"
                    "]"
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_DEEP, "semantic_analysis",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        findings_data = self._parse_json(resp.content[0].text)
        if not isinstance(findings_data, list):
            findings_data = findings_data.get("findings", [])
        return [self._dict_to_finding(f) for f in findings_data]

    async def _triage_findings(self, findings: list[CodeFinding], code_path: str) -> list[CodeFinding]:
        if not findings:
            return findings

        findings_summary = [
            {
                "id": f.id,
                "title": f.title,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet[:200],
                "vuln_class": f.vuln_class,
                "confidence": f.confidence,
            }
            for f in findings
        ]

        resp = client.messages.create(
            model=MODEL_PARSE,
            max_tokens=3000,
            system="You are a code security triage tool. Identify false positives in a list of security findings.",
            messages=[{
                "role": "user",
                "content": (
                    f"## Findings to Triage\n{json.dumps(findings_summary, indent=2)}\n\n"
                    "For each finding, determine if it is a false positive.\n"
                    "Common FP patterns: test fixtures, documentation examples, placeholder values, "
                    "dead code that can't be reached, sanitization code that handles the issue.\n\n"
                    "Return JSON array:\n"
                    '[\n  {"id": "CR001", "is_fp": false, "reason": ""}\n]'
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_PARSE, "fp_triage",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        triage = self._parse_json(resp.content[0].text)
        if not isinstance(triage, list):
            return findings

        triage_map = {item["id"]: item for item in triage if isinstance(item, dict)}
        for f in findings:
            if f.id in triage_map and triage_map[f.id].get("is_fp"):
                f.is_false_positive = True
                f.fp_reason = triage_map[f.id].get("reason", "")

        return findings

    async def _check_dependencies(self, code_path: str, language: str) -> list[CodeFinding]:
        # Collect dependency files
        dep_files = []
        for pattern in ("requirements.txt", "package.json", "pom.xml", "go.mod", "Gemfile.lock", "composer.lock"):
            matches = list(Path(code_path).rglob(pattern)) if Path(code_path).is_dir() else []
            dep_files.extend(str(m) for m in matches[:2])

        if not dep_files:
            return []

        deps_content = {}
        for dep_file in dep_files:
            try:
                deps_content[dep_file] = Path(dep_file).read_text()[:3000]
            except Exception:
                pass

        if not deps_content:
            return []

        resp = client.messages.create(
            model=MODEL_REASON,
            max_tokens=2048,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Dependency Files\n{json.dumps(deps_content, indent=2)}\n\n"
                    "Identify outdated or vulnerable dependencies. Focus on packages with known CVEs "
                    "or significantly outdated versions that typically have security fixes.\n\n"
                    "Return JSON array with same structure as code findings, "
                    "vuln_class='VulnerableDependency', code_snippet=package version line:\n"
                    '[\n  {"id": "DEP001", "file_path": "", "line_number": 0, ...}\n]'
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_REASON, "dependency_check",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        dep_data = self._parse_json(resp.content[0].text)
        if not isinstance(dep_data, list):
            return []
        return [self._dict_to_finding(f) for f in dep_data]

    async def _analyze_chains(self, findings: list[CodeFinding]) -> list[CodeFinding]:
        if len(findings) < 2:
            return findings

        med_and_above = [f for f in findings if f.severity in ("Critical", "High", "Medium") and not f.is_false_positive]
        if len(med_and_above) < 2:
            return findings

        summaries = [{"id": f.id, "title": f.title, "vuln_class": f.vuln_class, "severity": f.severity} for f in med_and_above[:15]]

        resp = client.messages.create(
            model=MODEL_REASON,
            max_tokens=1500,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Findings\n{json.dumps(summaries, indent=2)}\n\n"
                    "Identify any vulnerability chains where combining 2+ findings creates higher impact "
                    "(e.g., SSRF + IDOR = internal data exfiltration, XSS + CSRF bypass = account takeover).\n\n"
                    "Return JSON array of chains:\n"
                    '[\n  {"chain_id": "CHAIN-01", "finding_ids": ["CR001", "CR003"], "combined_severity": "Critical", "chain_description": ""}\n]'
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_REASON, "chain_analysis",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        chains = self._parse_json(resp.content[0].text)
        if not isinstance(chains, list):
            return findings

        # Apply chain IDs and potentially upgrade severity
        for chain in chains:
            chain_id = chain.get("chain_id", "")
            combined_sev = chain.get("combined_severity", "")
            for fid in chain.get("finding_ids", []):
                for f in findings:
                    if f.id == fid:
                        f.chain_id = chain_id
                        if combined_sev in ("Critical", "High") and f.severity in ("Medium", "Low"):
                            f.severity = combined_sev
        return findings

    def _dict_to_finding(self, d: dict) -> CodeFinding:
        return CodeFinding(
            id              = d.get("id", "CR000"),
            file_path       = d.get("file_path", "unknown"),
            line_number     = int(d.get("line_number", 0)),
            code_snippet    = d.get("code_snippet", ""),
            vuln_class      = d.get("vuln_class", "Unknown"),
            cwe             = d.get("cwe", ""),
            title           = d.get("title", "Untitled"),
            description     = d.get("description", ""),
            attack_scenario = d.get("attack_scenario", ""),
            poc             = d.get("poc", ""),
            impact          = d.get("impact", ""),
            remediation     = d.get("remediation", ""),
            severity        = d.get("severity", "Medium"),
            confidence      = d.get("confidence", "MEDIUM"),
            mitre_ttps      = d.get("mitre_ttps", []),
            owasp           = d.get("owasp", ""),
            confirmed_by    = d.get("confirmed_by", []),
            chain_id        = d.get("chain_id"),
        )

    def _parse_json(self, text: str) -> dict | list:
        import re
        text = text.strip()
        if text.startswith("```"):
            parts = text.split("```")
            text = parts[1] if len(parts) > 1 else text
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            m = re.search(r'(\{.*\}|\[.*\])', text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    pass
            return {}
