"""
Threat Model Agent — STRIDE + PASTA + DREAD + AI/ATLAS

Unlike active agents, this agent is analytical — it takes a system description
as input and reasons through it systematically. No external tool calls needed
for basic threat modeling; CVE and OSINT lookups are optional enrichment.

Flow:
  Input → Asset Identification → Trust Boundary Mapping → STRIDE Analysis
  → Attack Trees → AI Threats (if applicable) → DREAD Scoring → Report
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import anthropic

from agents.base_agent import BaseAgent
from config import (
    ANTHROPIC_API_KEY, DATA_DIR, MODEL_DEEP, MODEL_REASON,
    PROMPTS_DIR, SKILLS_DIR,
)
from shared.auth_gate import AuthRecord
from shared.logger import audit
from shared.reporter import Confidence, Finding, Severity, reporter
from shared.session import Scope, Session

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


@dataclass
class Threat:
    id:           str
    component:    str
    stride_cat:   str           # S/T/R/I/D/E
    title:        str
    description:  str
    attack_path:  str
    impact:       str
    mitre_ttps:   list[str]
    owasp:        str
    dread_scores: dict[str, int]
    controls:     list[str]
    is_ai_threat: bool = False

    @property
    def dread_total(self) -> float:
        return sum(self.dread_scores.values()) / len(self.dread_scores) if self.dread_scores else 0.0

    @property
    def severity(self) -> str:
        score = self.dread_total
        if score >= 8: return "Critical"
        if score >= 6: return "High"
        if score >= 4: return "Medium"
        return "Low"

    def to_finding(self, agent: str, target: str) -> Finding:
        return Finding(
            agent       = agent,
            title       = self.title,
            severity    = Severity(self.severity),
            evidence    = f"Threat identified via STRIDE analysis of component: {self.component}",
            observed    = f"Component: {self.component} | Category: {self.stride_cat} | Attack Path: {self.attack_path}",
            inferred    = self.description,
            cvss_score  = round(self.dread_total, 1),
            cwe         = "",
            mitre_attack= self.mitre_ttps,
            owasp       = self.owasp,
            description = self.description,
            impact      = self.impact,
            remediation = " | ".join(self.controls),
            confidence  = Confidence.HIGH,
            confirmed   = True,
            confirmed_by= ["stride_analysis", "attack_tree"],
            target      = target,
        )


@dataclass
class ThreatModelResult:
    target:        str
    system_type:   str
    has_ai:        bool
    assets:        list[dict]
    trust_boundaries: list[dict]
    threats:       list[Threat]
    attack_trees:  list[dict]
    ai_threats:    list[dict]
    recommendations: list[str]


class ThreatModelAgent(BaseAgent):
    name        = "threat_model"
    description = "Threat modeling: STRIDE + PASTA + AI threats + MITRE ATLAS"

    def __init__(self) -> None:
        super().__init__()
        self._mitre_attack  = json.loads((DATA_DIR / "mitre_attack.json").read_text())
        self._mitre_atlas   = json.loads((DATA_DIR / "mitre_atlas.json").read_text())
        self._owasp_llm     = json.loads((DATA_DIR / "owasp_llm_top10.json").read_text())
        self._ai_skill      = (SKILLS_DIR / "threat_model_ai" / "SKILL.md").read_text()

    async def run(
        self,
        target:  str,
        scope:   Scope,
        auth:    AuthRecord,
        session: Session,
        system_description: str = "",
        has_ai: bool = False,
    ) -> list[Finding]:
        audit.info(self.name, f"Starting threat model | target={target} | has_ai={has_ai}")

        if not system_description:
            system_description = target

        result = await self._analyze_system(system_description, target, has_ai)

        findings = []
        for threat in result.threats:
            finding = threat.to_finding(self.name, target)
            try:
                finding.validate()
                findings.append(finding)
                await session.add_finding(finding.to_dict())
                audit.finding(
                    self.name, finding.title, finding.severity.value,
                    finding.cvss_score, finding.confirmed, finding.confidence.value,
                )
            except ValueError as e:
                audit.error(self.name, f"Threat finding rejected: {e}")

        # Persist context
        await session.set_context("threat_model_result", {
            "system_type":  result.system_type,
            "has_ai":       result.has_ai,
            "assets":       result.assets,
            "trust_boundaries": result.trust_boundaries,
            "threat_count": len(result.threats),
            "ai_threat_count": len(result.ai_threats),
        })
        await session.close()

        audit.info(self.name, f"Threat model complete | threats={len(result.threats)} | ai_threats={len(result.ai_threats)}")
        return findings

    async def _analyze_system(
        self, description: str, target: str, has_ai: bool
    ) -> ThreatModelResult:
        # Phase 1 — Asset identification + trust boundary mapping
        audit.info(self.name, "Phase 1: Asset and trust boundary identification")
        assets_and_boundaries = await self._identify_assets(description)

        # Phase 2 — STRIDE analysis (Opus for depth)
        audit.info(self.name, "Phase 2: STRIDE analysis")
        threats = await self._run_stride(description, assets_and_boundaries)

        # Phase 3 — Attack trees for top threats
        audit.info(self.name, "Phase 3: Attack tree generation")
        attack_trees = await self._build_attack_trees(threats[:5], description)

        # Phase 4 — AI threat analysis (if applicable)
        ai_threats = []
        if has_ai:
            audit.info(self.name, "Phase 4: AI-specific threat analysis (ATLAS + LLM Top 10)")
            ai_threats = await self._analyze_ai_threats(description)
            threats += [self._ai_threat_to_threat(t) for t in ai_threats]

        # Phase 5 — DREAD scoring
        audit.info(self.name, "Phase 5: DREAD scoring and prioritization")
        threats = await self._score_threats(threats, description)

        # Phase 6 — Recommendations
        recommendations = await self._generate_recommendations(threats, has_ai)

        return ThreatModelResult(
            target=target,
            system_type=assets_and_boundaries.get("system_type", "Unknown"),
            has_ai=has_ai,
            assets=assets_and_boundaries.get("assets", []),
            trust_boundaries=assets_and_boundaries.get("trust_boundaries", []),
            threats=sorted(threats, key=lambda t: t.dread_total, reverse=True),
            attack_trees=attack_trees,
            ai_threats=ai_threats,
            recommendations=recommendations,
        )

    async def _identify_assets(self, description: str) -> dict:
        resp = client.messages.create(
            model=MODEL_REASON,
            max_tokens=2048,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## System Description\n{description}\n\n"
                    "Identify all assets and trust boundaries in this system.\n\n"
                    "Return JSON:\n"
                    "{\n"
                    '  "system_type": "web|api|mobile|desktop|cloud|hybrid|ai",\n'
                    '  "assets": [\n'
                    '    {"name": "", "type": "data|service|infrastructure", "sensitivity": "high|medium|low", "description": ""}\n'
                    "  ],\n"
                    '  "trust_boundaries": [\n'
                    '    {"from": "", "to": "", "data_flows": [], "controls": []}\n'
                    "  ],\n"
                    '  "user_roles": [],\n'
                    '  "crown_jewels": []\n'
                    "}"
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_REASON, "asset_identification",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        return self._parse_json(resp.content[0].text)

    async def _run_stride(self, description: str, context: dict) -> list[Threat]:
        resp = client.messages.create(
            model=MODEL_DEEP,
            max_tokens=8192,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## System Description\n{description}\n\n"
                    f"## Assets & Boundaries\n{json.dumps(context, indent=2)}\n\n"
                    f"## STRIDE Methodology\n{self._skill[:3000]}\n\n"
                    "Perform a thorough STRIDE analysis. For each component and trust boundary, "
                    "identify threats across all 6 STRIDE categories.\n\n"
                    "Return a JSON array of threats:\n"
                    "[\n"
                    "  {\n"
                    '    "id": "T001",\n'
                    '    "component": "component name",\n'
                    '    "stride_cat": "S|T|R|I|D|E",\n'
                    '    "title": "short threat title",\n'
                    '    "description": "detailed description",\n'
                    '    "attack_path": "step 1 → step 2 → step 3",\n'
                    '    "impact": "business and technical impact",\n'
                    '    "mitre_ttps": ["T1190", "T1078"],\n'
                    '    "owasp": "A01",\n'
                    '    "dread_scores": {"damage": 8, "reproducibility": 7, "exploitability": 6, "affected_users": 9, "discoverability": 5},\n'
                    '    "controls": ["control 1", "control 2"],\n'
                    '    "is_ai_threat": false\n'
                    "  }\n"
                    "]"
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_DEEP, "stride_analysis",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        threats_data = self._parse_json(resp.content[0].text)
        if not isinstance(threats_data, list):
            threats_data = threats_data.get("threats", [])
        return [self._dict_to_threat(t) for t in threats_data]

    async def _build_attack_trees(self, threats: list[Threat], description: str) -> list[dict]:
        if not threats:
            return []
        threat_summaries = [{"id": t.id, "title": t.title, "attack_path": t.attack_path} for t in threats]
        resp = client.messages.create(
            model=MODEL_REASON,
            max_tokens=3000,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Top Threats\n{json.dumps(threat_summaries, indent=2)}\n\n"
                    "Build attack trees for these threats. Show prerequisites and alternative paths.\n\n"
                    "Return JSON array:\n"
                    '[\n  {"threat_id": "T001", "goal": "...", "root": {"node": "...", "children": []}}\n]'
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_REASON, "attack_trees",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        result = self._parse_json(resp.content[0].text)
        return result if isinstance(result, list) else []

    async def _analyze_ai_threats(self, description: str) -> list[dict]:
        resp = client.messages.create(
            model=MODEL_DEEP,
            max_tokens=4096,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## System Description\n{description}\n\n"
                    f"## AI Threat Skill\n{self._ai_skill[:4000]}\n\n"
                    f"## OWASP LLM Top 10\n{json.dumps(self._owasp_llm['items'], indent=2)[:3000]}\n\n"
                    f"## MITRE ATLAS Key Techniques\n{json.dumps(self._mitre_atlas['key_techniques'], indent=2)[:2000]}\n\n"
                    "Perform AI-specific threat analysis. Apply AI-STRIDE, OWASP LLM Top 10, "
                    "MITRE ATLAS, and Agentic AI threats.\n\n"
                    "Return JSON array of AI-specific threats with the same structure as STRIDE threats "
                    "but add: atlas_ttp, owasp_llm_id, is_ai_threat: true"
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_DEEP, "ai_threat_analysis",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        result = self._parse_json(resp.content[0].text)
        return result if isinstance(result, list) else []

    async def _score_threats(self, threats: list[Threat], description: str) -> list[Threat]:
        # Threats already have DREAD scores from STRIDE step.
        # Re-validate scores that look off (all 5s, etc.)
        for t in threats:
            if not t.dread_scores or all(v == 5 for v in t.dread_scores.values()):
                t.dread_scores = {
                    "damage": 5, "reproducibility": 5, "exploitability": 5,
                    "affected_users": 5, "discoverability": 5,
                }
        return threats

    async def _generate_recommendations(self, threats: list[Threat], has_ai: bool) -> list[str]:
        critical_high = [t for t in threats if t.severity in ("Critical", "High")]
        resp = client.messages.create(
            model=MODEL_REASON,
            max_tokens=1500,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Critical/High Threats\n"
                    + "\n".join(f"- {t.title}: {t.attack_path}" for t in critical_high[:10])
                    + f"\n\nHas AI components: {has_ai}\n\n"
                    "Provide 5-10 prioritized security recommendations for this system. "
                    "Focus on architectural controls, not just technical patches. "
                    "Return a JSON array of recommendation strings."
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_REASON, "recommendations",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        result = self._parse_json(resp.content[0].text)
        return result if isinstance(result, list) else []

    def _dict_to_threat(self, d: dict) -> Threat:
        return Threat(
            id          = d.get("id", "T000"),
            component   = d.get("component", "Unknown"),
            stride_cat  = d.get("stride_cat", "I"),
            title       = d.get("title", "Untitled Threat"),
            description = d.get("description", ""),
            attack_path = d.get("attack_path", ""),
            impact      = d.get("impact", ""),
            mitre_ttps  = d.get("mitre_ttps", []),
            owasp       = d.get("owasp", ""),
            dread_scores= d.get("dread_scores", {"damage":5,"reproducibility":5,"exploitability":5,"affected_users":5,"discoverability":5}),
            controls    = d.get("controls", []),
            is_ai_threat= d.get("is_ai_threat", False),
        )

    def _ai_threat_to_threat(self, d: dict) -> Threat:
        t = self._dict_to_threat(d)
        t.is_ai_threat = True
        return t

    def _parse_json(self, text: str) -> dict | list:
        text = text.strip()
        if text.startswith("```"):
            parts = text.split("```")
            text = parts[1] if len(parts) > 1 else text
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            # Try extracting first JSON block
            import re
            m = re.search(r'(\{.*\}|\[.*\])', text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    pass
            return {}
