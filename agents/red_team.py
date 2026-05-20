"""
Red Team Agent — APT Simulation + MITRE ATT&CK

Flow:
  Campaign Planning → Recon (OSINT) → Initial Access → Execution
  → Privilege Escalation → Defense Evasion → Lateral Movement
  → Collection → Exfil (simulated) → C2 → Report

Focus: stealth, OPSEC, detection gap identification.
Every TTP mapped to MITRE ATT&CK.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

import anthropic

from agents.base_agent import BaseAgent, AgentContext
from config import ANTHROPIC_API_KEY, MODEL_DEEP, MODEL_REASON
from shared.auth_gate import AuthRecord
from shared.logger import audit
from shared.reporter import Confidence, Finding, Severity
from shared.session import Scope, Session

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


@dataclass
class CampaignPhase:
    name:       str
    tactic:     str       # MITRE ATT&CK tactic (TA0xxx)
    ttps_used:  list[str] = field(default_factory=list)
    detected:   bool = False
    detection_time: Optional[str] = None
    objective_reached: bool = False
    notes:      str = ""


@dataclass
class Campaign:
    objective:     str
    target_org:    str
    phases:        list[CampaignPhase] = field(default_factory=list)
    dwell_time:    str = ""
    crown_jewels_reached: bool = False
    detection_count: int = 0


class RedTeamAgent(BaseAgent):
    name        = "red_team"
    description = "Red team APT simulation: MITRE ATT&CK-mapped campaign with stealth focus"

    def __init__(self) -> None:
        super().__init__()

    async def run(
        self,
        target:      str,
        scope:       Scope,
        auth:        AuthRecord,
        session:     Session,
        objective:   str = "demonstrate persistent domain access",
        target_data: str = "",  # what to "exfiltrate" (demonstrate access to)
    ) -> list[Finding]:
        audit.info(self.name, f"Starting red team | target={target} | objective={objective}")

        context = AgentContext(
            target=target,
            scope=scope,
            session=session,
            auth=auth,
        )

        # Phase 0 — Campaign planning
        campaign = await self._plan_campaign(target, objective, context)

        # Phase 1 — Reconnaissance (OSINT, passive)
        await self._reconnaissance(target, campaign, context)

        # Phase 2 — Initial access simulation
        await self._initial_access(target, campaign, context)

        # Phase 3 — Post-access operations (ReAct loop)
        await self._post_access_operations(target, campaign, context)

        # Phase 4 — Detection gap analysis
        await self._analyze_detection_gaps(campaign, context)

        # Convert to findings
        findings = []
        for f in context.findings:
            try:
                f.validate()
                findings.append(f)
                audit.finding(
                    self.name, f.title, f.severity.value,
                    f.cvss_score, f.confirmed, f.confidence.value,
                )
            except ValueError as e:
                audit.error(self.name, f"Finding rejected: {e}")

        await session.set_context("red_team_result", {
            "objective":         objective,
            "phases_completed":  len(campaign.phases),
            "detections":        campaign.detection_count,
            "crown_jewels_reached": campaign.crown_jewels_reached,
        })
        await session.close()

        audit.info(self.name, f"Red team complete | findings={len(findings)} | detected={campaign.detection_count}x")
        return findings

    async def _plan_campaign(self, target: str, objective: str, context: AgentContext) -> Campaign:
        resp = client.messages.create(
            model=MODEL_DEEP,
            max_tokens=3000,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Target Organization\n{target}\n\n"
                    f"## Campaign Objective\n{objective}\n\n"
                    f"## Red Team Skill\n{self._skill[:3000]}\n\n"
                    "Plan a realistic APT simulation campaign. Map each phase to MITRE ATT&CK tactics. "
                    "Prioritize stealth over speed.\n\n"
                    "Return JSON:\n"
                    "{\n"
                    '  "objective": "",\n'
                    '  "crown_jewels": [],\n'
                    '  "initial_access_vector": "phishing|cve|valid_accounts",\n'
                    '  "phases": [\n'
                    '    {"name": "Reconnaissance", "tactic": "TA0043", "planned_ttps": ["T1598", "T1596"], "detection_risk": "low"}\n'
                    "  ],\n"
                    '  "c2_profile": "",\n'
                    '  "evasion_priority": "high|medium"\n'
                    "}"
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_DEEP, "campaign_planning",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        plan = self._parse_json(resp.content[0].text)
        campaign = Campaign(
            objective=objective,
            target_org=target,
        )
        for phase_data in plan.get("phases", []):
            campaign.phases.append(CampaignPhase(
                name=phase_data.get("name", ""),
                tactic=phase_data.get("tactic", ""),
                ttps_used=phase_data.get("planned_ttps", []),
            ))
        await context.session.set_context("campaign_plan", plan)
        return campaign

    async def _reconnaissance(self, target: str, campaign: Campaign, context: AgentContext) -> None:
        audit.info(self.name, "TA0043: Reconnaissance")
        phase = CampaignPhase(name="Reconnaissance", tactic="TA0043")

        # Passive OSINT only — no active scanning in recon phase
        try:
            import tool_wrappers.shodan as shodan_wrapper
            result = await shodan_wrapper.run(target)
            if result:
                thought = await self._think(context)
                analysis = await self._analyze(thought, result, context)
                context.tech_stack.update(analysis.new_context.get("tech", {}))
                phase.ttps_used.append("T1596")  # Search Open Technical Databases
                await context.session.add_tool_output("shodan", result)
        except Exception as e:
            audit.error(self.name, f"Shodan recon failed: {e}")

        phase.notes = "Passive reconnaissance complete — no active probing"
        campaign.phases.append(phase)

    async def _initial_access(self, target: str, campaign: Campaign, context: AgentContext) -> None:
        audit.info(self.name, "TA0001: Initial Access simulation")
        phase = CampaignPhase(name="Initial Access", tactic="TA0001")

        # Simulate initial access based on campaign plan
        # In practice: phishing simulation, CVE exploitation, or valid account use
        # We use nmap + nuclei to identify the most realistic initial access vector
        await self.rate_limiter.wait()

        try:
            import tool_wrappers.nmap as nmap_wrapper
            result = await nmap_wrapper.run(target, ports="80,443,8080,8443,22,21,3389,445,25,143")
            if result:
                thought = await self._think(context)
                analysis = await self._analyze(thought, result, context)
                context.open_ports = result.get("ports", [])
                phase.ttps_used.append("T1190")  # Exploit Public-Facing Application
                await context.session.add_tool_output("nmap_initial_access", result)
        except Exception as e:
            audit.error(self.name, f"Initial access recon failed: {e}")

        # Check for known CVEs in discovered services
        await self.rate_limiter.wait()
        try:
            import tool_wrappers.nuclei as nuclei_wrapper
            result = await nuclei_wrapper.run(target, mode="detect")
            if result:
                thought = await self._think(context)
                analysis = await self._analyze(thought, result, context)
                for item in result[:5]:
                    if item.get("severity") in ("critical", "high"):
                        phase.ttps_used.append("T1190")
                        context.interesting["initial_access_cve"] = item.get("template_id", "")
                await context.session.add_tool_output("nuclei_initial_access", result)
        except Exception as e:
            audit.error(self.name, f"Nuclei initial access check failed: {e}")

        phase.notes = f"Initial access vector identified. Open services: {len(context.open_ports)}"
        campaign.phases.append(phase)

    async def _post_access_operations(self, target: str, campaign: Campaign, context: AgentContext) -> None:
        audit.info(self.name, "Post-access operations: Execution → Persistence → Priv Esc → Lateral")

        # Use full ReAct loop for post-access phases
        # Opus drives every decision with red team OPSEC in mind
        max_iterations = 15
        for iteration in range(max_iterations):
            await self.rate_limiter.wait()
            thought = await self._think(context)

            if thought.dead_end:
                audit.info(self.name, "Red team: no further actions — mission complete or blocked")
                break

            result = await self._act(thought, context)
            analysis = await self._analyze(thought, result, context)
            context.update_from_analysis(analysis)

            # Track ATT&CK phases
            tactic = thought.rationale[:10] if thought.rationale else ""
            if "TA0" in tactic or "T1" in thought.next_action:
                phase_name = thought.next_action.split(":")[0] if ":" in thought.next_action else "Operation"
                campaign.phases.append(CampaignPhase(
                    name=phase_name,
                    tactic=tactic,
                    ttps_used=[thought.next_action],
                ))

            await context.session.add_tool_output(thought.next_action, result)

            if analysis.finding:
                context.findings.append(analysis.finding)
                if analysis.finding.severity.value == "Critical":
                    campaign.crown_jewels_reached = True

    async def _analyze_detection_gaps(self, campaign: Campaign, context: AgentContext) -> None:
        audit.info(self.name, "Analyzing detection gaps")

        ttps_used = []
        for phase in campaign.phases:
            ttps_used.extend(phase.ttps_used)

        resp = client.messages.create(
            model=MODEL_DEEP,
            max_tokens=3000,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Campaign Summary\n"
                    f"Objective: {campaign.objective}\n"
                    f"Phases: {len(campaign.phases)}\n"
                    f"TTPs Used: {list(set(ttps_used))}\n\n"
                    f"## Context\n{json.dumps(context.interesting, indent=2)[:2000]}\n\n"
                    "Analyze the detection gaps this campaign revealed. What should the blue team add to detect these TTPs?\n\n"
                    "Return JSON:\n"
                    "{\n"
                    '  "detection_gaps": [\n'
                    '    {"ttp": "T1078", "gap": "No alerting on impossible travel", "recommendation": "Enable Conditional Access geolocation policy", "siem_rule": ""}\n'
                    "  ],\n"
                    '  "purple_team_exercises": []\n'
                    "}"
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_DEEP, "detection_gap_analysis",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        gaps = self._parse_json(resp.content[0].text)

        # Create findings for each detection gap
        for gap in gaps.get("detection_gaps", []):
            finding = Finding(
                agent=self.name,
                title=f"Detection Gap: {gap.get('gap', 'Unknown')}",
                severity=Severity.HIGH,
                evidence=f"TTP {gap.get('ttp', '')} executed without triggering detection",
                observed=f"TTP: {gap.get('ttp', '')} | Gap: {gap.get('gap', '')}",
                inferred="Red team operated undetected through this technique",
                cvss_score=7.0,
                cwe="",
                mitre_attack=[gap.get("ttp", "")],
                description=gap.get("gap", ""),
                impact="Attacker can use this technique without detection, enabling persistent access",
                remediation=gap.get("recommendation", ""),
                confidence=Confidence.HIGH,
                confirmed=True,
                confirmed_by=["red_team_simulation"],
                target=campaign.target_org,
            )
            context.findings.append(finding)

        await context.session.set_context("detection_gaps", gaps)

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
