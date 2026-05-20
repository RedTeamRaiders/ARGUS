"""
BaseAgent — the core ReAct (Reason + Act) engine for all ARGUS agents.

Every sub-agent extends this class. The loop:
    Observe → Think (Claude) → Act (one tool) → Analyze → Update context → repeat

This is what makes ARGUS behave like a human pentester rather than a DAST scanner.
Claude reasons between EVERY action. Tools are the last resort, not the first.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import anthropic

from config import (
    ANTHROPIC_API_KEY, MODEL_PARSE, MODEL_REASON, MODEL_DEEP,
    MAX_RPS, PROMPTS_DIR, SKILLS_DIR,
)
from shared.auth_gate import AuthRecord
from shared.logger import audit
from shared.progress import LiveDashboard
from shared.reporter import Confidence, Finding, Severity
from shared.session import Scope, Session

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


# ── Anti-scanner rate limiter ──────────────────────────────────────────────

class RateLimiter:
    """Enforces max requests-per-minute to keep traffic looking human."""

    def __init__(self, max_rps: int = MAX_RPS) -> None:
        self._max_rps   = max_rps
        self._min_gap   = 60.0 / max_rps   # seconds between requests
        self._last_call = 0.0

    async def wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        wait    = self._min_gap - elapsed
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_call = time.monotonic()


# ── Thought / Analysis dataclasses ────────────────────────────────────────

@dataclass
class Thought:
    """What Claude decides to do next and why."""
    observation:  str          # what the last result actually means
    hypothesis:   str          # what could be vulnerable / interesting
    rationale:    str          # why this hypothesis
    next_action:  dict         # {tool: str, params: dict, reason: str}
    what_i_expect: str         # what confirmation looks like
    dead_end:     bool = False # should we move on from current surface?
    confidence:   str  = "Medium"


@dataclass
class Analysis:
    """What Claude concludes after seeing a tool result."""
    summary:       str
    interesting:   bool
    follow_up:     str          # what to investigate next if interesting
    finding:       Optional[Finding] = None
    new_context:   dict         = field(default_factory=dict)


@dataclass
class AgentContext:
    """The agent's accumulating mental model of the target."""
    target:        str
    scope:         Scope
    session:       Session
    auth:          AuthRecord

    tech_stack:    list[str]    = field(default_factory=list)
    open_ports:    list[dict]   = field(default_factory=list)
    endpoints:     list[str]    = field(default_factory=list)
    users:         list[str]    = field(default_factory=list)
    credentials:   list[dict]   = field(default_factory=list)
    interesting:   list[str]    = field(default_factory=list)   # notable observations
    tried:         set[str]     = field(default_factory=set)    # actions already taken
    findings:      list[Finding]= field(default_factory=list)
    focus_stack:   list[str]    = field(default_factory=list)   # things to dig into

    _exhaustion_limit: int      = 50    # max think/act cycles

    def push_focus(self, topic: str) -> None:
        if topic not in self.focus_stack:
            self.focus_stack.append(topic)

    def pop_focus(self) -> Optional[str]:
        return self.focus_stack.pop() if self.focus_stack else None

    def mark_tried(self, action_key: str) -> None:
        self.tried.add(action_key)

    def already_tried(self, action_key: str) -> bool:
        return action_key in self.tried

    def exhausted(self) -> bool:
        cycle_count = len(self.tried)
        return cycle_count >= self._exhaustion_limit

    def summary(self) -> str:
        """Returns a concise mental model summary for Claude's context window."""
        return json.dumps({
            "target":       self.target,
            "tech_stack":   self.tech_stack,
            "open_ports":   self.open_ports[:20],
            "endpoints":    self.endpoints[:30],
            "users":        self.users[:10],
            "interesting":  self.interesting[-10:],
            "focus_stack":  self.focus_stack[-5:],
            "findings_count": len(self.findings),
            "findings_titles": [f.title for f in self.findings],
            "tried_count":  len(self.tried),
        }, indent=2)


# ── BaseAgent ─────────────────────────────────────────────────────────────

class BaseAgent:
    name:        str = "base"
    description: str = "Base ARGUS agent"

    def __init__(self) -> None:
        self._rate_limiter = RateLimiter()
        self._skill        = self._load_skill()
        self._system_prompt= self._load_prompt()
        self._tool_specs: list[dict] = []   # set by sub-agent
        self._dashboard: Optional[LiveDashboard] = None

    def _load_skill(self) -> str:
        path = SKILLS_DIR / self.name / "SKILL.md"
        return path.read_text() if path.exists() else ""

    def _load_prompt(self) -> str:
        path = PROMPTS_DIR / f"{self.name}.md"
        return path.read_text() if path.exists() else (
            f"You are an elite {self.name} specialist. "
            "Think carefully before every action. "
            "You behave like a senior human pentester, not a scanner."
        )

    # ── Core ReAct loop ───────────────────────────────────────────────────

    async def run(
        self,
        target: str,
        scope:  Scope,
        auth:   AuthRecord,
        session: Session,
    ) -> list[Finding]:
        """
        Main entry point. Sub-agents call this or override it.
        Returns all confirmed findings for the engagement.
        """
        context = AgentContext(
            target=target, scope=scope, session=session, auth=auth
        )
        audit.info(self.name, f"Starting engagement | target={target}")

        self._dashboard = LiveDashboard(
            target=target, agent=self.name,
            cycles_max=context._exhaustion_limit,
        )
        self._dashboard.start()

        while not context.exhausted():
            # ── THINK ────────────────────────────────────────────────────
            thought = await self._think(context)

            if thought.dead_end and not context.focus_stack:
                audit.info(self.name, "No more attack surfaces. Ending loop.")
                break

            action_key = f"{thought.next_action.get('tool')}:{json.dumps(thought.next_action.get('params', {}), sort_keys=True)}"
            if context.already_tried(action_key):
                context.mark_tried(action_key + "_skip")
                continue

            context.mark_tried(action_key)

            if self._dashboard:
                tool = thought.next_action.get("tool", "")
                self._dashboard.set_last_action(f"{tool}: {thought.rationale[:70]}")

            # ── ACT ───────────────────────────────────────────────────────
            result = await self._act(thought, context)

            # ── ANALYZE ───────────────────────────────────────────────────
            analysis = await self._analyze(thought, result, context)

            # Update mental model
            context.interesting.extend(analysis.new_context.get("interesting", []))
            context.tech_stack  = list(set(context.tech_stack  + analysis.new_context.get("tech_stack", [])))
            context.open_ports += analysis.new_context.get("open_ports", [])
            context.endpoints  += analysis.new_context.get("endpoints", [])
            context.users       = list(set(context.users + analysis.new_context.get("users", [])))

            if analysis.finding:
                try:
                    analysis.finding.validate()
                    context.findings.append(analysis.finding)
                    await session.add_finding(analysis.finding.to_dict())
                    if self._dashboard:
                        self._dashboard.add_finding(analysis.finding.severity.value)
                    audit.finding(
                        self.name,
                        analysis.finding.title,
                        analysis.finding.severity.value,
                        analysis.finding.cvss_score,
                        analysis.finding.confirmed,
                        analysis.finding.confidence.value,
                    )
                except ValueError as e:
                    audit.error(self.name, f"Finding rejected: {e}")

            if analysis.interesting and analysis.follow_up:
                context.push_focus(analysis.follow_up)

            if self._dashboard:
                self._dashboard.tick()

        if self._dashboard:
            self._dashboard.stop()

        await session.close()
        audit.info(self.name, f"Engagement complete | findings={len(context.findings)}")
        return context.findings

    # ── Think step (Claude reasons about what to do next) ─────────────────

    async def _think(self, context: AgentContext, model: str = "") -> Thought:
        await self._rate_limiter.wait()
        model = model or MODEL_REASON

        messages = [
            {
                "role": "user",
                "content": (
                    f"## Current Mental Model\n{context.summary()}\n\n"
                    f"## Skill Reference\n{self._skill[:3000]}\n\n"
                    "## Your Task\n"
                    "Based on what you know so far, decide the single most valuable next action.\n"
                    "Think like an elite human pentester — not a scanner.\n\n"
                    "Respond in this exact JSON format:\n"
                    "{\n"
                    '  "observation": "what the current state means",\n'
                    '  "hypothesis": "what could be vulnerable or interesting",\n'
                    '  "rationale": "why you believe this",\n'
                    '  "next_action": {"tool": "<tool_name>", "params": {}, "reason": "why this tool"},\n'
                    '  "what_i_expect": "what confirmation of the hypothesis looks like",\n'
                    '  "dead_end": false,\n'
                    '  "confidence": "High|Medium|Low"\n'
                    "}"
                ),
            }
        ]

        t0 = time.monotonic()
        resp = client.messages.create(
            model=model,
            max_tokens=1024,
            system=self._system_prompt,
            messages=messages,
        )
        duration = time.monotonic() - t0

        audit.claude_call(
            agent=self.name, model=model, purpose="think",
            tokens_in=resp.usage.input_tokens,
            tokens_out=resp.usage.output_tokens,
            cached_tokens=getattr(resp.usage, "cache_read_input_tokens", 0),
        )

        try:
            raw = resp.content[0].text.strip()
            # Strip markdown code fences if present
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            data = json.loads(raw)
            return Thought(
                observation   = data.get("observation", ""),
                hypothesis    = data.get("hypothesis", ""),
                rationale     = data.get("rationale", ""),
                next_action   = data.get("next_action", {"tool": "noop", "params": {}, "reason": ""}),
                what_i_expect = data.get("what_i_expect", ""),
                dead_end      = data.get("dead_end", False),
                confidence    = data.get("confidence", "Medium"),
            )
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            audit.error(self.name, f"Think parse error: {e}")
            return Thought(
                observation="Parse error", hypothesis="", rationale="",
                next_action={"tool": "noop", "params": {}, "reason": "parse error"},
                what_i_expect="", dead_end=True,
            )

    # ── Act step (calls the tool wrapper) ─────────────────────────────────

    async def _act(self, thought: Thought, context: AgentContext) -> dict:
        tool_name = thought.next_action.get("tool", "noop")
        params    = thought.next_action.get("params", {})

        if tool_name == "noop":
            return {"tool": "noop", "parsed": [], "raw_output": "", "error": None}

        # Scope check before every tool call
        target = params.get("target", context.target)
        if not context.scope.contains(target):
            audit.scope_check(self.name, target, in_scope=False)
            return {"tool": tool_name, "parsed": [], "raw_output": "",
                    "error": f"OUT_OF_SCOPE: {target}"}

        audit.scope_check(self.name, target, in_scope=True)

        # Dynamically load the tool wrapper
        try:
            module = importlib.import_module(f"tool_wrappers.{tool_name}")
        except ModuleNotFoundError:
            audit.error(self.name, f"Tool wrapper not found: tool_wrappers.{tool_name}")
            return {"tool": tool_name, "parsed": [], "raw_output": "",
                    "error": f"wrapper_not_found: {tool_name}"}

        t0 = time.monotonic()
        audit.tool_call(agent=self.name, tool=tool_name,
                        command=f"{tool_name}({json.dumps(params)[:80]})", target=target)

        await self._rate_limiter.wait()
        try:
            result = await module.run(target=target, options=params)
            duration = time.monotonic() - t0
            audit.tool_call(agent=self.name, tool=tool_name,
                            command=str(params)[:80], target=target,
                            duration_s=round(duration, 2), success=True)
            await context.session.add_tool_output(tool_name, str(params), result if isinstance(result, dict) else {"raw": str(result)})
            return result if isinstance(result, dict) else {"tool": tool_name, "parsed": [], "raw_output": str(result), "error": None}
        except Exception as e:
            duration = time.monotonic() - t0
            audit.tool_call(agent=self.name, tool=tool_name,
                            command=str(params)[:80], target=target,
                            duration_s=round(duration, 2), success=False, error=str(e))
            return {"tool": tool_name, "parsed": [], "raw_output": "", "error": str(e)}

    # ── Analyze step (Claude interprets the result) ────────────────────────

    async def _analyze(self, thought: Thought, result: dict, context: AgentContext) -> Analysis:
        await self._rate_limiter.wait()

        parsed_preview = json.dumps(result.get("parsed", [])[:5], indent=2)[:2000]

        messages = [
            {
                "role": "user",
                "content": (
                    f"## Hypothesis\n{thought.hypothesis}\n\n"
                    f"## Expected confirmation\n{thought.what_i_expect}\n\n"
                    f"## Tool Result (parsed)\n```json\n{parsed_preview}\n```\n\n"
                    f"## Raw output (first 500 chars)\n{result.get('raw_output', '')[:500]}\n\n"
                    "## Current findings so far\n"
                    + "\n".join(f"- {f.title} ({f.severity.value})" for f in context.findings[-5:])
                    + "\n\nAnalyze this result. Does it confirm the hypothesis? "
                    "Is there a vulnerability? What should be investigated next?\n\n"
                    "Respond in this exact JSON format:\n"
                    "{\n"
                    '  "summary": "what this result actually tells us",\n'
                    '  "interesting": true/false,\n'
                    '  "follow_up": "specific next thing to investigate if interesting",\n'
                    '  "finding": null or {\n'
                    '    "title": "", "severity": "Critical|High|Medium|Low|Info",\n'
                    '    "cvss_score": 0.0, "cwe": "", "owasp": "",\n'
                    '    "description": "", "evidence": "<DIRECT TOOL OUTPUT — MANDATORY>",\n'
                    '    "observed": "", "inferred": "",\n'
                    '    "poc": "", "impact": "", "remediation": "",\n'
                    '    "confidence": "High|Medium|Low",\n'
                    '    "confirmed": false, "confirmed_by": []\n'
                    "  },\n"
                    '  "new_context": {\n'
                    '    "tech_stack": [], "open_ports": [], "endpoints": [],\n'
                    '    "users": [], "interesting": []\n'
                    "  }\n"
                    "}"
                ),
            }
        ]

        resp = client.messages.create(
            model=MODEL_REASON,
            max_tokens=2048,
            system=self._system_prompt,
            messages=messages,
        )

        audit.claude_call(
            agent=self.name, model=MODEL_REASON, purpose="analyze",
            tokens_in=resp.usage.input_tokens,
            tokens_out=resp.usage.output_tokens,
            cached_tokens=getattr(resp.usage, "cache_read_input_tokens", 0),
        )

        try:
            raw = resp.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            data = json.loads(raw)

            finding = None
            if data.get("finding"):
                fd = data["finding"]
                finding = Finding(
                    agent       = self.name,
                    title       = fd.get("title", "Untitled"),
                    severity    = Severity(fd.get("severity", "Info")),
                    evidence    = fd.get("evidence", ""),
                    observed    = fd.get("observed", ""),
                    inferred    = fd.get("inferred", ""),
                    cvss_score  = float(fd.get("cvss_score", 0.0)),
                    cwe         = fd.get("cwe", ""),
                    owasp       = fd.get("owasp", ""),
                    description = fd.get("description", ""),
                    poc         = fd.get("poc", ""),
                    impact      = fd.get("impact", ""),
                    remediation = fd.get("remediation", ""),
                    confidence  = Confidence(fd.get("confidence", "Low")),
                    confirmed   = fd.get("confirmed", False),
                    confirmed_by= fd.get("confirmed_by", []),
                    target      = context.target,
                )

            return Analysis(
                summary     = data.get("summary", ""),
                interesting = data.get("interesting", False),
                follow_up   = data.get("follow_up", ""),
                finding     = finding,
                new_context = data.get("new_context", {}),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            audit.error(self.name, f"Analyze parse error: {e}")
            return Analysis(summary="Parse error", interesting=False, follow_up="")

    # ── Deep reasoning helper (Opus) ──────────────────────────────────────

    async def _deep_think(self, prompt: str, context: str = "") -> str:
        """Use Opus for attack chain construction and adversarial reasoning."""
        resp = client.messages.create(
            model=MODEL_DEEP,
            max_tokens=4096,
            system=self._system_prompt,
            messages=[{"role": "user", "content": f"{context}\n\n{prompt}"}],
        )
        audit.claude_call(
            agent=self.name, model=MODEL_DEEP, purpose="deep_think",
            tokens_in=resp.usage.input_tokens,
            tokens_out=resp.usage.output_tokens,
            cached_tokens=getattr(resp.usage, "cache_read_input_tokens", 0),
        )
        return resp.content[0].text

    # ── Parse helper (Haiku) ──────────────────────────────────────────────

    async def _parse(self, raw_output: str, schema_hint: str = "") -> dict:
        """Use Haiku to parse raw tool output into structured JSON cheaply."""
        resp = client.messages.create(
            model=MODEL_PARSE,
            max_tokens=2048,
            system="You are a precise data extractor. Extract structured data from tool output. Return only valid JSON.",
            messages=[{
                "role": "user",
                "content": (
                    f"Parse this tool output into structured JSON.\n"
                    f"Schema hint: {schema_hint}\n\n"
                    f"Output:\n{raw_output[:4000]}"
                ),
            }],
        )
        audit.claude_call(
            agent=self.name, model=MODEL_PARSE, purpose="parse",
            tokens_in=resp.usage.input_tokens,
            tokens_out=resp.usage.output_tokens,
        )
        try:
            raw = resp.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw_output[:1000]}
