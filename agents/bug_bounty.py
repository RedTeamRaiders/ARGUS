"""
Bug Bounty Agent — Full Attack Chain (OSCP/OSWE-Style)

Flow:
  Passive Recon → Active Recon → Vulnerability Identification
  → Exploitation → Chain Analysis → Evidence Collection → Report

Human-like: one action at a time, confirms primitives before chaining,
crown-jewels-first, canary tokens before payloads.
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
    SKILLS_DIR,
)
from shared.auth_gate import AuthRecord
from shared.logger import audit
from shared.reporter import Confidence, Finding, Severity, reporter
from shared.session import Scope, Session

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

# Load payload knowledge at import time
_PKB = DATA_DIR / "payload_knowledge"


def _load_pkb(name: str) -> dict:
    p = _PKB / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else {}


XSS_REFLECTED  = _load_pkb("xss_reflected")
XSS_STORED     = _load_pkb("xss_stored")
XSS_DOM        = _load_pkb("xss_dom")
XSS_BLIND      = _load_pkb("xss_blind")
XSS_WAF        = _load_pkb("xss_waf_bypass")
XSS_UPLOAD     = _load_pkb("xss_file_upload")
SQLI           = _load_pkb("sqli_patterns")
SSRF           = _load_pkb("ssrf_patterns")
SSTI           = _load_pkb("ssti_patterns")


class BugBountyAgent(BaseAgent):
    name        = "bug_bounty"
    description = "Bug bounty: full attack chain (OSCP/OSWE-style recon → exploit → chain → report)"

    def __init__(self) -> None:
        super().__init__()

    async def run(
        self,
        target:     str,
        scope:      Scope,
        auth:       AuthRecord,
        session:    Session,
        login_url:  str = "",
        username:   str = "",
        password:   str = "",
        scope_urls: list[str] | None = None,
    ) -> list[Finding]:
        audit.info(self.name, f"Starting bug bounty | target={target}")

        # Build initial context for ReAct loop
        from agents.base_agent import AgentContext
        context = AgentContext(
            target=target,
            scope=scope,
            session=session,
            auth=auth,
        )
        context.focus_stack = ["passive_recon"]

        # Phase 1 — Passive Recon
        audit.info(self.name, "Phase 1: Passive recon")
        await self._passive_recon(target, context)

        # Phase 2 — Active Recon (one tool at a time)
        audit.info(self.name, "Phase 2: Active recon")
        await self._active_recon(target, context)

        # Phase 3 — Vuln identification (ReAct loop runs here)
        audit.info(self.name, "Phase 3: Vulnerability identification via ReAct loop")
        await self._vuln_identification(target, context)

        # Phase 4 — XSS pipeline (crawl + canary + context analysis + payload)
        audit.info(self.name, "Phase 4: XSS testing pipeline")
        xss_findings = await self._xss_pipeline(target, context, login_url, username, password)
        for f in xss_findings:
            await session.add_finding(f.to_dict())
            context.findings.append(f)

        # Phase 5 — Chain analysis
        audit.info(self.name, "Phase 5: Vulnerability chain analysis")
        await self._analyze_chains(context)

        # Validate and collect findings
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

        await session.set_context("bug_bounty_result", {
            "total_findings": len(findings),
            "tech_stack":     context.tech_stack,
            "endpoints":      len(context.endpoints),
        })
        await session.close()

        audit.info(self.name, f"Bug bounty complete | findings={len(findings)}")
        return findings

    async def _passive_recon(self, target: str, context) -> None:
        # Use ReAct loop: think about what passive recon tells us
        thought = await self._think(context)
        audit.info(self.name, f"Passive recon thought: {thought.rationale}")

        # Historical URLs via gau
        try:
            import tool_wrappers.gau as gau_wrapper
            gau_result = await gau_wrapper.run(target)
            audit.tool_call(self.name, "gau", {"target": target})
            if gau_result:
                analysis = await self._analyze(thought, gau_result, context)
                context.endpoints.extend(analysis.new_context.get("endpoints", []))
                await context.session.add_tool_output("gau", gau_result)
        except Exception as e:
            audit.error(self.name, f"GAU failed: {e}")

        # JavaScript endpoint extraction
        try:
            import tool_wrappers.linkfinder as lf_wrapper
            lf_result = await lf_wrapper.run(target)
            if lf_result:
                analysis = await self._analyze(thought, lf_result, context)
                context.endpoints.extend(analysis.new_context.get("endpoints", []))
                await context.session.add_tool_output("linkfinder", lf_result)
        except Exception as e:
            audit.error(self.name, f"LinkFinder failed: {e}")

    async def _active_recon(self, target: str, context) -> None:
        await self.rate_limiter.wait()

        # httpx probe
        try:
            import tool_wrappers.httpx as httpx_wrapper
            result = await httpx_wrapper.run(target)
            if result:
                thought = await self._think(context)
                analysis = await self._analyze(thought, result, context)
                context.tech_stack.update(analysis.new_context.get("tech", {}))
                await context.session.add_tool_output("httpx", result)
        except Exception as e:
            audit.error(self.name, f"httpx failed: {e}")

        await self.rate_limiter.wait()

        # Directory enumeration
        try:
            import tool_wrappers.gobuster as gb_wrapper
            result = await gb_wrapper.run(target)
            if result:
                thought = await self._think(context)
                analysis = await self._analyze(thought, result, context)
                context.endpoints.extend(analysis.new_context.get("endpoints", []))
                await context.session.add_tool_output("gobuster", result)
        except Exception as e:
            audit.error(self.name, f"Gobuster failed: {e}")

        await self.rate_limiter.wait()

        # Nuclei detection-only
        try:
            import tool_wrappers.nuclei as nuclei_wrapper
            result = await nuclei_wrapper.run(target, mode="detect")
            if result:
                thought = await self._think(context)
                analysis = await self._analyze(thought, result, context)
                for finding_hint in analysis.new_context.get("findings", []):
                    context.interesting.append(finding_hint)
                await context.session.add_tool_output("nuclei", result)
        except Exception as e:
            audit.error(self.name, f"Nuclei failed: {e}")

    async def _vuln_identification(self, target: str, context) -> None:
        # Ask Opus what to test given everything we've learned
        resp = client.messages.create(
            model=MODEL_DEEP,
            max_tokens=4096,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Target\n{target}\n\n"
                    f"## Tech Stack\n{json.dumps(context.tech_stack, indent=2)}\n\n"
                    f"## Endpoints Discovered\n{json.dumps(context.endpoints[:30], indent=2)}\n\n"
                    f"## Interesting Findings So Far\n{json.dumps(context.interesting[:10], indent=2)}\n\n"
                    f"## Bug Bounty Skill\n{self._skill[:3000]}\n\n"
                    "Based on the recon, identify the highest-priority vulnerability targets. "
                    "For each, describe: what to test, which tool to use, what confirms the vulnerability.\n\n"
                    "Return JSON array:\n"
                    "[\n"
                    '  {"priority": 1, "attack_class": "SQLi|XSS|SSRF|AuthBypass|IDOR", '
                    '"target_param": "", "tool": "sqlmap|dalfox|manual|nuclei", '
                    '"confirm_step": "", "expected_impact": ""}\n'
                    "]"
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_DEEP, "vuln_identification",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        targets = self._parse_json(resp.content[0].text)
        if isinstance(targets, list):
            context.focus_stack = [t.get("attack_class", "") for t in targets[:5]]

    async def _xss_pipeline(
        self,
        target: str,
        context,
        login_url: str,
        username: str,
        password: str,
    ) -> list[Finding]:
        findings = []

        # 1. Crawl the application
        try:
            from tool_wrappers.argus_crawler.crawler import ArgusCrawler
            from tool_wrappers.argus_crawler.auth_handler import AuthConfig, AuthHandler
            from tool_wrappers.argus_crawler.monitor import ExecutionMonitor
            from tool_wrappers.argus_crawler.payload_injector import PayloadInjector
            from tool_wrappers.argus_crawler.evidence_collector import EvidenceCollector

            # Crawl first — no payloads
            crawler = ArgusCrawler(target, max_depth=3, max_pages=80)
            crawl_result = await crawler.crawl()
            await context.session.add_tool_output("argus_crawler", {"pages": len(crawl_result.pages), "forms": crawl_result.total_forms})

            audit.info(self.name, f"Crawl complete: {len(crawl_result.pages)} pages, {crawl_result.total_forms} forms")

            # 2. Ask Claude which surfaces to test with XSS
            surfaces_to_test = await self._select_xss_surfaces(crawl_result, context)
            evidence_collector = EvidenceCollector()

            # 3. For each surface: canary → confirm reflection → context analysis → payload
            from playwright.async_api import async_playwright

            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True, slow_mo=100)
                ctx_browser = await browser.new_context()

                for surface_info in surfaces_to_test[:20]:
                    await self.rate_limiter.wait()
                    surface = surface_info.get("surface", {})
                    page_url = surface_info.get("page_url", target)

                    try:
                        page = await ctx_browser.new_page()
                        await page.goto(page_url, wait_until="networkidle", timeout=15000)
                        await evidence_collector.attach_to_page(page)

                        async with ExecutionMonitor(page) as monitor:
                            # Step 1: Canary to confirm reflection
                            canary = "argus_xss_test_001"
                            from tool_wrappers.argus_crawler.payload_injector import PayloadInjector
                            injector = PayloadInjector(page)
                            result = await injector.inject(surface, canary)

                            if not result.injected:
                                await page.close()
                                continue

                            content = await page.content()
                            if canary not in content:
                                await page.close()
                                continue  # No reflection — skip

                            # Step 2: Ask Claude for context-appropriate payload
                            payload = await self._select_xss_payload(surface, content, canary)

                            # Step 3: Navigate back and inject real payload
                            await page.goto(page_url, wait_until="networkidle", timeout=10000)
                            inject_result = await injector.inject(surface, payload)

                            if not inject_result.injected:
                                await page.close()
                                continue

                            # Step 4: Wait and check for execution
                            events = await monitor.check_execution(wait_ms=1500)

                            if monitor.confirmed_xss:
                                # Confirmed! Collect evidence
                                evidence = await evidence_collector.capture(
                                    page, payload, "dialog",
                                    f"xss_{surface.get('name', 'unknown')}"
                                )
                                finding = Finding(
                                    agent=self.name,
                                    title=f"Reflected XSS in {surface.get('name', 'parameter')}",
                                    severity=Severity.HIGH,
                                    evidence=evidence.to_evidence_string(),
                                    observed=f"Payload: {payload} | URL: {page_url} | Input: {surface.get('name')}",
                                    inferred="JavaScript execution confirmed via alert() dialog",
                                    cvss_score=7.4,
                                    cwe="CWE-79",
                                    owasp="A03",
                                    description=f"Reflected XSS in parameter {surface.get('name')} at {page_url}",
                                    poc=f"Payload: {payload}",
                                    impact="Attacker can execute arbitrary JavaScript in victim browser, steal session cookies, perform CSRF",
                                    remediation="HTML-encode all user-supplied output. Implement Content Security Policy.",
                                    confidence=Confidence.HIGH,
                                    confirmed=True,
                                    confirmed_by=["playwright_dialog_confirmation"],
                                    target=target,
                                    url=page_url,
                                    parameter=surface.get("name", ""),
                                )
                                findings.append(finding)
                                audit.finding(self.name, finding.title, "High", 7.4, True, "HIGH")

                        await page.close()
                    except Exception as e:
                        audit.error(self.name, f"XSS test failed for {surface.get('name', '?')}: {e}")

                await browser.close()
        except Exception as e:
            audit.error(self.name, f"XSS pipeline failed: {e}")

        return findings

    async def _select_xss_surfaces(self, crawl_result, context) -> list[dict]:
        pages_summary = [
            {
                "url": p.url,
                "forms": len(p.forms),
                "title": p.title,
            }
            for p in crawl_result.pages[:20]
        ]
        resp = client.messages.create(
            model=MODEL_REASON,
            max_tokens=2000,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Crawled Pages\n{json.dumps(pages_summary, indent=2)}\n\n"
                    "Select the highest-priority input surfaces for XSS testing. "
                    "Prioritize: comment fields, search boxes, profile fields, admin-visible inputs.\n\n"
                    "Return JSON array:\n"
                    '[\n  {"page_url": "", "surface": {}, "reason": ""}\n]'
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_REASON, "surface_selection",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        result = self._parse_json(resp.content[0].text)
        if isinstance(result, list):
            return result

        # Fallback: all surfaces from crawl
        surfaces = []
        for page in crawl_result.pages:
            for form in page.forms:
                for inp in form.get("inputs", []):
                    surfaces.append({"page_url": page.url, "surface": inp, "reason": "crawled"})
        return surfaces

    async def _select_xss_payload(self, surface: dict, page_content: str, canary: str) -> str:
        resp = client.messages.create(
            model=MODEL_REASON,
            max_tokens=500,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Input Surface\n{json.dumps(surface, indent=2)}\n\n"
                    f"## Page Context (around canary)\n{self._extract_canary_context(page_content, canary)}\n\n"
                    f"## Payload Knowledge\n{json.dumps({'contexts': list(XSS_REFLECTED.get('contexts', {}).keys())}, indent=2)}\n\n"
                    "Select the most appropriate XSS payload for this reflection context. "
                    "Return ONLY the payload string, nothing else."
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_REASON, "payload_selection",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        payload = resp.content[0].text.strip().strip('"\'')
        if not payload or len(payload) < 5:
            return "<img src=x onerror=alert(1)>"
        return payload

    def _extract_canary_context(self, html: str, canary: str) -> str:
        idx = html.find(canary)
        if idx < 0:
            return "(canary not found in page)"
        start = max(0, idx - 200)
        end = min(len(html), idx + 200)
        return html[start:end]

    async def _analyze_chains(self, context) -> None:
        if len(context.findings) < 2:
            return
        finding_summaries = [
            {"title": f.title, "severity": f.severity.value, "cwe": f.cwe}
            for f in context.findings[:10]
        ]
        resp = client.messages.create(
            model=MODEL_DEEP,
            max_tokens=2000,
            system=self._system_prompt,
            messages=[{
                "role": "user",
                "content": (
                    f"## Confirmed Findings\n{json.dumps(finding_summaries, indent=2)}\n\n"
                    "Identify vulnerability chains that combine these findings for higher impact. "
                    "Specifically: can any finding be used to reach admin access, account takeover, or data exfiltration?\n\n"
                    "Return JSON:\n"
                    '{"chains": [{"id": "CHAIN-01", "findings": [], "combined_impact": "", "severity": "Critical|High"}]}'
                ),
            }],
        )
        audit.claude_call(self.name, MODEL_DEEP, "chain_analysis",
                          resp.usage.input_tokens, resp.usage.output_tokens)
        result = self._parse_json(resp.content[0].text)
        chains = result.get("chains", []) if isinstance(result, dict) else []
        for chain in chains:
            audit.info(self.name, f"Chain identified: {chain.get('id')} — {chain.get('combined_impact', '')}")

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
