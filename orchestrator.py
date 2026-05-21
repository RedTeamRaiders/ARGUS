"""
ARGUS Orchestrator — routes user selections to agents, manages sessions, triggers reports.
"""
from __future__ import annotations

import asyncio
import importlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from config import TEMPLATES_DIR
from shared.auth_gate import AuthRecord, require_authorization
from shared.logger import audit
from shared.reporter import Finding, Reporter, Severity
from shared.session import Scope, Session

console = Console()
reporter = Reporter()

MENU = {
    "1": ("pentest",      "Penetration Testing",    "Black/White Box — full attack chain"),
    "2": ("bug_bounty",   "Bug Bounty",             "OSCP/OSWE-style web application testing"),
    "3": ("red_team",     "Red Teaming",            "APT simulation + MITRE ATT&CK coverage"),
    "4": ("ai_redteam",   "AI Red Teaming",         "OWASP LLM Top 10 + MITRE ATLAS + Agentic AI"),
    "5": ("voice_redteam","Voice Red Teaming",      "IVR bypass + voice biometric + acoustic attacks"),
    "6": ("threat_model", "Threat Modeling",        "STRIDE + PASTA + AI/ATLAS scenarios"),
    "7": ("code_review",  "Secure Code Review",     "SAST + semantic analysis + CWE mapping"),
}

REPORTS_DIR = Path("reports")


class Orchestrator:

    async def run_menu(self) -> None:
        """Main interactive menu loop."""
        while True:
            _print_menu()
            choice = Prompt.ask("[bold cyan]Select module[/bold cyan]", choices=list(MENU.keys()) + ["0", "r"])

            if choice == "0":
                console.print("\n[bold]ARGUS shutting down. Stay safe.[/bold]\n")
                break
            elif choice == "r":
                await self._show_recent_sessions()
            elif choice in MENU:
                await self._run_agent_flow(choice)

    async def _run_agent_flow(self, menu_choice: str) -> None:
        """Full flow: auth gate → agent config → run → report."""
        agent_name, display_name, _ = MENU[menu_choice]
        # Map menu choice to the engagement type string so auth gate
        # skips the redundant "Select engagement type" prompt.
        engagement_type = {
            "1": "Penetration Test",
            "2": "Bug Bounty",
            "3": "Red Team",
            "4": "AI Red Team",
            "5": "Voice Red Team",
            "6": "Threat Model",
            "7": "Secure Code Review",
        }[menu_choice]

        console.print(f"\n[bold cyan]► {display_name}[/bold cyan]\n")

        try:
            auth = await require_authorization(agent_name, engagement_type=engagement_type)
        except Exception as e:
            console.print(f"\n[bold red]Authorization failed: {e}[/bold red]\n")
            return

        agent_config = await self._collect_agent_config(agent_name, auth)

        session = await Session.create(
            target=auth.target,
            scope=auth.scope,
            agent=agent_name,
        )

        console.print(f"\n[dim]Session ID: {session.id}[/dim]")
        console.print(f"[dim]Starting {display_name}...[/dim]\n")

        try:
            findings = await self._dispatch(agent_name, auth, session, agent_config)
        except KeyboardInterrupt:
            console.print("\n[yellow]Engagement interrupted by operator.[/yellow]")
            findings = await self._load_session_findings(session)
        except Exception as e:
            audit.error(agent_name, f"Agent failed: {e}")
            console.print(f"\n[bold red]Agent error: {e}[/bold red]\n")
            findings = []

        await session.close()

        if findings:
            await self._generate_report(agent_name, auth, session, findings)
        else:
            console.print("\n[dim]No findings to report.[/dim]\n")

    async def _dispatch(
        self,
        agent_name: str,
        auth: AuthRecord,
        session: Session,
        config: dict,
    ) -> list[Finding]:
        """Dynamically import and run the chosen agent."""
        try:
            mod = importlib.import_module(f"agents.{agent_name}")
            agent_cls = getattr(mod, self._to_class_name(agent_name))
        except (ModuleNotFoundError, AttributeError) as e:
            console.print(f"[red]Cannot load agent {agent_name}: {e}[/red]")
            return []

        agent = agent_cls()

        # Build common kwargs all agents accept
        kwargs = {
            "target": auth.target,
            "scope":  auth.scope.to_dict(),
            "auth":   auth.to_dict(),
            "session": session,
        }
        kwargs.update(config)

        return await agent.run(**kwargs)

    async def _collect_agent_config(self, agent_name: str, auth: AuthRecord) -> dict:
        """Collect agent-specific options from the operator."""
        config: dict = {}

        if agent_name == "pentest":
            mode = Prompt.ask(
                "Testing mode",
                choices=["blackbox", "whitebox"],
                default="blackbox",
            )
            config["mode"] = mode
            if mode == "whitebox":
                code_path = Prompt.ask("Path to source code directory", default=".")
                config["code_path"] = code_path

        elif agent_name == "bug_bounty":
            login_url = Prompt.ask("Login URL (blank if none)", default="")
            if login_url:
                config["login_url"] = login_url
                config["username"] = Prompt.ask("Username")
                config["password"] = Prompt.ask("Password", password=True)
            scope_urls_input = Prompt.ask(
                "Additional in-scope URLs (comma-separated, blank for target only)",
                default="",
            )
            if scope_urls_input:
                config["scope_urls"] = [u.strip() for u in scope_urls_input.split(",") if u.strip()]

        elif agent_name == "red_team":
            objective = Prompt.ask(
                "Campaign objective",
                default="Demonstrate persistent access to crown jewels",
            )
            config["objective"] = objective

        elif agent_name == "ai_redteam":
            endpoint = Prompt.ask("Target AI endpoint URL (blank for simulation mode)", default="")
            if endpoint:
                config["endpoint_url"] = endpoint
                api_key = Prompt.ask("Target API key (blank if not required)", default="", password=True)
                if api_key:
                    config["api_key"] = api_key
            system_desc = Prompt.ask(
                "Describe the AI system architecture (blank to auto-detect)",
                default="",
            )
            if system_desc:
                config["system_under_test"] = system_desc

        elif agent_name == "voice_redteam":
            target_number = Prompt.ask(
                "Target phone/SIP/WebSocket endpoint (blank for simulation)",
                default="",
            )
            if target_number:
                config["target_number"] = target_number
            target_type = Prompt.ask(
                "System type",
                choices=["ivr", "voice_assistant", "call_center_ai", "voice_auth"],
                default="ivr",
            )
            config["target_type"] = target_type
            acoustic = False
            if Confirm.ask("Include acoustic attack tests? (requires physical access authorization)", default=False):
                if Confirm.ask("[bold red]Confirm: you have explicit written authorization for physical/acoustic testing?[/bold red]", default=False):
                    acoustic = True
            config["acoustic_authorized"] = acoustic

        elif agent_name == "threat_model":
            system_desc = Prompt.ask("Describe the system to model (architecture, data flows, components)")
            config["system_description"] = system_desc
            is_ai = Confirm.ask("Does the system include AI/ML components?", default=False)
            config["include_ai_threats"] = is_ai

        elif agent_name == "code_review":
            code_path = Prompt.ask("Path to code to review", default=".")
            config["code_path"] = code_path
            language = Prompt.ask(
                "Primary language",
                choices=["python", "javascript", "typescript", "java", "go", "php", "ruby", "auto"],
                default="auto",
            )
            config["language"] = language
            framework = Prompt.ask("Framework (Flask, Django, React, etc. — blank if none)", default="")
            if framework:
                config["framework"] = framework

        return config

    async def _generate_report(
        self,
        agent_name: str,
        auth: AuthRecord,
        session: Session,
        findings: list[Finding],
        extra_meta: dict | None = None,
    ) -> None:
        """Render and save Markdown, JSON, HTML, and PDF reports."""
        REPORTS_DIR.mkdir(exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = auth.target.replace("://", "_").replace("/", "_").replace(".", "_")[:40]
        base_name = f"{timestamp}_{agent_name}_{safe_target}"

        # Recover session context for richer meta
        session_state = {}
        try:
            session_state = await session.get_state() or {}
        except Exception:
            pass

        meta = {
            "agent":          agent_name,
            "target":         auth.target,
            "operator":       getattr(auth, "operator", "ARGUS Operator"),
            "session_id":     session.id,
            "generated_at":   datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "total_findings": len(findings),
            "scope":          getattr(auth, "scope_description", ""),
            "mode":           session_state.get("mode", ""),
            "tech_stack":     session_state.get("tech_stack", []),
            "open_ports":     session_state.get("open_ports", []),
            "sections":       [],
        }

        # Agent-specific extra sections
        meta.update(self._build_agent_meta(agent_name, session_state))
        if extra_meta:
            meta.update(extra_meta)

        md_path   = REPORTS_DIR / f"{base_name}.md"
        json_path = REPORTS_DIR / f"{base_name}.json"
        html_path = REPORTS_DIR / f"{base_name}.html"
        pdf_path  = REPORTS_DIR / f"{base_name}.pdf"

        reporter.save(reporter.render_markdown(findings, meta), md_path)
        reporter.save(reporter.render_json(findings, meta),     json_path)
        reporter.save(reporter.render_html(findings, meta),     html_path)
        pdf_ok = reporter.render_pdf(findings, meta, pdf_path)

        _print_summary(findings, auth.target)
        console.print(f"\n[bold green]✓ Reports saved:[/bold green]")
        console.print(f"  Markdown : [cyan]{md_path}[/cyan]")
        console.print(f"  JSON     : [cyan]{json_path}[/cyan]")
        console.print(f"  HTML     : [cyan]{html_path}[/cyan]")
        if pdf_ok:
            console.print(f"  PDF      : [cyan]{pdf_path}[/cyan]")
        else:
            console.print(f"  PDF      : [dim]skipped (weasyprint unavailable)[/dim]")
        console.print()

    @staticmethod
    def _build_agent_meta(agent_name: str, session_state: dict) -> dict:
        """Build agent-specific metadata sections for the report."""
        extra: dict = {"sections": []}

        if agent_name == "pentest":
            post = session_state.get("pentest_result", {})
            if post:
                extra["mode"] = post.get("mode", "")
            attack_chain = session_state.get("attack_chain", [])
            if attack_chain:
                extra["sections"].append({
                    "title": "Attack Chain Narrative",
                    "type": "text",
                    "content": "\n".join(f"{i+1}. {step}" for i, step in enumerate(attack_chain)),
                })
            bloodhound = session_state.get("bloodhound_paths", [])
            if bloodhound:
                extra["sections"].append({
                    "title": "Active Directory Attack Paths",
                    "type": "text",
                    "content": "\n".join(f"• {p}" for p in bloodhound[:10]),
                })

        elif agent_name == "bug_bounty":
            scope_urls = session_state.get("scope_urls", [])
            if scope_urls:
                extra["sections"].append({
                    "title": "Tested Endpoints",
                    "type": "text",
                    "content": "\n".join(f"• {u}" for u in scope_urls),
                })

        elif agent_name == "red_team":
            objective = session_state.get("objective", "")
            if objective:
                extra["executive_summary"] = (
                    f"Campaign Objective: {objective}\n"
                    + session_state.get("campaign_summary", "")
                )
            detection_gaps = session_state.get("detection_gaps", [])
            if detection_gaps:
                extra["sections"].append({
                    "title": "Detection Gaps",
                    "type": "text",
                    "content": "\n".join(f"• {g}" for g in detection_gaps),
                })

        elif agent_name == "ai_redteam":
            sut = session_state.get("system_under_test", "")
            if sut:
                extra["sections"].append({
                    "title": "AI System Under Test",
                    "type": "text",
                    "content": sut,
                })
            extra["methodology"] = "OWASP LLM Top 10 · MITRE ATLAS · NIST AI RMF 1.0"

        elif agent_name == "voice_redteam":
            ttype = session_state.get("target_type", "")
            extra["sections"].append({
                "title": "Voice System Profile",
                "type": "text",
                "content": f"System Type: {ttype or 'Not specified'}",
            })

        elif agent_name == "threat_model":
            stride = session_state.get("stride_table", [])
            if stride:
                extra["sections"].append({
                    "title": "STRIDE Threat Matrix",
                    "type": "table",
                    "columns": ["Category", "Threat", "Component", "Mitigation", "Risk"],
                    "rows": [[r.get("category",""), r.get("threat",""), r.get("component",""),
                               r.get("mitigation",""), r.get("risk","")] for r in stride],
                })
            sys_desc = session_state.get("system_description", "")
            if sys_desc:
                extra["sections"].insert(0, {
                    "title": "System Description",
                    "type": "text",
                    "content": sys_desc,
                })

        elif agent_name == "code_review":
            code_path = session_state.get("code_path", "")
            language  = session_state.get("language", "")
            framework = session_state.get("framework", "")
            parts = []
            if code_path: parts.append(f"Code Path: {code_path}")
            if language:  parts.append(f"Language: {language}")
            if framework: parts.append(f"Framework: {framework}")
            if parts:
                extra["sections"].append({
                    "title": "Code Review Scope",
                    "type": "text",
                    "content": "\n".join(parts),
                })

        return extra

    async def _load_session_findings(self, session: Session) -> list[Finding]:
        """Load findings from an interrupted session."""
        raw_list = await session.get_findings()
        findings = []
        for d in raw_list:
            try:
                findings.append(Finding.from_dict(d))
            except Exception:
                pass
        return findings

    async def _show_recent_sessions(self) -> None:
        """Display recent engagement sessions."""
        sessions = await Session.list_recent(10)
        if not sessions:
            console.print("\n[dim]No previous sessions found.[/dim]\n")
            return

        table = Table(title="Recent Sessions", border_style="cyan")
        table.add_column("ID", style="dim", width=12)
        table.add_column("Target")
        table.add_column("Agent")
        table.add_column("Status")
        table.add_column("Started")

        for s in sessions:
            table.add_row(
                s["id"][:8] + "...",
                s["target"],
                s["agent"],
                s["status"],
                s["created_at"][:16],
            )

        console.print(table)
        console.print()

    @staticmethod
    def _to_class_name(agent_name: str) -> str:
        """Convert snake_case agent name to PascalCase class name."""
        return "".join(part.capitalize() for part in agent_name.split("_")) + "Agent"


def _print_menu() -> None:
    """Print the ARGUS main menu."""
    banner = (
        "\n"
        "╔══════════════════════════════════════════════════╗\n"
        "║         A R G U S  Security Intelligence         ║\n"
        "║    Autonomous Reconnaissance & General-purpose   ║\n"
        "║         Universal Security System  v1.0          ║\n"
        "╠══════════════════════════════════════════════════╣\n"
        "║  [1]  Penetration Testing   (Black/White Box)    ║\n"
        "║  [2]  Bug Bounty            (Full Attack Chain)  ║\n"
        "║  [3]  Red Teaming           (APT Simulation)     ║\n"
        "║  [4]  AI Red Teaming        (LLM/Agent Attacks)  ║\n"
        "║  [5]  Voice Red Teaming     (Voice AI Attacks)   ║\n"
        "║  [6]  Threat Modeling       (STRIDE + AI/ATLAS)  ║\n"
        "║  [7]  Secure Code Review    (SAST + Semantic)    ║\n"
        "╠══════════════════════════════════════════════════╣\n"
        "║  [r]  Recent Sessions                            ║\n"
        "║  [0]  Exit                                       ║\n"
        "╚══════════════════════════════════════════════════╝"
    )
    console.print(Text(banner, style="bold cyan"))


def _print_summary(findings: list[Finding], target: str) -> None:
    """Print a findings summary table."""
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    table = Table(title=f"Findings Summary — {target}", border_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    style_map = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH:     "red",
        Severity.MEDIUM:   "yellow",
        Severity.LOW:      "green",
        Severity.INFO:     "dim",
    }
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts[sev]:
            table.add_row(sev.value, str(counts[sev]), style=style_map[sev])

    console.print(table)
