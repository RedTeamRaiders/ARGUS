"""
Authorization gate — MUST be called before any active agent runs.
Collects target, scope, and explicit written authorization from the operator.
Raises AuthorizationError if the operator does not confirm.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.text import Text

from shared.session import Scope
from shared.logger import audit

console = Console()


class AuthorizationError(Exception):
    """Raised when authorization is not granted or scope is invalid."""


@dataclass
class AuthRecord:
    """Immutable record of operator authorization — attached to every session."""
    operator:       str
    target:         str
    scope:          Scope
    engagement_type: str
    authorization_statement: str
    authorized_at:  str

    def to_dict(self) -> dict:
        return {
            "operator": self.operator,
            "target": self.target,
            "scope": self.scope.to_dict(),
            "engagement_type": self.engagement_type,
            "authorization_statement": self.authorization_statement,
            "authorized_at": self.authorized_at,
        }


ENGAGEMENT_TYPES = {
    "1": "Penetration Test",
    "2": "Bug Bounty",
    "3": "Red Team",
    "4": "AI Red Team",
    "5": "Voice Red Team",
    "6": "Threat Model",
    "7": "Secure Code Review",
}

# Phrases that constitute written authorization
_AUTH_KEYWORDS = [
    "i have permission",
    "i have authorization",
    "i am authorized",
    "authorized to test",
    "permission to test",
    "i own this",
    "i have written authorization",
    "authorized engagement",
    "i confirm authorization",
]


def _validate_authorization_statement(statement: str) -> bool:
    normalized = statement.lower().strip()
    return any(kw in normalized for kw in _AUTH_KEYWORDS)


async def require_authorization(agent_name: str) -> AuthRecord:
    """
    Interactive authorization gate.
    Returns AuthRecord on success, raises AuthorizationError on failure.
    """
    console.print()
    console.print(Panel(
        Text.from_markup(
            "[bold red]⚠  AUTHORIZATION REQUIRED[/bold red]\n\n"
            "[yellow]ARGUS may only be used against systems you own or have explicit\n"
            "written permission to test. Unauthorized testing is illegal.\n\n"
            "You are responsible for ensuring this engagement is authorized.[/yellow]"
        ),
        border_style="red",
        title="[bold]ARGUS — Authorization Gate[/bold]",
    ))
    console.print()

    # Operator name
    operator = Prompt.ask("[bold]Your name / operator ID[/bold]")
    if not operator.strip():
        raise AuthorizationError("Operator name is required.")

    # Target
    target = Prompt.ask("[bold]Primary target[/bold] (IP, domain, URL, or description)")
    if not target.strip():
        raise AuthorizationError("Target is required.")

    # Scope
    console.print("\n[bold]Scope[/bold] — enter all in-scope assets (comma-separated)")
    console.print("[dim]Examples: 192.168.1.0/24, example.com, *.example.com[/dim]")
    scope_input = Prompt.ask("In-scope targets")
    scope_targets = [s.strip() for s in scope_input.split(",") if s.strip()]
    if not scope_targets:
        raise AuthorizationError("At least one in-scope target is required.")

    console.print("[dim]Exclusions (comma-separated, leave blank if none)[/dim]")
    excl_input = Prompt.ask("Exclusions", default="")
    exclusions = [e.strip() for e in excl_input.split(",") if e.strip()]

    scope = Scope(scope_targets, exclusions)

    # Engagement type
    console.print("\n[bold]Engagement type:[/bold]")
    for k, v in ENGAGEMENT_TYPES.items():
        console.print(f"  [{k}] {v}")
    eng_choice = Prompt.ask("Select", choices=list(ENGAGEMENT_TYPES.keys()))
    engagement_type = ENGAGEMENT_TYPES[eng_choice]

    # Written authorization statement
    console.print()
    console.print("[bold yellow]Authorization statement[/bold yellow]")
    console.print(
        "[dim]Type a statement confirming you have permission to test this target.\n"
        'Example: "I have written authorization to test example.com"[/dim]'
    )
    auth_statement = Prompt.ask("Your statement")

    if not _validate_authorization_statement(auth_statement):
        console.print(
            "\n[bold red]✗ Authorization statement is insufficient.[/bold red]\n"
            "[red]Your statement must confirm you have permission or authorization to test.[/red]"
        )
        raise AuthorizationError("Insufficient authorization statement.")

    # Final confirmation
    console.print()
    console.print(Panel(
        f"[bold]Operator:[/bold]  {operator}\n"
        f"[bold]Target:[/bold]    {target}\n"
        f"[bold]Scope:[/bold]     {', '.join(scope_targets)}\n"
        f"[bold]Exclusions:[/bold] {', '.join(exclusions) or 'none'}\n"
        f"[bold]Type:[/bold]      {engagement_type}\n"
        f"[bold]Statement:[/bold] {auth_statement}",
        title="[bold green]Engagement Summary[/bold green]",
        border_style="green",
    ))

    confirmed = Confirm.ask("\n[bold]Confirm and proceed?[/bold]")
    if not confirmed:
        raise AuthorizationError("Operator cancelled authorization.")

    record = AuthRecord(
        operator=operator,
        target=target,
        scope=scope,
        engagement_type=engagement_type,
        authorization_statement=auth_statement,
        authorized_at=datetime.now(timezone.utc).isoformat(),
    )

    audit.info(agent_name, f"Authorization granted | operator={operator} | target={target} | type={engagement_type}")
    console.print(f"\n[bold green]✓ Authorization recorded. Starting {agent_name}...[/bold green]\n")

    return record
