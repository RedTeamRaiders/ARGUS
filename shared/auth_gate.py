"""
Authorization gate — MUST be called before any active agent runs.
Collects target, scope, and explicit written authorization from the operator.
Raises AuthorizationError if the operator does not confirm.
"""
from __future__ import annotations

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


class AuthGate:
    """Scope enforcement gate called inside agent run() methods."""

    @staticmethod
    def require(scope, target: str) -> None:
        """Raise AuthorizationError if target is out of scope."""
        from shared.session import Scope as _Scope
        if isinstance(scope, dict):
            scope = _Scope.from_dict(scope)
        if not scope.contains(target):
            raise AuthorizationError(f"Target {target!r} is out of scope for this engagement.")


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

# Words/phrases that constitute authorization — intentionally broad to
# handle natural phrasing, common misspellings (autorization), and
# non-native English speakers.
_AUTH_KEYWORDS = [
    "i have permission",
    "i have authorization",
    "i have authoriz",      # covers authorization / autorization / authorised
    "i am authorized",
    "i am authorised",
    "authorized to test",
    "authorised to test",
    "permission to test",
    "i own this",
    "i own the",
    "this is my ",
    "written authorization",
    "written authoriz",
    "written permission",
    "authorized engagement",
    "authorised engagement",
    "i confirm auth",
    "have auth",            # "have auth to test"
    "have perm",            # "have permission"
    "legal auth",
    "explicit auth",
    "explicit perm",
    "scope of work",
    "statement of work",
    "bug bounty",           # being on a bug bounty program is implicit authorization
    "ctf",                  # CTF / capture the flag
    "pentest agreement",
    "rules of engagement",
]


def _validate_authorization_statement(statement: str) -> bool:
    normalized = statement.lower().strip()
    return any(kw in normalized for kw in _AUTH_KEYWORDS)


async def require_authorization(
    agent_name: str,
    engagement_type: str = "",
) -> AuthRecord:
    """
    Interactive authorization gate.

    engagement_type: if provided by the caller (e.g. orchestrator already
    knows the module), skips the engagement type selection prompt.

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

    # Engagement type — skip if already provided by caller
    if not engagement_type:
        console.print("\n[bold]Engagement type:[/bold]")
        for k, v in ENGAGEMENT_TYPES.items():
            console.print(f"  [{k}] {v}")
        eng_choice = Prompt.ask("Select", choices=list(ENGAGEMENT_TYPES.keys()))
        engagement_type = ENGAGEMENT_TYPES[eng_choice]

    # Written authorization statement
    # Skip if ARGUS_TRUSTED_OPERATOR=1 is set (operator has a blanket authorization)
    import os
    if os.getenv("ARGUS_TRUSTED_OPERATOR") == "1":
        auth_statement = "Trusted operator — blanket authorization confirmed via ARGUS_TRUSTED_OPERATOR env var"
    else:
        console.print()
        console.print("[bold yellow]Authorization statement[/bold yellow]")
        console.print(
            "[dim]Confirm you are authorized to test this target.\n"
            'Example: "I have written authorization to test example.com"[/dim]'
        )
        auth_statement = Prompt.ask("Your statement")

        if not _validate_authorization_statement(auth_statement):
            console.print(
                "\n[bold red]✗ Authorization statement is insufficient.[/bold red]\n"
                "[red]Include words like: 'I have authorization', 'I have permission',"
                " 'I own this', 'written authorization', 'bug bounty', 'CTF'[/red]\n"
                "[dim]Or set ARGUS_TRUSTED_OPERATOR=1 in your .env to skip this check.[/dim]"
            )
            raise AuthorizationError("Insufficient authorization statement.")

    # Final confirmation
    console.print()
    console.print(Panel(
        f"[bold]Operator:[/bold]   {operator}\n"
        f"[bold]Target:[/bold]     {target}\n"
        f"[bold]Scope:[/bold]      {', '.join(scope_targets)}\n"
        f"[bold]Exclusions:[/bold] {', '.join(exclusions) or 'none'}\n"
        f"[bold]Type:[/bold]       {engagement_type}\n"
        f"[bold]Statement:[/bold]  {auth_statement}",
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
