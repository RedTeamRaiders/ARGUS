#!/usr/bin/env python3
"""
ARGUS — Autonomous Reconnaissance & General-purpose Universal Security System
Entry point.
"""
import asyncio
import sys

from dotenv import load_dotenv
from rich.console import Console
from rich.text import Text

load_dotenv()

console = Console()

ARGUS_BANNER = r"""
[bold cyan]
    ___    ____  ________  _______
   /   |  / __ \/ ____/ / / / ___/
  / /| | / /_/ / / __/ / / /\__ \
 / ___ |/ _, _/ /_/ / /_/ /___/ /
/_/  |_/_/ |_|\____/\____//____/
[/bold cyan][dim]
Autonomous Reconnaissance & General-purpose Universal Security System
Version 1.0 — RedTeamRaiders/ARGUS
[/dim]
[bold yellow]WARNING: For authorized security testing only.
Unauthorized use is illegal. You are responsible for your actions.[/bold yellow]
"""


def _check_dependencies() -> bool:
    """Verify required Python packages are installed."""
    required = [
        ("anthropic",   "anthropic"),
        ("rich",        "rich"),
        ("aiosqlite",   "aiosqlite"),
        ("jinja2",      "Jinja2"),
        ("dotenv",      "python-dotenv"),
    ]
    missing = []
    for module, package in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if missing:
        console.print(f"\n[bold red]Missing required packages:[/bold red] {', '.join(missing)}")
        console.print(f"[dim]Install with: pip install {' '.join(missing)}[/dim]\n")
        return False
    return True


def _check_api_key() -> bool:
    """Warn if ANTHROPIC_API_KEY is not set."""
    import os
    if not os.getenv("ANTHROPIC_API_KEY"):
        console.print("\n[bold red]ANTHROPIC_API_KEY not set.[/bold red]")
        console.print("[dim]Create a .env file with ANTHROPIC_API_KEY=sk-ant-...[/dim]\n")
        return False
    return True


async def main() -> int:
    console.print(Text.from_markup(ARGUS_BANNER))

    if not _check_dependencies():
        return 1

    if not _check_api_key():
        return 1

    # Import here after dependency check
    from orchestrator import Orchestrator
    orch = Orchestrator()
    await orch.run_menu()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(0)
