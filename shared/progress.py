"""
Live progress dashboard for ARGUS engagements.
Shows phase, ReAct cycle progress bar, elapsed time, and findings by severity.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from shared.reporter import Severity


@dataclass
class DashboardState:
    target:       str
    agent:        str
    phase:        str      = "Initializing"
    cycles_done:  int      = 0
    cycles_max:   int      = 50
    counts: dict           = field(default_factory=lambda: {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
    })
    last_action:  str      = ""
    started_at:   float    = field(default_factory=time.monotonic)


class LiveDashboard:
    """
    Wraps rich.live.Live to render a real-time engagement dashboard.
    Call update() from the agent's ReAct loop; call stop() when done.
    """

    _SEVERITY_STYLES = {
        "Critical": "bold red",
        "High":     "red",
        "Medium":   "yellow",
        "Low":      "green",
        "Info":     "dim",
    }

    def __init__(self, target: str, agent: str, cycles_max: int = 50) -> None:
        self.state = DashboardState(target=target, agent=agent, cycles_max=cycles_max)
        self._console = Console()
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40, style="cyan", complete_style="bold cyan"),
            TextColumn("[cyan]{task.percentage:>5.1f}%[/cyan] ({task.completed}/{task.total} cycles)"),
            TimeElapsedColumn(),
            console=self._console,
            expand=False,
        )
        self._task_id = self._progress.add_task(
            "ReAct loop", total=cycles_max, completed=0
        )
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=4,
            transient=False,
        )

    def start(self) -> None:
        self._live.start()

    def stop(self) -> None:
        self._live.stop()
        self._print_final_summary()

    def set_phase(self, phase: str) -> None:
        self.state.phase = phase
        self._refresh()

    def set_last_action(self, action: str) -> None:
        self.state.last_action = action[:80]
        self._refresh()

    def tick(self) -> None:
        """Advance one ReAct cycle."""
        self.state.cycles_done = min(self.state.cycles_done + 1, self.state.cycles_max)
        self._progress.update(self._task_id, completed=self.state.cycles_done)
        self._refresh()

    def add_finding(self, severity: str) -> None:
        sev = severity.capitalize() if severity.lower() != "info" else "Info"
        if sev in self.state.counts:
            self.state.counts[sev] += 1
        self._refresh()

    def _refresh(self) -> None:
        self._live.update(self._render())

    def _render(self) -> Panel:
        pct = int(self.state.cycles_done / self.state.cycles_max * 100)

        # ── Header ────────────────────────────────────────────────────────
        header = Text()
        header.append(f"  Target : ", style="dim")
        header.append(f"{self.state.target}\n", style="bold white")
        header.append(f"  Agent  : ", style="dim")
        header.append(f"{self.state.agent}  ", style="bold cyan")
        header.append(f"Phase  : ", style="dim")
        header.append(f"{self.state.phase}\n", style="bold yellow")
        if self.state.last_action:
            header.append(f"  Action : ", style="dim")
            header.append(f"{self.state.last_action}\n", style="italic dim white")

        # ── Findings table ────────────────────────────────────────────────
        findings_table = Table(
            title="Findings",
            title_style="bold white",
            border_style="dim",
            show_header=True,
            header_style="bold",
            expand=False,
            min_width=28,
        )
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Count", justify="center", width=7)

        total = 0
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            count = self.state.counts[sev]
            total += count
            style = self._SEVERITY_STYLES[sev]
            if count > 0:
                findings_table.add_row(
                    Text(sev, style=style),
                    Text(str(count), style=f"bold {style.split()[-1]}"),
                )

        if total == 0:
            findings_table.add_row(Text("—", style="dim"), Text("—", style="dim"))

        total_row = Table.grid(expand=False)
        total_row.add_column()
        total_row.add_row(Text(f"  Total findings: {total}", style="bold white"))

        # ── Body ──────────────────────────────────────────────────────────
        body = Columns([self._progress, findings_table], expand=False, equal=False)

        content = Text()
        content.append_text(header)
        content.append("\n")

        from rich.console import Group as RichGroup
        rendered = RichGroup(header, self._progress, findings_table, total_row)

        return Panel(
            rendered,
            title=f"[bold cyan]ARGUS[/bold cyan] — [dim]{pct}% complete[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )

    def _print_final_summary(self) -> None:
        counts = self.state.counts
        total  = sum(counts.values())

        table = Table(
            title=f"Engagement Complete — {self.state.target}",
            title_style="bold white",
            border_style="bold cyan",
            show_header=True,
            header_style="bold",
        )
        table.add_column("Severity", width=12)
        table.add_column("Count",    justify="center", width=8)

        for sev, style in self._SEVERITY_STYLES.items():
            count = counts[sev]
            if count > 0:
                table.add_row(Text(sev, style=style), Text(str(count), style=f"bold {style.split()[-1]}"))

        table.add_section()
        table.add_row(Text("Total", style="bold white"), Text(str(total), style="bold white"))

        self._console.print()
        self._console.print(table)
        elapsed = time.monotonic() - self.state.started_at
        self._console.print(
            f"  [dim]Completed in {int(elapsed // 60)}m {int(elapsed % 60)}s "
            f"| {self.state.cycles_done} ReAct cycles[/dim]\n"
        )
