"""
coverage_gate.py — generic, taxonomy-agnostic coverage enforcement.

Guarantees a report cannot finalize with untested categories silently
skipped under budget or context pressure. The gate knows only:
  - a manifest: list of CategoryRecord({category_id, applicable_modes})
  - a terminal status per category: CONFIRMED | TESTED_CLEAN | SKIPPED(reason)
  - a finalize-time check() that refuses finalization on any gap

It does NOT know OWASP, STRIDE, ATT&CK, or any other taxonomy. That
knowledge belongs in a manifest loader module (e.g.
shared/manifests/owasp_top10.py) — never here. Other agents (Code Review,
Red Team) are expected to reuse this exact class with their own manifests
in a later pass, so keep it generic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class CoverageStatus(str, Enum):
    CONFIRMED    = "CONFIRMED"     # at least one finding materialized in this category
    TESTED_CLEAN = "TESTED_CLEAN"  # actively tested, nothing found
    SKIPPED      = "SKIPPED"       # not tested — reason required


@dataclass
class CategoryRecord:
    """One manifest entry: a category and which test modes apply to it."""
    category_id:      str
    applicable_modes: list[str] = field(default_factory=list)   # e.g. ["blackbox", "whitebox"]


@dataclass
class StatusEntry:
    status:        CoverageStatus
    reason:        str = ""     # required for SKIPPED, informational otherwise
    finding_count: int = 0
    mode:          str = ""     # which mode produced this status


class CoverageGateError(Exception):
    """Raised by check() when finalization is refused."""


class CoverageGate:
    """
    Tracks terminal coverage status per category for one engagement and
    refuses report finalization if any applicable category has no status
    at all.

    Usage:
        gate = CoverageGate(manifest, engagement_modes=["blackbox"])
        ...
        gate.report("A03:2021", CoverageStatus.CONFIRMED, finding_count=2, mode="blackbox")
        ...
        gate.check()   # raises CoverageGateError if anything is missing
    """

    def __init__(self, manifest: list[CategoryRecord], engagement_modes: list[str]) -> None:
        self._manifest         = manifest
        self._engagement_modes = set(engagement_modes)
        self._status:  dict[str, StatusEntry] = {}
        # Taxonomy-agnostic hook for Part 4's chain detection: any id registered
        # here (a CANDIDATE_CHAIN event id, not a category_id) must also resolve
        # to CONFIRMED or SKIPPED before check() passes. Kept as a separate
        # namespace so category coverage and chain coverage never collide.
        self._chain_events: dict[str, StatusEntry] = {}

    def _applicable(self) -> list[CategoryRecord]:
        """Categories that apply to at least one mode this engagement is running."""
        return [
            c for c in self._manifest
            if set(c.applicable_modes) & self._engagement_modes
        ]

    def report(
        self,
        category_id:   str,
        status:        CoverageStatus,
        reason:        str = "",
        finding_count: int = 0,
        mode:          str = "",
    ) -> None:
        if status == CoverageStatus.SKIPPED and not reason.strip():
            raise ValueError(f"SKIPPED status for {category_id!r} requires a reason.")
        self._status[category_id] = StatusEntry(
            status=status, reason=reason, finding_count=finding_count, mode=mode,
        )

    def get(self, category_id: str) -> Optional[StatusEntry]:
        return self._status.get(category_id)

    def missing(self) -> list[str]:
        """Applicable categories with no reported status at all."""
        return [c.category_id for c in self._applicable() if c.category_id not in self._status]

    # ── Chain-event coverage (wired up fully in Part 4) ────────────────────

    def report_chain_event(self, event_id: str, status: CoverageStatus, reason: str = "") -> None:
        """A CANDIDATE_CHAIN event resolving to CONFIRMED or SKIPPED(reason)."""
        if status == CoverageStatus.SKIPPED and not reason.strip():
            raise ValueError(f"SKIPPED chain event {event_id!r} requires a reason.")
        if status == CoverageStatus.TESTED_CLEAN:
            raise ValueError("Chain events resolve to CONFIRMED or SKIPPED only, not TESTED_CLEAN.")
        self._chain_events[event_id] = StatusEntry(status=status, reason=reason)

    def register_chain_event(self, event_id: str) -> None:
        """Open a pending chain event — must be resolved before check() passes."""
        self._chain_events.setdefault(event_id, StatusEntry(status=None))  # type: ignore[arg-type]

    def pending_chain_events(self) -> list[str]:
        return [eid for eid, entry in self._chain_events.items() if entry.status is None]

    def check(self) -> None:
        """Raise CoverageGateError if any applicable category or open chain event lacks a terminal status."""
        gaps = self.missing()
        pending = self.pending_chain_events()
        if gaps or pending:
            parts = []
            if gaps:
                parts.append(f"{len(gaps)} categor{'y' if len(gaps) == 1 else 'ies'} with no status: {', '.join(gaps)}")
            if pending:
                parts.append(f"{len(pending)} unresolved chain event(s): {', '.join(pending)}")
            raise CoverageGateError("Coverage gate failed — " + "; ".join(parts))

    def matrix(self) -> list[dict]:
        """Rows for the report's Coverage Matrix section."""
        rows = []
        for c in self._applicable():
            entry = self._status.get(c.category_id)
            rows.append({
                "category":      c.category_id,
                "mode":          entry.mode if entry else "",
                "status":        entry.status.value if entry else "NOT_RUN",
                "finding_count": entry.finding_count if entry else 0,
                "reason":        entry.reason if entry else "",
            })
        return rows
