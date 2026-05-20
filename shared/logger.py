import json
import logging
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, asdict

LOG_DIR = Path(__file__).parent.parent / ".claude"
AUDIT_LOG = LOG_DIR / "audit.log"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ToolCallEntry:
    event: str = "tool_call"
    timestamp: str = ""
    agent: str = ""
    tool: str = ""
    command: str = ""
    target: str = ""
    duration_s: float = 0.0
    success: bool = True
    error: Optional[str] = None


@dataclass
class ClaudeCallEntry:
    event: str = "claude_call"
    timestamp: str = ""
    agent: str = ""
    model: str = ""
    purpose: str = ""       # think / analyze / parse
    tokens_in: int = 0
    tokens_out: int = 0
    cached_tokens: int = 0


@dataclass
class FindingEntry:
    event: str = "finding"
    timestamp: str = ""
    agent: str = ""
    title: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    confirmed: bool = False
    confidence: str = ""


@dataclass
class ScopeCheckEntry:
    event: str = "scope_check"
    timestamp: str = ""
    agent: str = ""
    target: str = ""
    in_scope: bool = False


class AuditLogger:
    """Append-only JSON-lines audit trail for every ARGUS action."""

    def __init__(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        # stdlib logger for console output
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        self._log = logging.getLogger("argus")

    def _write(self, entry: dict) -> None:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def tool_call(
        self,
        agent: str,
        tool: str,
        command: str,
        target: str = "",
        duration_s: float = 0.0,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        entry = ToolCallEntry(
            timestamp=_now(),
            agent=agent,
            tool=tool,
            command=command,
            target=target,
            duration_s=duration_s,
            success=success,
            error=error,
        )
        self._write(asdict(entry))
        level = logging.INFO if success else logging.WARNING
        self._log.log(level, "[%s] %s: %s", agent, tool, str(command)[:120])

    def claude_call(
        self,
        agent: str,
        model: str,
        purpose: str,
        tokens_in: int = 0,
        tokens_out: int = 0,
        cached_tokens: int = 0,
    ) -> None:
        entry = ClaudeCallEntry(
            timestamp=_now(),
            agent=agent,
            model=model,
            purpose=purpose,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cached_tokens=cached_tokens,
        )
        self._write(asdict(entry))
        self._log.info(
            "[%s] claude/%s (%s) in=%d out=%d cached=%d",
            agent, model.split("-")[1], purpose, tokens_in, tokens_out, cached_tokens,
        )

    def finding(self, agent: str, title: str, severity: str,
                cvss_score: float, confirmed: bool, confidence: str) -> None:
        entry = FindingEntry(
            timestamp=_now(),
            agent=agent,
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            confirmed=confirmed,
            confidence=confidence,
        )
        self._write(asdict(entry))
        icon = "🔴" if severity in ("Critical", "High") else "🟡" if severity == "Medium" else "🔵"
        self._log.info("%s [%s] %s | %s (confirmed=%s)", icon, severity, title, agent, confirmed)

    def scope_check(self, agent: str, target: str, in_scope: bool) -> None:
        entry = ScopeCheckEntry(
            timestamp=_now(), agent=agent, target=target, in_scope=in_scope
        )
        self._write(asdict(entry))
        if not in_scope:
            self._log.warning("[%s] OUT-OF-SCOPE blocked: %s", agent, target)

    def info(self, agent: str, message: str) -> None:
        self._write({"event": "info", "timestamp": _now(), "agent": agent, "message": message})
        self._log.info("[%s] %s", agent, message)

    def error(self, agent: str, message: str, exc: Optional[Exception] = None) -> None:
        self._write({
            "event": "error", "timestamp": _now(), "agent": agent,
            "message": message, "exception": str(exc) if exc else None,
        })
        self._log.error("[%s] %s%s", agent, message, f" | {exc}" if exc else "")

    def token_summary(self) -> dict[str, Any]:
        """Reads audit log and returns cumulative token usage — for quota tracking."""
        totals: dict[str, int] = {"tokens_in": 0, "tokens_out": 0, "cached_tokens": 0, "claude_calls": 0}
        if not AUDIT_LOG.exists():
            return totals
        with open(AUDIT_LOG) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry.get("event") == "claude_call":
                        totals["tokens_in"]     += entry.get("tokens_in", 0)
                        totals["tokens_out"]    += entry.get("tokens_out", 0)
                        totals["cached_tokens"] += entry.get("cached_tokens", 0)
                        totals["claude_calls"]  += 1
                except json.JSONDecodeError:
                    continue
        return totals


# Global singleton — import and use everywhere
audit = AuditLogger()
