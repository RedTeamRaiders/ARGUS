import json
import uuid
import aiosqlite
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from config import SESSION_DB

DB_PATH = SESSION_DB


CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    scope_json  TEXT NOT NULL,
    agent       TEXT NOT NULL,
    status      TEXT DEFAULT 'active',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    agent       TEXT NOT NULL,
    data_json   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS tool_outputs (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    agent       TEXT NOT NULL,
    tool        TEXT NOT NULL,
    command     TEXT NOT NULL,
    output_json TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS context_store (
    session_id  TEXT NOT NULL,
    key         TEXT NOT NULL,
    value_json  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (session_id, key),
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Scope:
    """Defines what is in-scope for an engagement."""

    def __init__(self, targets: list[str], exclusions: list[str] = []) -> None:
        self.targets = [t.strip() for t in targets]
        self.exclusions = [e.strip() for e in exclusions]

    def contains(self, target: str) -> bool:
        target = target.strip()
        for excl in self.exclusions:
            if target == excl or target.endswith(excl):
                return False
        for t in self.targets:
            if target == t or target.endswith(f".{t}") or t in target:
                return True
        return False

    def to_dict(self) -> dict:
        return {"targets": self.targets, "exclusions": self.exclusions}

    @classmethod
    def from_dict(cls, d: dict) -> "Scope":
        return cls(d.get("targets", []), d.get("exclusions", []))

    def __repr__(self) -> str:
        return f"Scope(targets={self.targets}, exclusions={self.exclusions})"


class Session:
    """Async SQLite-backed session. One session per engagement."""

    def __init__(self, session_id: str, target: str, scope: Scope, agent: str) -> None:
        self.id = session_id
        self.target = target
        self.scope = scope
        self.agent = agent

    @classmethod
    async def create(cls, target: str, scope: Scope, agent: str) -> "Session":
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        session_id = str(uuid.uuid4())
        now = _now()
        async with aiosqlite.connect(DB_PATH) as db:
            await db.executescript(CREATE_TABLES)
            await db.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?,?,?)",
                (session_id, target, json.dumps(scope.to_dict()), agent, "active", now, now),
            )
            await db.commit()
        return cls(session_id, target, scope, agent)

    @classmethod
    async def resume(cls, session_id: str) -> Optional["Session"]:
        """Resume an existing session by ID."""
        async with aiosqlite.connect(DB_PATH) as db:
            await db.executescript(CREATE_TABLES)
            async with db.execute(
                "SELECT target, scope_json, agent FROM sessions WHERE id=?", (session_id,)
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        scope = Scope.from_dict(json.loads(row[1]))
        return cls(session_id, row[0], scope, row[2])

    @classmethod
    async def list_recent(cls, limit: int = 10) -> list[dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.executescript(CREATE_TABLES)
            async with db.execute(
                "SELECT id, target, agent, status, created_at FROM sessions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ) as cur:
                rows = await cur.fetchall()
        return [{"id": r[0], "target": r[1], "agent": r[2], "status": r[3], "created_at": r[4]} for r in rows]

    async def add_finding(self, finding_data: dict) -> str:
        finding_id = str(uuid.uuid4())
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?)",
                (finding_id, self.id, self.agent, json.dumps(finding_data), _now()),
            )
            await db.execute(
                "UPDATE sessions SET updated_at=? WHERE id=?", (_now(), self.id)
            )
            await db.commit()
        return finding_id

    async def add_tool_output(self, tool: str, command: str, output: dict) -> None:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO tool_outputs VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), self.id, self.agent, tool, command, json.dumps(output), _now()),
            )
            await db.commit()

    async def set_context(self, key: str, value: Any) -> None:
        """Store a key-value pair in the session mental model."""
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT OR REPLACE INTO context_store VALUES (?,?,?,?)",
                (self.id, key, json.dumps(value), _now()),
            )
            await db.commit()

    async def get_context(self, key: str, default: Any = None) -> Any:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT value_json FROM context_store WHERE session_id=? AND key=?",
                (self.id, key),
            ) as cur:
                row = await cur.fetchone()
        return json.loads(row[0]) if row else default

    async def get_all_context(self) -> dict[str, Any]:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT key, value_json FROM context_store WHERE session_id=?", (self.id,)
            ) as cur:
                rows = await cur.fetchall()
        return {r[0]: json.loads(r[1]) for r in rows}

    async def get_findings(self) -> list[dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT data_json FROM findings WHERE session_id=? ORDER BY created_at",
                (self.id,),
            ) as cur:
                rows = await cur.fetchall()
        return [json.loads(r[0]) for r in rows]

    async def close(self) -> None:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE sessions SET status='completed', updated_at=? WHERE id=?",
                (_now(), self.id),
            )
            await db.commit()
