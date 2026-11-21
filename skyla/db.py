"""SQLite persistence layer (WAL mode). PostgreSQL migration path is documented
in docs/TECHNICAL_SPECIFICATION.md — the repository interface below is the
single seam where the backend can be swapped without touching callers."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    instruction TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'general',
    status TEXT NOT NULL DEFAULT 'queued',
    autonomy_level INTEGER NOT NULL DEFAULT 0,
    plan_json TEXT,
    result TEXT,
    verification_json TEXT,
    model_used TEXT,
    cost_usd REAL DEFAULT 0,
    error TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS task_steps (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id),
    idx INTEGER NOT NULL,
    title TEXT NOT NULL,
    agent TEXT NOT NULL DEFAULT 'executive',
    status TEXT NOT NULL DEFAULT 'pending',
    output TEXT,
    model_used TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    autonomy_level INTEGER
);
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'text',
    content TEXT NOT NULL,
    license TEXT DEFAULT 'user-provided',
    hash TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts
    USING fts5(title, content, content='documents', content_rowid='rowid');
CREATE TABLE IF NOT EXISTS memories (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'user',
    reliability REAL NOT NULL DEFAULT 0.5,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS connector_state (
    connector TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    detail TEXT,
    updated_at REAL NOT NULL
);
"""


class Database:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # -- generic helpers -------------------------------------------------
    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- audit -----------------------------------------------------------
    def audit(self, actor: str, action: str, detail: str = "", autonomy_level: int | None = None) -> None:
        self.execute(
            "INSERT INTO audit_log (ts, actor, action, detail, autonomy_level) VALUES (?,?,?,?,?)",
            (time.time(), actor, action, detail, autonomy_level),
        )

    def audit_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return [dict(r) for r in self.query(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    # -- tasks -----------------------------------------------------------
    def create_task(self, title: str, instruction: str, kind: str, autonomy_level: int) -> str:
        tid = f"task_{uuid.uuid4().hex[:10]}"
        now = time.time()
        self.execute(
            "INSERT INTO tasks (id,title,instruction,kind,status,autonomy_level,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (tid, title, instruction, kind, "queued", autonomy_level, now, now))
        return tid

    def update_task(self, tid: str, **fields: Any) -> None:
        cols = []
        vals: list[Any] = []
        for k, v in fields.items():
            if k in ("plan", "verification"):
                cols.append(f"{k}_json=?")
                vals.append(json.dumps(v) if v is not None else None)
            else:
                cols.append(f"{k}=?")
                vals.append(v)
        cols.append("updated_at=?")
        vals.append(time.time())
        vals.append(tid)
        self.execute(f"UPDATE tasks SET {', '.join(cols)} WHERE id=?", tuple(vals))

    def get_task(self, tid: str) -> dict[str, Any] | None:
        r = self.query_one("SELECT * FROM tasks WHERE id=?", (tid,))
        if not r:
            return None
        d = dict(r)
        d["plan"] = json.loads(d.pop("plan_json")) if d["plan_json"] else None
        d["verification"] = json.loads(d.pop("verification_json")) if d["verification_json"] else None
        d["steps"] = [dict(s) for s in self.query(
            "SELECT * FROM task_steps WHERE task_id=? ORDER BY idx", (tid,))]
        return d

    def list_tasks(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            d = dict(r)
            d["plan"] = json.loads(d.pop("plan_json")) if d["plan_json"] else None
            d["verification"] = json.loads(d.pop("verification_json")) if d["verification_json"] else None
            out.append(d)
        return out

    def add_step(self, task_id: str, idx: int, title: str, agent: str) -> str:
        sid = f"step_{uuid.uuid4().hex[:10]}"
        now = time.time()
        self.execute(
            "INSERT INTO task_steps (id,task_id,idx,title,agent,status,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (sid, task_id, idx, title, agent, "pending", now, now))
        return sid

    def update_step(self, sid: str, **fields: Any) -> None:
        cols = ", ".join(f"{k}=?" for k in fields)
        self.execute(f"UPDATE task_steps SET {cols}, updated_at=? WHERE id=?",
                     (*fields.values(), time.time(), sid))

    def recover_interrupted(self) -> int:
        """Mark tasks left 'running' by a previous process as interrupted (resumable)."""
        cur = self.execute(
            "UPDATE tasks SET status='interrupted' WHERE status='running'")
        return cur.rowcount

    # -- documents -------------------------------------------------------
    def add_document(self, title: str, source: str, kind: str, content: str, license_: str) -> str:
        import hashlib
        did = f"doc_{uuid.uuid4().hex[:10]}"
        h = hashlib.sha256(content.encode()).hexdigest()
        self.execute(
            "INSERT INTO documents (id,title,source,kind,content,license,hash,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (did, title, source, kind, content, license_, h, time.time()))
        self.execute(
            "INSERT INTO documents_fts (rowid,title,content) VALUES ((SELECT rowid FROM documents WHERE id=?),?,?)",
            (did, title, content))
        return did

    def search_documents(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        try:
            rows = self.query(
                "SELECT d.id,d.title,d.source,d.kind,d.license,d.hash,"
                " substr(d.content,1,400) AS excerpt FROM documents_fts f"
                " JOIN documents d ON d.rowid=f.rowid WHERE documents_fts MATCH ? LIMIT ?",
                (query, limit))
        except sqlite3.OperationalError:
            rows = self.query(
                "SELECT id,title,source,kind,license,hash,substr(content,1,400) AS excerpt"
                " FROM documents WHERE content LIKE ? OR title LIKE ? LIMIT ?",
                (f"%{query}%", f"%{query}%", limit))
        return [dict(r) for r in rows]

    def list_documents(self, limit: int = 50) -> list[dict[str, Any]]:
        return [dict(r) for r in self.query(
            "SELECT id,title,source,kind,license,hash,created_at FROM documents"
            " ORDER BY created_at DESC LIMIT ?", (limit,))]

    # -- memory ----------------------------------------------------------
    def set_memory(self, kind: str, key: str, value: str, source: str, reliability: float) -> str:
        mid = f"mem_{uuid.uuid4().hex[:10]}"
        now = time.time()
        self.execute(
            "INSERT INTO memories (id,kind,key,value,source,reliability,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (mid, kind, key, value, source, reliability, now, now))
        return mid

    def search_memories(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        return [dict(r) for r in self.query(
            "SELECT * FROM memories WHERE value LIKE ? OR key LIKE ? ORDER BY reliability DESC LIMIT ?",
            (f"%{query}%", f"%{query}%", limit))]

    # -- connectors ------------------------------------------------------
    def set_connector(self, name: str, mode: str, detail: str = "") -> None:
        self.execute(
            "INSERT INTO connector_state (connector,mode,detail,updated_at) VALUES (?,?,?,?)"
            " ON CONFLICT(connector) DO UPDATE SET mode=excluded.mode,detail=excluded.detail,updated_at=excluded.updated_at",
            (name, mode, detail, time.time()))

    def get_connectors(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.query("SELECT * FROM connector_state ORDER BY connector")]
