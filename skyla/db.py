"""SQLite persistence layer (WAL mode). PostgreSQL migration path is documented
in docs/TECHNICAL_SPECIFICATION.md — the repository interface below is the
single seam where the backend can be swapped without touching callers."""
from __future__ import annotations

import json
import os
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
    owner_id TEXT NOT NULL DEFAULT '',
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
-- v0.2.0: identity, idempotency ledger, observability
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    mfa_secret TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_last_step INTEGER NOT NULL DEFAULT 0,
    grants TEXT DEFAULT '[]',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL DEFAULT '[]',
    expires_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS action_ledger (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    connector TEXT NOT NULL,
    operation TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    provider_response TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS provider_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ok'
);
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);
"""

# Ordered, versioned migrations (WS5). Each is idempotent (IF NOT EXISTS /
# guarded ALTER). Reversible where feasible; down-migrations documented in
# docs/DATABASE_MIGRATION_PLAN.md.
MIGRATIONS: list[tuple[int, str]] = [
    (1, "baseline v0.1.0 schema"),
    (2, "v0.2.0 identity + ledger + usage tables"),
    (3, "owner_id columns for cross-user isolation"),
    (4, "per-agent/per-connector grants column on users"),
    (5, "memories.owner_id NOT NULL for tenant isolation (A-05)"),
    (6, "users.mfa_last_step for TOTP replay protection (A-10)"),
]

_OWNER_COLUMNS = {"tasks": "owner_id", "documents": "owner_id", "memories": "owner_id"}


def _secure_db_dir(directory: Path) -> None:
    """The database directory must be 0700: it contains credentials-adjacent data."""
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass


class Database:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        _secure_db_dir(Path(path).parent)
        existed = Path(path).exists()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._apply_migrations()
        # Holds password hashes and TOTP secrets: never group/world readable.
        for suffix in ("", "-wal", "-shm"):
            try:
                os.chmod(f"{path}{suffix}", 0o600)
            except OSError:
                pass

    def _apply_migrations(self) -> None:
        """Apply pending schema migrations in order (idempotent)."""
        for version, _desc in MIGRATIONS:
            if self.query_one("SELECT version FROM schema_version WHERE version=?", (version,)):
                continue
            if version == 6:
                cols = [r[1] for r in self.query("PRAGMA table_info(users)")]
                if "mfa_last_step" not in cols:
                    self.execute("ALTER TABLE users ADD COLUMN mfa_last_step INTEGER NOT NULL DEFAULT 0")
            if version == 5:
                cols = [r[1] for r in self.query("PRAGMA table_info(memories)")]
                if "owner_id" not in cols:
                    self.execute("ALTER TABLE memories ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''")
                    # Legacy rows predate tenant isolation; they are owned by the
                    # bootstrap admin, exactly like v0.1.0 task/document rows.
                    self.execute("UPDATE memories SET owner_id='admin' WHERE owner_id=''")
            if version == 4:
                cols = [r[1] for r in self.query("PRAGMA table_info(users)")]
                if "grants" not in cols:
                    self.execute("ALTER TABLE users ADD COLUMN grants TEXT DEFAULT '[]'")
            if version == 3:
                for table, col in _OWNER_COLUMNS.items():
                    cols = [r[1] for r in self.query(f"PRAGMA table_info({table})")]
                    if col not in cols:
                        self.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT DEFAULT 'admin'")
            self.execute("INSERT INTO schema_version (version, applied_at) VALUES (?,?)",
                         (version, time.time()))

    def schema_version(self) -> int:
        r = self.query_one("SELECT MAX(version) AS v FROM schema_version")
        return int(r["v"]) if r and r["v"] else 0

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

    def recover_interrupted_ledger(self) -> int:
        """WS3: ledger entries claimed but never completed (process died mid-write)
        are marked 'unknown'. Their external effect is indeterminate, so a retry
        must reconcile provider state before re-executing (see IDEMPOTENCY_DESIGN.md)."""
        cur = self.execute(
            "UPDATE action_ledger SET state='unknown', updated_at=?"
            " WHERE state='pending'", (time.time(),))
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
    # -- memory (tenant-isolated, A-05) ---------------------------------
    # Every operation takes an explicit tenant. There is no "fetch then filter"
    # path: ownership is part of the WHERE clause so a forgotten check cannot
    # leak rows. An empty tenant is rejected -- deny by default.
    @staticmethod
    def _require_tenant(owner_id: str | None) -> str:
        if not owner_id or not str(owner_id).strip():
            raise ValueError("tenant identity required for memory operations")
        return str(owner_id)

    def set_memory(self, kind: str, key: str, value: str, source: str,
                   reliability: float, owner_id: str) -> str:
        tenant = self._require_tenant(owner_id)
        mid = f"mem_{uuid.uuid4().hex[:10]}"
        now = time.time()
        self.execute(
            "INSERT INTO memories (id,owner_id,kind,key,value,source,reliability,"
            "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (mid, tenant, kind, key, value, source, reliability, now, now))
        return mid

    def get_memory(self, mid: str, owner_id: str) -> dict[str, Any] | None:
        """Fetch one memory, or None if it is not owned by this tenant.

        Returning None (not a 403) keeps existence private.
        """
        tenant = self._require_tenant(owner_id)
        r = self.query_one("SELECT * FROM memories WHERE id=? AND owner_id=?",
                           (mid, tenant))
        return dict(r) if r else None

    def search_memories(self, query: str, owner_id: str,
                        limit: int = 10) -> list[dict[str, Any]]:
        tenant = self._require_tenant(owner_id)
        return [dict(r) for r in self.query(
            "SELECT * FROM memories WHERE owner_id=? AND (value LIKE ? OR key LIKE ?)"
            " ORDER BY reliability DESC LIMIT ?",
            (tenant, f"%{query}%", f"%{query}%", limit))]

    def list_memories(self, owner_id: str, limit: int = 200) -> list[dict[str, Any]]:
        tenant = self._require_tenant(owner_id)
        return [dict(r) for r in self.query(
            "SELECT * FROM memories WHERE owner_id=? ORDER BY created_at DESC LIMIT ?",
            (tenant, limit))]

    def update_memory(self, mid: str, owner_id: str, value: str) -> bool:
        tenant = self._require_tenant(owner_id)
        cur = self.execute(
            "UPDATE memories SET value=?, updated_at=? WHERE id=? AND owner_id=?",
            (value, time.time(), mid, tenant))
        return cur.rowcount > 0

    def delete_memory(self, mid: str, owner_id: str) -> bool:
        tenant = self._require_tenant(owner_id)
        cur = self.execute("DELETE FROM memories WHERE id=? AND owner_id=?",
                           (mid, tenant))
        return cur.rowcount > 0

    def export_memories(self, owner_id: str) -> list[dict[str, Any]]:
        """Full tenant export -- scoped in SQL, identical to list but unbounded."""
        tenant = self._require_tenant(owner_id)
        return [dict(r) for r in self.query(
            "SELECT * FROM memories WHERE owner_id=? ORDER BY created_at", (tenant,))]

    # -- idempotency ledger (WS3) --------------------------------------
    def ledger_begin(self, key: str, fingerprint: str, connector: str, operation: str) -> dict:
        """Atomically claim an idempotency key. Returns {status, record}.

        status is one of:
          new        - this caller owns the action
          duplicate  - the same request was already accepted
          conflict   - the same key was used with a different fingerprint
          in_flight  - another worker holds the claim and has not finished

        v0.2.2: this must be correct ACROSS PROCESSES, not merely within one. The
        previous implementation was check-then-insert: two API workers could both
        read "no row" and both insert, so both would proceed to perform the external
        action. Uniqueness was saved by the UNIQUE constraint, but the loser got an
        uncaught IntegrityError instead of a duplicate result (measured: 5 of 6
        concurrent workers crashed).

        The claim is now a single INSERT whose outcome decides ownership. SQLite
        serialises writers, so exactly one INSERT can succeed; every other caller
        observes the existing row via the IntegrityError path and is told what it
        is. There is no window between check and claim.
        """
        lid = f"op_{uuid.uuid4().hex[:10]}"
        now = time.time()
        try:
            self.execute(
                "INSERT INTO action_ledger (id,idempotency_key,fingerprint,connector,"
                "operation,state,attempts,created_at,updated_at)"
                " VALUES (?,?,?,?,?,?,0,?,?)",
                (lid, key, fingerprint, connector, operation, "pending", now, now))
        except sqlite3.IntegrityError:
            # Lost the race (or the key already existed): read the winner.
            existing = self.query_one(
                "SELECT * FROM action_ledger WHERE idempotency_key=?", (key,))
            if not existing:
                # Constraint fired but no row is visible: do not proceed.
                return {"status": "in_flight", "record": {"id": "", "state": "unknown"}}
            record = dict(existing)
            if existing["fingerprint"] != fingerprint:
                return {"status": "conflict", "record": record}
            if existing["state"] == "pending":
                return {"status": "in_flight", "record": record}
            return {"status": "duplicate", "record": record}
        return {"status": "new", "record": {"id": lid, "state": "pending"}}

    def ledger_complete(self, key: str, state: str, provider_response: str = "") -> None:
        self.execute(
            "UPDATE action_ledger SET state=?, provider_response=?, attempts=attempts+1, updated_at=?"
            " WHERE idempotency_key=?",
            (state, provider_response, time.time(), key))

    def ledger_reap_stale(self, older_than_s: float = 300.0) -> list[str]:
        """Recover claims abandoned by a crashed worker.

        A worker that dies between ledger_begin() and ledger_complete() leaves a
        'pending' row forever, which would block that idempotency key for good.
        Claims older than `older_than_s` are marked 'unknown' so a retry can
        proceed, and the operator can see what was interrupted.
        """
        cutoff = time.time() - older_than_s
        rows = self.query(
            "SELECT idempotency_key FROM action_ledger"
            " WHERE state='pending' AND updated_at < ?", (cutoff,))
        keys = [r["idempotency_key"] for r in rows]
        for key in keys:
            self.execute(
                "UPDATE action_ledger SET state='unknown', updated_at=? "
                "WHERE idempotency_key=? AND state='pending'", (time.time(), key))
        if keys:
            self.audit("system", "idempotency.reaped", f"count={len(keys)}")
        return keys

    def ledger_get(self, key: str) -> dict | None:
        r = self.query_one("SELECT * FROM action_ledger WHERE idempotency_key=?", (key,))
        return dict(r) if r else None

    # -- provider usage (WS6/WS7) --------------------------------------
    def log_usage(self, provider: str, model: str, input_tokens: int, output_tokens: int,
                  cost_usd: float, latency_ms: int, status: str = "ok") -> None:
        self.execute(
            "INSERT INTO provider_usage (ts,provider,model,input_tokens,output_tokens,cost_usd,latency_ms,status)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), provider, model, input_tokens, output_tokens, cost_usd, latency_ms, status))

    def usage_summary(self) -> dict:
        r = self.query_one(
            "SELECT COUNT(*) AS calls, COALESCE(SUM(cost_usd),0) AS cost,"
            " COALESCE(SUM(input_tokens),0) AS in_tok, COALESCE(SUM(output_tokens),0) AS out_tok"
            " FROM provider_usage")
        return dict(r) if r else {}

    # -- connectors ------------------------------------------------------
    def set_connector(self, name: str, mode: str, detail: str = "") -> None:
        self.execute(
            "INSERT INTO connector_state (connector,mode,detail,updated_at) VALUES (?,?,?,?)"
            " ON CONFLICT(connector) DO UPDATE SET mode=excluded.mode,detail=excluded.detail,updated_at=excluded.updated_at",
            (name, mode, detail, time.time()))

    def get_connectors(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.query("SELECT * FROM connector_state ORDER BY connector")]
