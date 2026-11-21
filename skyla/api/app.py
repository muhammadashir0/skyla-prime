"""SKYLA PRIME API v0.2.0 — identity, RBAC, idempotency, observability."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..agents.registry import list_agents
from ..auth import AuthService, bootstrap_admin
from ..config import get_settings
from ..core.orchestrator import Orchestrator
from ..core.planner import plan_task
from ..db import MIGRATIONS, Database
from ..dbguard import DatabaseIntegrityError, enforce as enforce_db
from ..execution.providers import get_execution_provider
from ..integrations.calendar import GoogleCalendarConnector
from ..integrations.gmail import GmailConnector
from ..integrations.registry import Connector, ConnectorRegistry
from ..integrations.telegram import TelegramConnector
from ..knowledge.store import KnowledgeStore
from ..models.registry import registry_as_dicts
from ..models.router import ModelRouter, classify_task, route_candidates
from ..observability import get_logger, metrics, new_trace_id, redact
from ..execution.service import CapacityExceeded, governor
from ..security import check_autonomy, scan_untrusted
from ..throttle import LoginBlocked, login_throttle
from ..trust import (AUTHORITY_FLOOR, Provenance, TrustViolation, TrustedText,
                     require_authority, risk_score)
from ..workflows.operations import (workflow_inbox, workflow_meeting,
                                    workflow_research, workflow_telegram_command)

log = get_logger("skyla.api")
settings = get_settings()
# M5 / A-07: classify the database BEFORE any write. Refuse ambiguous or damaged
# states instead of silently creating an empty application database.
try:
    _db_report = enforce_db(
        settings.db_path,
        max_schema_version=max(v for v, _ in MIGRATIONS),
        allow_init=os.getenv("SKYLA_INIT_DB", "1") != "0",
    )
except DatabaseIntegrityError as exc:  # fail closed, loudly, before serving
    raise RuntimeError(f"SKYLA PRIME refused to start: {exc}") from exc

db = Database(settings.db_path)


def _record_usage(provider: str, model: str, in_tok: int, out_tok: int,
                  cost: float, latency_ms: int) -> None:
    """WS6/WS7: every provider call is persisted for cost + latency reporting.
    Wired into OpenAICompatibleProvider via usage_callback below."""
    try:
        db.log_usage(provider, model, in_tok, out_tok, cost, latency_ms)
        metrics.inc("provider_calls")
        metrics.inc("provider_cost_micro_usd", int(cost * 1_000_000))
        metrics.observe("provider_latency_ms", latency_ms)
    except Exception:  # never let telemetry break a completion
        log.exception("usage recording failed")

db.recover_interrupted()
db.recover_interrupted_ledger()
auth = AuthService(db)
boot = bootstrap_admin(db, auth)
if boot and boot.get("generated_password"):
    # Write the one-time credential to a 0600 file instead of the log stream.
    cred_path = Path(settings.db_path).parent / "bootstrap_admin_credential.txt"
    try:
        cred_path.parent.mkdir(parents=True, exist_ok=True)
        cred_path.write_text(
            f"username={boot['username']}\npassword={boot['generated_password']}\n",
            encoding="utf-8")
        cred_path.chmod(0o600)
        log.warning("Bootstrap admin %s created. One-time credential written to %s "
                    "(delete after first login).", boot["username"], cred_path)
    except OSError:
        log.error("Bootstrap admin %s created but the credential file could not be "
                  "written; set SKYLA_ADMIN_PASSWORD and recreate the admin.", boot["username"])
router = ModelRouter()
for _p in router.providers.values():
    if hasattr(_p, "_usage_callback"):
        _p._usage_callback = _record_usage
orchestrator = Orchestrator(db, router)
knowledge = KnowledgeStore(db)
gmail = GmailConnector()
calendar = GoogleCalendarConnector()
telegram = TelegramConnector()
execution = get_execution_provider()

connectors = ConnectorRegistry(db)
for c in (gmail, calendar, telegram):
    connectors.register(Connector(name=c.name, display_name=c.display_name,
                                  capabilities=c.capabilities, auth=c.auth,
                                  mode=c.mode, detail=c.detail, client=c))

app = FastAPI(title="SKYLA PRIME", version="0.2.0")


@app.middleware("http")
async def trace_requests(request: Request, call_next):
    """WS7: per-request trace id + structured access log + latency metric.

    Secrets are never logged: only method, route, status and duration. Error
    bodies are not logged. Every response carries X-Trace-Id for correlation.
    """
    trace_id = new_trace_id()
    t0 = time.time()
    try:
        response = await call_next(request)
    except Exception:
        elapsed = int((time.time() - t0) * 1000)
        metrics.inc("http_errors")
        log.exception("unhandled error trace_id=%s %s %s (%dms)",
                      trace_id, request.method, request.url.path, elapsed)
        raise
    elapsed = int((time.time() - t0) * 1000)
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    metrics.inc("http_requests")
    metrics.observe("http_latency_ms", elapsed)
    if response.status_code >= 500:
        metrics.inc("http_5xx")
    elif response.status_code == 401:
        metrics.inc("http_401")
    elif response.status_code == 403:
        metrics.inc("http_403")
    response.headers["X-Trace-Id"] = trace_id
    log.info("trace_id=%s %s %s -> %d (%dms)", trace_id, request.method,
             path, response.status_code, elapsed)
    return response


# ------------------------------------------------------------------ auth
def _resolve_user(authorization: str | None) -> tuple[dict, list[str] | None]:
    """Resolve Bearer token → (user, scopes|None). Legacy SKYLA_API_TOKEN
    maps to an admin user. Raises 401 when invalid/unset."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")
    token = authorization[len("Bearer "):].strip()
    if settings.api_token and token == settings.api_token:
        return {"id": "legacy-admin", "username": "legacy-admin",
                "role": "admin", "grants": []}, None
    user = auth.resolve_session(token)
    if user:
        return user, None
    resolved = auth.resolve_api_token(token)
    if resolved:
        return resolved
    raise HTTPException(401, "Invalid or expired token")


def _require(authorization: str | None, capability: str,
             scopes: list[str] | None = None) -> dict:
    """Server-side authorization gate. `scopes` is passed when the caller has
    already resolved the token so scoped tokens are honoured."""
    user, resolved_scopes = _resolve_user(authorization)
    if scopes is None:
        scopes = resolved_scopes
    if not auth.has_capability(user, capability, scopes):
        db.audit(user.get("username", "?"), "authz.denied", capability,
                 None)
        raise HTTPException(403, f"Capability '{capability}' required")
    return user


def _visible(user: dict, owner_id: str | None) -> bool:
    """Cross-user isolation: admins see all; others only their own."""
    return user.get("role") == "admin" or (owner_id or "admin") == user.get("id")


def _require_connector_write(user: dict, connector: str, scopes: list[str] | None) -> None:
    """Per-connector write permission -- required before any external side effect."""
    cap = f"connector:{connector}:write"
    if not auth.has_capability(user, cap, scopes):
        raise HTTPException(403, f"Capability '{cap}' required")


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "operator"


class TokenCreate(BaseModel):
    scopes: list[str]
    ttl_days: int = 30


@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request):
    remote = (request.client.host if request.client else "") or ""
    try:
        user = auth.authenticate(body.username, body.password, body.mfa_code,
                                 throttle=login_throttle, remote=remote)
    except LoginBlocked as exc:
        db.audit(body.username, "auth.login.blocked", exc.reason)
        raise HTTPException(429, detail=str(exc),
                           headers={"Retry-After": str(exc.retry_after_s)}) from exc
    if not user:
        raise HTTPException(401, "Invalid credentials or MFA code")
    token = auth.create_session(user["id"])
    db.audit(user["username"], "auth.login", f"user={user['id']}")
    return {"token": token, "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}


@app.post("/api/auth/logout")
def logout(authorization: str | None = Header(None)):
    user, _ = _resolve_user(authorization)
    auth.revoke_session(authorization[len("Bearer "):].strip())
    db.audit(user["username"], "auth.logout", "")
    return {"ok": True}


@app.post("/api/auth/users", status_code=201)
def create_user(body: UserCreate, authorization: str | None = Header(None)):
    admin = _require(authorization, "*")
    try:
        user = auth.create_user(body.username, body.password, body.role)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    db.audit(admin["username"], "auth.user.create", f"{body.username} role={body.role}")
    return user


@app.post("/api/auth/users/{user_id}/mfa")
def enable_mfa(user_id: str, authorization: str | None = Header(None)):
    user = _require(authorization, "*")
    secret = auth.enable_mfa(user_id)
    db.audit(user["username"], "auth.mfa.enable", user_id)
    return {"mfa_secret": secret, "note": "Store securely; shown once."}


@app.post("/api/auth/tokens", status_code=201)
def create_token(body: TokenCreate, authorization: str | None = Header(None)):
    user = _require(authorization, "tasks:read")
    token = auth.create_api_token(user["id"], body.scopes, body.ttl_days * 86400)
    db.audit(user["username"], "auth.token.create", f"scopes={body.scopes}")
    return {"token": token, "note": "Shown once; store securely."}


@app.post("/api/auth/tokens/revoke")
def revoke_token(authorization: str | None = Header(None)):
    user = _require(authorization, "tasks:read")
    auth.revoke_api_token(authorization[len("Bearer "):].strip())
    db.audit(user["username"], "auth.token.revoke", "")
    return {"ok": True}


# ---------------------------------------------------------------- health/metrics
@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.app_name, "version": "0.2.0",
            "providers": sorted(router.providers.keys()),
            "execution": execution.status(),
            "max_autonomy": settings.max_autonomy_level,
            "schema_version": db.schema_version()}


@app.get("/api/metrics")
def get_metrics(authorization: str | None = Header(None)):
    _require(authorization, "audit:read")
    snap = metrics.snapshot()
    snap["usage"] = db.usage_summary()
    snap["connectors"] = connectors.list()
    return snap


@app.get("/api/providers/health")
async def providers_health(authorization: str | None = Header(None)):
    _require(authorization, "models:read")
    results = []
    for name, provider in router.providers.items():
        if hasattr(provider, "health_check"):
            results.append(await provider.health_check())
        else:
            results.append({"provider": name, "status": "MOCK" if name == "local" else "UNKNOWN"})
    return results


# ---------------------------------------------------------------- tasks
class TaskCreate(BaseModel):
    instruction: str
    autonomy_level: int = 0
    title: str | None = None
    idempotency_key: str | None = None


@app.post("/api/tasks")
async def create_task(body: TaskCreate, authorization: str | None = Header(None)):
    user, scopes = _resolve_user(authorization)
    _require(authorization, "tasks:create", scopes)
    check_autonomy(body.autonomy_level, settings.max_autonomy_level)
    if body.idempotency_key:
        fp = hashlib.sha256(body.instruction.encode()).hexdigest()
        claim = db.ledger_begin(body.idempotency_key, fp, "core", "task.create")
        if claim["status"] == "duplicate":
            return {"id": claim["record"].get("provider_response", ""),
                    "status": "duplicate", "note": "Idempotent replay"}
        if claim["status"] == "conflict":
            raise HTTPException(409, "Idempotency key reused with different payload")
    planned_agents = sorted({s_.agent for s_ in plan_task(body.instruction).steps})
    for agent_name in planned_agents:
        if not auth.has_capability(user, f"agent:{agent_name}:run", scopes):
            raise HTTPException(
                403, f"Agent '{agent_name}' is not permitted for this identity")
    # M3: the instruction is authenticated user input and therefore has
    # task:create authority. It is still risk-scored: heavy anomaly counts force
    # an autonomy downgrade rather than being silently ignored.
    instruction = TrustedText(body.instruction, Provenance.AUTHENTICATED_USER,
                              source=user["username"])
    try:
        require_authority([instruction], "task:create")
    except TrustViolation as exc:
        db.audit(user["username"], "task.denied.trust", str(exc)[:120])
        raise HTTPException(403, str(exc)) from exc
    risk = risk_score([instruction])
    if risk["requires_review"] and body.autonomy_level > 0:
        db.audit(user["username"], "task.risk.downgrade",
                 f"score={risk['score']} {risk['anomalies'][:2]}")
        raise HTTPException(403, {
            "error": "risk_review_required",
            "detail": "Instruction scored high risk; re-submit at autonomy_level=0 "
                      "for a read-only plan, or review the content.",
            "risk": risk})

    tid = db.create_task(body.title or body.instruction[:60],
                         body.instruction, classify_task(body.instruction),
                         body.autonomy_level)
    db.execute("UPDATE tasks SET owner_id=? WHERE id=?", (user["id"], tid))
    if body.idempotency_key:
        db.ledger_complete(body.idempotency_key, "completed", tid)
    db.audit(user["username"], "task.create", f"{tid} level={body.autonomy_level} anomalies={len(instruction.anomalies)} risk={risk['score']}",
             body.autonomy_level)
    asyncio.create_task(orchestrator.run_task_async(tid))
    return {"id": tid, "status": "queued",
            "trust": {"provenance": int(instruction.provenance),
                      "label": instruction.label, "anomalies": instruction.anomalies,
                      "risk": risk}}


@app.get("/api/tasks")
def list_tasks(authorization: str | None = Header(None)):
    user = _require(authorization, "tasks:read")
    tasks = db.list_tasks()
    return [t for t in tasks if _visible(user, t.get("owner_id"))]


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str, authorization: str | None = Header(None)):
    user = _require(authorization, "tasks:read")
    task = db.get_task(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if not _visible(user, task.get("owner_id")):
        raise HTTPException(404, "Task not found")  # no existence leak
    return task


# ---------------------------------------------------------------- models/agents
@app.get("/api/models")
def models(authorization: str | None = Header(None)):
    _require(authorization, "models:read")
    return {"registry": registry_as_dicts(),
            "configured_providers": sorted(router.providers.keys())}


@app.get("/api/models/route")
def route_preview(kind: str = "general", authorization: str | None = Header(None)):
    _require(authorization, "models:read")
    return [{"model_id": e.model_id, "provider": e.provider,
             "quality": e.quality, "cost_in": e.cost_per_1m_in}
            for e in route_candidates(kind)]


@app.get("/api/agents")
def agents(authorization: str | None = Header(None)):
    _require(authorization, "agents:read")
    return list_agents()


# ---------------------------------------------------------------- knowledge
class DocumentCreate(BaseModel):
    title: str
    content: str
    source: str = "user-upload"
    license: str = "user-provided"


class MemoryCreate(BaseModel):
    key: str
    value: str
    kind: str = "preference"
    reliability: float = 0.8


@app.post("/api/knowledge/documents")
def ingest(body: DocumentCreate, authorization: str | None = Header(None)):
    user = _require(authorization, "knowledge:write")
    document = TrustedText(body.content, Provenance.UPLOADED_DOC,
                           source=body.source or user["username"])
    doc = knowledge.ingest(body.title, body.content, body.source, "text", body.license)
    doc["trust"] = {"provenance": int(document.provenance),
                    "label": document.label, "anomalies": document.anomalies,
                    "authority": "none (untrusted document)"}
    db.execute("UPDATE documents SET owner_id=? WHERE id=?", (user["id"], doc["id"]))
    db.audit(user["username"], "knowledge.ingest", f"{doc['id']} {body.title}")
    return doc


@app.get("/api/knowledge/search")
def search(q: str, authorization: str | None = Header(None)):
    user = _require(authorization, "knowledge:read")
    return [d for d in knowledge.search(q) if _visible(user, d.get("owner_id"))]


@app.get("/api/knowledge/documents")
def docs(authorization: str | None = Header(None)):
    user = _require(authorization, "knowledge:read")
    return [d for d in knowledge.list() if _visible(user, d.get("owner_id"))]


# ---------------------------------------------------------------- memory (A-05)
# Ownership is enforced IN SQL (db._require_tenant + WHERE owner_id=?), never by
# filtering a general result set. Foreign ids return 404 so existence is private.
class MemoryCreate(BaseModel):
    key: str
    value: str
    kind: str = "preference"
    reliability: float = 0.8


class MemoryUpdate(BaseModel):
    value: str


def _tenant(user: dict) -> str:
    """The tenant identity for memory operations. Deny by default."""
    tid = user.get("id")
    if not tid:
        raise HTTPException(403, "No tenant identity on this principal")
    return tid


@app.post("/api/knowledge/memory")
def remember(body: MemoryCreate, authorization: str | None = Header(None)):
    user, scopes = _resolve_user(authorization)
    _require(authorization, "memory:write", scopes)
    tenant = _tenant(user)
    mem = knowledge.remember(body.key, body.value, owner_id=tenant,
                             kind=body.kind, source="user",
                             reliability=body.reliability)
    db.audit(user["username"], "memory.set", f"{body.key}")
    return mem


@app.get("/api/knowledge/memory")
def recall(q: str = "", authorization: str | None = Header(None)):
    """Search or list memories belonging to the caller's tenant only."""
    user, scopes = _resolve_user(authorization)
    _require(authorization, "knowledge:read", scopes)
    tenant = _tenant(user)
    if q:
        return knowledge.recall(q, owner_id=tenant)
    return knowledge.list_memories(tenant)


@app.get("/api/knowledge/memory/{memory_id}")
def get_memory(memory_id: str, authorization: str | None = Header(None)):
    user, scopes = _resolve_user(authorization)
    _require(authorization, "knowledge:read", scopes)
    mem = knowledge.get_memory(memory_id, owner_id=_tenant(user))
    if not mem:
        raise HTTPException(404, "Memory not found")
    return mem


@app.patch("/api/knowledge/memory/{memory_id}")
def update_memory(memory_id: str, body: MemoryUpdate,
                  authorization: str | None = Header(None)):
    user, scopes = _resolve_user(authorization)
    _require(authorization, "memory:write", scopes)
    if not knowledge.update_memory(memory_id, body.value, owner_id=_tenant(user)):
        db.audit(user["username"], "memory.update.denied", memory_id)
        raise HTTPException(404, "Memory not found")
    db.audit(user["username"], "memory.update", memory_id)
    return {"updated": memory_id}


@app.delete("/api/knowledge/memory/{memory_id}")
def forget(memory_id: str, authorization: str | None = Header(None)):
    user, scopes = _resolve_user(authorization)
    _require(authorization, "memory:write", scopes)
    if not knowledge.forget(memory_id, owner_id=_tenant(user)):
        db.audit(user["username"], "memory.delete.denied", memory_id)
        raise HTTPException(404, "Memory not found")
    db.audit(user["username"], "memory.delete", memory_id)
    return {"deleted": memory_id}


@app.get("/api/knowledge/memory-export")
def export_memory(authorization: str | None = Header(None)):
    """Full tenant export. Scoped in SQL; never includes another tenant's rows."""
    user, scopes = _resolve_user(authorization)
    _require(authorization, "knowledge:read", scopes)
    tenant = _tenant(user)
    rows = knowledge.export_memories(tenant)
    db.audit(user["username"], "memory.export", f"count={len(rows)}")
    return {"owner_id": tenant, "count": len(rows), "memories": rows}


# ---------------------------------------------------------------- execution
class CodeRun(BaseModel):
    code: str
    network: bool = False


@app.post("/api/execute/python")
def execute_python(body: CodeRun, request: Request,
                   authorization: str | None = Header(None)):
    user, scopes = _resolve_user(authorization)
    _require(authorization, "execute", scopes)
    check_autonomy(2, settings.max_autonomy_level)

    # M3: code execution must be authorized by a TRUSTED principal context.
    # The request itself is authentic user input, so it has that authority --
    # but the gate is explicit and would refuse an untrusted-origin action.
    try:
        require_authority([TrustedText(body.code, Provenance.AUTHENTICATED_USER,
                                       source=user["username"])], "execute:code")
    except TrustViolation as exc:
        db.audit(user["username"], "execute.denied.trust", str(exc)[:120])
        raise HTTPException(403, str(exc)) from exc

    if not execution.isolated or not execution.status().get("available", False):
        # Fail closed: never run untrusted code on an uncontained provider.
        db.audit(user["username"], "execute.refused",
                 f"provider={execution.name} isolated={execution.isolated}")
        raise HTTPException(503, {
            "error": "execution_unavailable",
            "detail": ("No contained execution provider is available. Arbitrary code "
                       "execution is refused rather than run unisolated."),
            "provider": execution.status(),
        })

    try:
        with governor:
            memory_mb = governor.clamp_memory(settings.sandbox_memory_mb)
            result = execution.run(body.code, settings.sandbox_timeout_s,
                                   memory_mb, network=body.network)
    except CapacityExceeded as exc:
        metrics.inc("execution_rejected_capacity")
        raise HTTPException(429, detail=str(exc),
                           headers={"Retry-After": "5"}) from exc

    result.update(execution.status())
    result["capacity"] = governor.stats()
    db.audit(user["username"], "execute.python",
             f"provider={execution.name} ok={result['ok']} "
             f"killed={result.get('processes_killed', 0)}")
    return result


# ---------------------------------------------------------------- connectors/workflows
@app.get("/api/connectors")
def list_connectors(authorization: str | None = Header(None)):
    _require(authorization, "connectors:read")
    return connectors.list()


class MeetingRequest(BaseModel):
    attendee: str
    autonomy_level: int = 1
    idempotency_key: str | None = None


class ResearchRequest(BaseModel):
    url: str


class TelegramRequest(BaseModel):
    text: str
    chat_id: str = "mock-chat"
    idempotency_key: str | None = None


def _require_trusted_action(user: dict, action: str, content: str) -> TrustedText:
    """Every consequential action needs a TRUSTED initiating context (M3).

    Content that originated in a document, email, web page, tool output or model
    response can never satisfy this, no matter how it is phrased.
    """
    ctx = TrustedText(content, Provenance.AUTHENTICATED_USER, source=user["username"])
    try:
        require_authority([ctx], action)
    except TrustViolation as exc:
        db.audit(user["username"], f"action.denied.trust.{action}", str(exc)[:120])
        raise HTTPException(403, str(exc)) from exc
    return ctx


def _ledger_guard(key: str | None, fingerprint: str, connector: str, operation: str) -> dict | None:
    """WS3 guard: returns a replay response for a duplicate key, raises 409 on
    fingerprint mismatch, returns None when the caller may proceed.

    A duplicate replays the recorded provider result so the caller sees the same
    outcome as the original request -- no second external write ever happens.
    """
    if not key:
        return None
    claim = db.ledger_begin(key, fingerprint, connector, operation)
    if claim["status"] == "conflict":
        db.audit("system", "idempotency.conflict", f"{connector}.{operation} key={key}")
        raise HTTPException(409, "Idempotency key reused with different payload")
    if claim["status"] == "duplicate":
        rec = claim["record"]
        if rec["state"] == "pending":
            # Another request holds this key and has not finished yet.
            raise HTTPException(409, "Operation with this idempotency key is in flight")
        replay: dict = {}
        if rec.get("provider_response"):
            try:
                replay = json.loads(rec["provider_response"])
            except (ValueError, TypeError):
                replay = {"raw": rec["provider_response"]}
        replay["duplicate"] = True
        replay["idempotency_key"] = key
        replay["original_state"] = rec["state"]
        db.audit("system", "idempotency.replay", f"{connector}.{operation} key={key}")
        return replay
    return None


@app.post("/api/workflows/inbox")
async def wf_inbox(authorization: str | None = Header(None)):
    user = _require(authorization, "workflows:run")
    result = await workflow_inbox(gmail, router, 1)
    db.audit(user["username"], "workflow.inbox", f"mode={result['mode']}")
    return result


@app.post("/api/workflows/meeting")
async def wf_meeting(body: MeetingRequest, authorization: str | None = Header(None)):
    user, scopes = _resolve_user(authorization)
    _require(authorization, "workflows:run", scopes)
    check_autonomy(body.autonomy_level, settings.max_autonomy_level)
    fp = hashlib.sha256(f"{body.attendee}|{body.autonomy_level}".encode()).hexdigest()
    _require_connector_write(user, "google-calendar", scopes)
    _require_trusted_action(user, "connector:write", f"{body.attendee}|{body.autonomy_level}")
    replay = _ledger_guard(body.idempotency_key, fp, "google-calendar", "event.create")
    if replay:
        return replay
    result = await workflow_meeting(calendar, body.attendee, body.autonomy_level)
    if body.idempotency_key:
        db.ledger_complete(body.idempotency_key, "completed", json.dumps(result)[:2000])
    db.audit(user["username"], "workflow.meeting",
             f"attendee={body.attendee} level={body.autonomy_level}", body.autonomy_level)
    return result


@app.post("/api/workflows/research")
async def wf_research(body: ResearchRequest, authorization: str | None = Header(None)):
    user = _require(authorization, "workflows:run")
    result = await workflow_research(body.url, knowledge, router)
    db.audit(user["username"], "workflow.research", body.url)
    return result


@app.post("/api/workflows/telegram")
async def wf_telegram(body: TelegramRequest, authorization: str | None = Header(None)):
    user, scopes = _resolve_user(authorization)
    _require(authorization, "workflows:run", scopes)
    fp = hashlib.sha256(f"{body.chat_id}|{body.text}".encode()).hexdigest()
    _require_connector_write(user, "telegram", scopes)
    _require_trusted_action(user, "connector:write", f"{body.chat_id}|{body.text}")
    replay = _ledger_guard(body.idempotency_key, fp, "telegram", "message.send")
    if replay:
        return replay
    result = await workflow_telegram_command(body.text, telegram, body.chat_id)
    if body.idempotency_key:
        db.ledger_complete(body.idempotency_key, "completed", json.dumps(result)[:2000])
    db.audit(user["username"], "workflow.telegram", body.text[:80])
    return result


class GmailDraftRequest(BaseModel):
    message_id: str
    body: str
    idempotency_key: str | None = None


@app.post("/api/workflows/gmail/draft")
async def wf_gmail_draft(body: GmailDraftRequest, authorization: str | None = Header(None)):
    """External WRITE -> always ledger-guarded (WS3). A duplicate request replays
    the recorded provider result instead of creating a second draft."""
    user, scopes = _resolve_user(authorization)
    _require(authorization, "workflows:run", scopes)
    fp = hashlib.sha256(f"{body.message_id}|{body.body}".encode()).hexdigest()
    _require_connector_write(user, "gmail", scopes)
    _require_trusted_action(user, "connector:write", f"{body.message_id}|{body.body}")
    replay = _ledger_guard(body.idempotency_key, fp, "gmail", "draft.create")
    if replay:
        return replay
    try:
        result = await gmail.draft_reply(body.message_id, body.body)
    except Exception as exc:  # provider failure: record it, do not leave 'pending'
        if body.idempotency_key:
            db.ledger_complete(body.idempotency_key, "failed", json.dumps({"error": str(exc)})[:2000])
        metrics.inc("connector_errors")
        db.audit(user["username"], "workflow.gmail.draft.failed", str(exc)[:120])
        raise HTTPException(502, "Gmail draft creation failed") from exc
    if body.idempotency_key:
        db.ledger_complete(body.idempotency_key, "completed", json.dumps(result)[:2000])
    metrics.inc("external_writes")
    db.audit(user["username"], "workflow.gmail.draft", f"message={body.message_id} mode={result.get('mode')}")
    return result


# ---------------------------------------------------------------- audit
@app.get("/api/audit")
def audit(authorization: str | None = Header(None)):
    _require(authorization, "audit:read")
    return db.audit_recent(100)


# ---------------------------------------------------------------- dashboard
STATIC = Path(__file__).resolve().parent.parent.parent / "apps" / "web" / "static"
if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/")
def index():
    idx = STATIC / "index.html"
    return FileResponse(str(idx)) if idx.exists() else {"app": "SKYLA PRIME", "docs": "/docs"}
