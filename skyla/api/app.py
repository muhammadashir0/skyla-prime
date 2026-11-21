"""SKYLA PRIME API — FastAPI application.

Serves the dashboard (static) and the full REST API. All state-changing
endpoints are audit-logged; autonomy levels are enforced server-side.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..agents.registry import list_agents
from ..config import get_settings
from ..core.orchestrator import Orchestrator
from ..db import Database
from ..execution.sandbox import run_python
from ..integrations.calendar import GoogleCalendarConnector
from ..integrations.gmail import GmailConnector
from ..integrations.registry import Connector, ConnectorRegistry
from ..integrations.telegram import TelegramConnector
from ..knowledge.store import KnowledgeStore
from ..models.registry import registry_as_dicts
from ..models.router import ModelRouter, classify_task, route_candidates
from ..security import check_autonomy, require_auth, scan_untrusted
from ..workflows.operations import (workflow_inbox, workflow_meeting,
                                    workflow_research, workflow_telegram_command)

settings = get_settings()
db = Database(settings.db_path)
db.recover_interrupted()
router = ModelRouter()
orchestrator = Orchestrator(db, router)
knowledge = KnowledgeStore(db)
gmail = GmailConnector()
calendar = GoogleCalendarConnector()
telegram = TelegramConnector()

connectors = ConnectorRegistry(db)
for c in (gmail, calendar, telegram):
    connectors.register(Connector(name=c.name, display_name=c.display_name,
                                  capabilities=c.capabilities, auth=c.auth,
                                  mode=c.mode, detail=c.detail, client=c))

app = FastAPI(title="SKYLA PRIME", version="0.1.0")


def _actor(authorization: str | None) -> str:
    return require_auth(authorization, settings.api_token)


class TaskCreate(BaseModel):
    instruction: str
    autonomy_level: int = 0
    title: str | None = None


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


class CodeRun(BaseModel):
    code: str


class ResearchRequest(BaseModel):
    url: str


class MeetingRequest(BaseModel):
    attendee: str
    autonomy_level: int = 1


class TelegramRequest(BaseModel):
    text: str
    chat_id: str = "mock-chat"


# ---------------------------------------------------------------- health
@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.app_name, "version": "0.1.0",
            "providers": sorted(router.providers.keys()),
            "max_autonomy": settings.max_autonomy_level}


# ---------------------------------------------------------------- tasks
@app.post("/api/tasks")
async def create_task(body: TaskCreate, authorization: str | None = Header(None)):
    actor = _actor(authorization)
    check_autonomy(body.autonomy_level, settings.max_autonomy_level)
    flags = scan_untrusted(body.instruction)
    tid = db.create_task(body.title or body.instruction[:60],
                         body.instruction, classify_task(body.instruction),
                         body.autonomy_level)
    db.audit(actor, "task.create", f"{tid} level={body.autonomy_level} flags={flags}",
             body.autonomy_level)
    asyncio.create_task(orchestrator.run_task_async(tid))
    return {"id": tid, "status": "queued", "injection_flags": flags}


@app.get("/api/tasks")
def list_tasks(authorization: str | None = Header(None)):
    _actor(authorization)
    return db.list_tasks()


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str, authorization: str | None = Header(None)):
    _actor(authorization)
    task = db.get_task(task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    return task


# ---------------------------------------------------------------- models
@app.get("/api/models")
def models(authorization: str | None = Header(None)):
    _actor(authorization)
    return {"registry": registry_as_dicts(),
            "configured_providers": sorted(router.providers.keys())}


@app.get("/api/models/route")
def route_preview(kind: str = "general", authorization: str | None = Header(None)):
    _actor(authorization)
    return [{"model_id": e.model_id, "provider": e.provider,
             "quality": e.quality, "cost_in": e.cost_per_1m_in}
            for e in route_candidates(kind)]


# ---------------------------------------------------------------- agents
@app.get("/api/agents")
def agents(authorization: str | None = Header(None)):
    _actor(authorization)
    return list_agents()


# ---------------------------------------------------------------- knowledge
@app.post("/api/knowledge/documents")
def ingest(body: DocumentCreate, authorization: str | None = Header(None)):
    actor = _actor(authorization)
    doc = knowledge.ingest(body.title, body.content, body.source, "text", body.license)
    db.audit(actor, "knowledge.ingest", f"{doc['id']} {body.title}")
    return doc


@app.get("/api/knowledge/search")
def search(q: str, authorization: str | None = Header(None)):
    _actor(authorization)
    return knowledge.search(q)


@app.get("/api/knowledge/documents")
def docs(authorization: str | None = Header(None)):
    _actor(authorization)
    return knowledge.list()


@app.post("/api/knowledge/memory")
def remember(body: MemoryCreate, authorization: str | None = Header(None)):
    actor = _actor(authorization)
    mem = knowledge.remember(body.key, body.value, body.kind, "user", body.reliability)
    db.audit(actor, "memory.set", f"{body.key}")
    return mem


@app.get("/api/knowledge/memory")
def recall(q: str, authorization: str | None = Header(None)):
    _actor(authorization)
    return knowledge.recall(q)


# ---------------------------------------------------------------- execution
@app.post("/api/execute/python")
def execute_python(body: CodeRun, authorization: str | None = Header(None)):
    actor = _actor(authorization)
    check_autonomy(2, settings.max_autonomy_level)
    result = run_python(body.code, settings.sandbox_timeout_s, settings.sandbox_memory_mb)
    db.audit(actor, "execute.python", f"ok={result['ok']}")
    return result


# ---------------------------------------------------------------- connectors
@app.get("/api/connectors")
def list_connectors(authorization: str | None = Header(None)):
    _actor(authorization)
    return connectors.list()


# ---------------------------------------------------------------- workflows
@app.post("/api/workflows/inbox")
async def wf_inbox(authorization: str | None = Header(None)):
    actor = _actor(authorization)
    result = await workflow_inbox(gmail, router, 1)
    db.audit(actor, "workflow.inbox", f"mode={result['mode']}")
    return result


@app.post("/api/workflows/meeting")
async def wf_meeting(body: MeetingRequest, authorization: str | None = Header(None)):
    actor = _actor(authorization)
    check_autonomy(body.autonomy_level, settings.max_autonomy_level)
    result = await workflow_meeting(calendar, body.attendee, body.autonomy_level)
    db.audit(actor, "workflow.meeting", f"attendee={body.attendee} level={body.autonomy_level}",
             body.autonomy_level)
    return result


@app.post("/api/workflows/research")
async def wf_research(body: ResearchRequest, authorization: str | None = Header(None)):
    actor = _actor(authorization)
    result = await workflow_research(body.url, knowledge, router)
    db.audit(actor, "workflow.research", body.url)
    return result


@app.post("/api/workflows/telegram")
async def wf_telegram(body: TelegramRequest, authorization: str | None = Header(None)):
    actor = _actor(authorization)
    result = await workflow_telegram_command(body.text, telegram, body.chat_id)
    db.audit(actor, "workflow.telegram", body.text[:80])
    return result


# ---------------------------------------------------------------- audit
@app.get("/api/audit")
def audit(authorization: str | None = Header(None)):
    _actor(authorization)
    return db.audit_recent(100)


# ---------------------------------------------------------------- dashboard
STATIC = Path(__file__).resolve().parent.parent.parent / "apps" / "web" / "static"
if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/")
def index():
    idx = STATIC / "index.html"
    return FileResponse(str(idx)) if idx.exists() else {"app": "SKYLA PRIME", "docs": "/docs"}
