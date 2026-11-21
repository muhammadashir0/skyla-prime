"""PRIME PERSONAL OPERATIONS MANAGER workflows (Part VIII §13).

Workflow B: inbox triage + draft replies.
Workflow C: calendar availability + meeting proposal/creation.
Workflow D: research report (fetch → store → summarize via model).
Workflow E: Telegram command handling.
All respect autonomy levels: drafts/preparations at L1, sends only at L2+.
"""
from __future__ import annotations

from ..integrations.calendar import GoogleCalendarConnector
from ..integrations.gmail import GmailConnector
from ..integrations.telegram import TelegramConnector
from ..knowledge.research import fetch_url
from ..knowledge.store import KnowledgeStore
from ..models.base import ChatRequest
from ..models.router import ModelRouter


async def workflow_inbox(gmail: GmailConnector, router: ModelRouter,
                         autonomy_level: int = 1) -> dict:
    """Workflow B — summarize important correspondence and draft replies."""
    summary = await gmail.summarize_inbox()
    important = [m for m in summary["messages"] if "IMPORTANT" in m.get("labels", [])]
    drafts = []
    for msg in important[:3]:
        draft = await gmail.draft_reply(
            msg["id"], f"Thank you for your message regarding '{msg['subject']}'. "
                      f"I will review and respond in detail shortly.")
        drafts.append({"message_id": msg["id"], "subject": msg["subject"], **draft})
    return {"mode": summary["mode"], "total": summary["total"], "unread": summary["unread"],
            "important": important, "drafts": drafts,
            "autonomy_note": "Drafts prepared at Level 1; sending requires Level 2+ authorization."}


async def workflow_meeting(calendar: GoogleCalendarConnector, attendee: str,
                           autonomy_level: int = 1) -> dict:
    """Workflow C — inspect availability and propose/create a meeting."""
    events = await calendar.list_events()
    busy = [{"start": e.get("start", ""), "end": e.get("end", "")} for e in events]
    slots = await calendar.find_slots(busy)
    created = None
    if autonomy_level >= 2 and slots:
        created = await calendar.create_event(
            f"Meeting with {attendee}", f"2026-11-24T{slots[0]['start']}:00Z",
            f"2026-11-24T{slots[0]['end']}:00Z", [attendee])
    return {"mode": calendar.mode, "existing_events": events, "proposed_slots": slots,
            "created": created,
            "autonomy_note": ("Event created (Level 2+)" if created else
                              "Slots proposed only — creation requires Level 2+ authorization.")}


async def workflow_research(url: str, store: KnowledgeStore, router: ModelRouter) -> dict:
    """Workflow D — fetch a source, store it with provenance, summarize it."""
    fetched = await fetch_url(url)
    stored = store.ingest(title=f"Web: {url}", content=fetched["text"],
                          source=url, kind="web", license_="see-source-terms")
    result = await router.chat(ChatRequest(
        system="You are the SKYLA PRIME Research Director. Summarize the evidence "
               "below with citations to the source URL. Flag uncertainty.",
        user=f"Source: {url}\n\nEvidence:\n{fetched['text'][:6000]}",
        task_kind="research"))
    return {"url": url, "stored_document": stored, "injection_flags": fetched["injection_flags"],
            "summary": result.text, "model": result.model, "cost_usd": result.cost_usd}


async def workflow_telegram_command(text: str, telegram: TelegramConnector,
                                    chat_id: str = "mock-chat") -> dict:
    """Workflow E — handle a Telegram command and reply."""
    cmd = text.strip().lower()
    if cmd.startswith("status"):
        reply = "SKYLA PRIME is operational. Use the dashboard for full status."
    elif cmd.startswith("inbox"):
        reply = "Inbox triage available via Workflow B (POST /api/workflows/inbox)."
    elif cmd.startswith("help"):
        reply = ("Commands: status · inbox · help. "
                 "Full task submission is available in the SKYLA PRIME dashboard.")
    else:
        reply = f"Received: '{text}'. Task submission is available in the dashboard."
    return await telegram.send_message(chat_id, reply)
