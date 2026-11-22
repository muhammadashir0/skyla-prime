"""Gmail connector — Google Gmail API (official) with mock fixtures.

Live mode requires: GOOGLE_OAUTH_CLIENT_ID/SECRET + GOOGLE_REFRESH_TOKEN
(OAuth2 refresh flow). Without them the connector serves clearly-labeled
mock data so workflows can be tested end-to-end.
"""
from __future__ import annotations

import httpx
from ..egress_client import client as egress_client

from ..config import get_settings

MOCK_MESSAGES = [
    {"id": "mock-1", "from": "professor@example.edu", "subject": "Meeting next week",
     "snippet": "Could we meet next Tuesday to discuss the research proposal?",
     "labels": ["INBOX", "IMPORTANT"], "unread": True},
    {"id": "mock-2", "from": "team@example.com", "subject": "Sprint review moved",
     "snippet": "The sprint review has been moved to Thursday 10:00.",
     "labels": ["INBOX"], "unread": True},
    {"id": "mock-3", "from": "newsletter@example.com", "subject": "Weekly digest",
     "snippet": "Your weekly digest is ready.",
     "labels": ["INBOX", "CATEGORY_PROMOTIONS"], "unread": False},
]


class GmailConnector:
    name = "gmail"
    display_name = "Gmail"
    capabilities = ["search", "read_thread", "draft_reply", "send", "labels", "summarize"]
    auth = "OAuth2 (Google)"

    def __init__(self):
        s = get_settings()
        self.live = bool(s.google_refresh_token and s.google_oauth_client_id)
        self.mode = "live" if self.live else "mock"
        self.detail = ("Live Gmail API" if self.live else
                       "Mock mode — set GOOGLE_OAUTH_* + GOOGLE_REFRESH_TOKEN for live access")
        self._s = s

    async def _access_token(self) -> str:
        async with egress_client("connector-google", timeout=30) as client:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={"client_id": self._s.google_oauth_client_id,
                      "client_secret": self._s.google_oauth_client_secret,
                      "refresh_token": self._s.google_refresh_token,
                      "grant_type": "refresh_token"})
            resp.raise_for_status()
            return resp.json()["access_token"]

    async def search(self, query: str = "", max_results: int = 10) -> list[dict]:
        if not self.live:
            return [m for m in MOCK_MESSAGES
                    if query.lower() in (m["subject"] + m["snippet"] + m["from"]).lower()][:max_results]
        token = await self._access_token()
        async with egress_client("connector-google", timeout=30) as client:
            resp = await client.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                params={"q": query, "maxResults": max_results},
                headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()
            return resp.json().get("messages", [])

    async def summarize_inbox(self, max_results: int = 10) -> dict:
        msgs = await self.search("", max_results)
        unread = [m for m in msgs if m.get("unread")]
        return {"mode": self.mode, "total": len(msgs), "unread": len(unread),
                "messages": msgs,
                "note": "Mock data" if not self.live else "Live Gmail data"}

    async def draft_reply(self, message_id: str, body: str) -> dict:
        if not self.live:
            return {"mode": "mock", "message_id": message_id, "draft_body": body,
                    "status": "draft-prepared-not-sent"}
        token = await self._access_token()
        async with egress_client("connector-google", timeout=30) as client:
            resp = await client.post(
                "https://gmail.googleapis.com/gmail/v1/users/me/drafts",
                json={"message": {"raw": body}},
                headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()
            return {"mode": "live", "draft": resp.json()}
