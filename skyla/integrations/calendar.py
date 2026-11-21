"""Google Calendar connector — official API with mock fixtures."""
from __future__ import annotations

import httpx

from ..config import get_settings

MOCK_EVENTS = [
    {"id": "mock-ev-1", "summary": "Research meeting", "start": "2026-11-24T10:00:00Z",
     "end": "2026-11-24T11:00:00Z", "attendees": ["professor@example.edu"]},
    {"id": "mock-ev-2", "summary": "Sprint review", "start": "2026-11-26T10:00:00Z",
     "end": "2026-11-26T11:00:00Z", "attendees": []},
]


class GoogleCalendarConnector:
    name = "google-calendar"
    display_name = "Google Calendar"
    capabilities = ["list_events", "check_availability", "create_event",
                    "update_event", "invite", "find_slots"]
    auth = "OAuth2 (Google)"

    def __init__(self):
        s = get_settings()
        self.live = bool(s.google_refresh_token and s.google_oauth_client_id)
        self.mode = "live" if self.live else "mock"
        self.detail = ("Live Google Calendar API" if self.live else
                       "Mock mode — set GOOGLE_OAUTH_* + GOOGLE_REFRESH_TOKEN for live access")
        self._s = s

    async def _access_token(self) -> str:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={"client_id": self._s.google_oauth_client_id,
                      "client_secret": self._s.google_oauth_client_secret,
                      "refresh_token": self._s.google_refresh_token,
                      "grant_type": "refresh_token"})
            resp.raise_for_status()
            return resp.json()["access_token"]

    async def list_events(self, time_min: str = "", time_max: str = "") -> list[dict]:
        if not self.live:
            return MOCK_EVENTS
        token = await self._access_token()
        params = {"calendarId": "primary", "singleEvents": True, "orderBy": "startTime"}
        if time_min:
            params["timeMin"] = time_min
        if time_max:
            params["timeMax"] = time_max
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://www.googleapis.com/calendar/v3/calendars/primary/events",
                params=params, headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()
            return resp.json().get("items", [])

    async def create_event(self, summary: str, start: str, end: str,
                           attendees: list[str] | None = None) -> dict:
        if not self.live:
            return {"mode": "mock", "status": "event-prepared-not-created",
                    "summary": summary, "start": start, "end": end,
                    "attendees": attendees or []}
        token = await self._access_token()
        body = {"summary": summary, "start": {"dateTime": start}, "end": {"dateTime": end}}
        if attendees:
            body["attendees"] = [{"email": a} for a in attendees]
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://www.googleapis.com/calendar/v3/calendars/primary/events",
                json=body, headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()
            return {"mode": "live", "event": resp.json()}

    async def find_slots(self, busy: list[dict], work_start: int = 9, work_end: int = 17) -> list[dict]:
        """Propose free 1-hour slots on a weekday given busy intervals (mock-safe)."""
        slots = []
        for hour in range(work_start, work_end):
            start = f"{hour:02d}:00"
            end = f"{hour+1:02d}:00"
            conflict = any(b.get("start", "") <= start < b.get("end", "") or
                           b.get("start", "") < end <= b.get("end", "")
                           for b in busy)
            if not conflict:
                slots.append({"start": start, "end": end})
        return slots[:5]
