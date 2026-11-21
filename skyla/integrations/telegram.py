"""Telegram connector — Bot API (official). Sends operational notifications
and accepts commands via webhook/polling. Without a bot token it runs in
mock mode (messages are logged, not sent).
"""
from __future__ import annotations

import httpx

from ..config import get_settings


class TelegramConnector:
    name = "telegram"
    display_name = "Telegram (PRIME COMMAND BOT)"
    capabilities = ["send_message", "receive_commands", "task_notifications",
                    "approval_requests", "status_reports"]
    auth = "Bot token"

    def __init__(self):
        s = get_settings()
        self.token = s.telegram_bot_token
        self.live = bool(self.token)
        self.mode = "live" if self.live else "mock"
        self.detail = ("Live Telegram Bot API" if self.live else
                       "Mock mode — set TELEGRAM_BOT_TOKEN for live notifications")

    async def send_message(self, chat_id: str, text: str) -> dict:
        if not self.live:
            return {"mode": "mock", "chat_id": chat_id, "text": text,
                    "status": "logged-not-sent"}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                json={"chat_id": chat_id, "text": text})
            resp.raise_for_status()
            return {"mode": "live", "result": resp.json()}

    async def get_me(self) -> dict:
        if not self.live:
            return {"mode": "mock", "bot": "skyla-prime-mock-bot"}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"https://api.telegram.org/bot{self.token}/getMe")
            resp.raise_for_status()
            return {"mode": "live", "result": resp.json()}
