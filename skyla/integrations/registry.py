"""PRIME CONNECT — unified connector registry.

Agents discover integrations here instead of hardcoding applications.
Each connector declares capabilities, auth mode and live/mock status.
Connectors without credentials run in explicit MOCK mode with fixture data
— never represented as live (Part XXI §32).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..db import Database


@dataclass
class Connector:
    name: str
    display_name: str
    capabilities: list[str]
    auth: str
    mode: str  # "live" | "mock" | "unconfigured"
    detail: str = ""
    client: object | None = field(default=None, repr=False)


class ConnectorRegistry:
    def __init__(self, db: Database):
        self.db = db
        self._connectors: dict[str, Connector] = {}

    def register(self, connector: Connector) -> None:
        self._connectors[connector.name] = connector
        self.db.set_connector(connector.name, connector.mode, connector.detail)

    def get(self, name: str) -> Connector | None:
        return self._connectors.get(name)

    def list(self) -> list[dict]:
        return [{"name": c.name, "display_name": c.display_name,
                 "capabilities": c.capabilities, "auth": c.auth,
                 "mode": c.mode, "detail": c.detail}
                for c in self._connectors.values()]

    def refresh_status(self) -> None:
        for c in self._connectors.values():
            self.db.set_connector(c.name, c.mode, c.detail)
