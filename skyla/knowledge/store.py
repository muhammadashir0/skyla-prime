"""PRIME KNOWLEDGE — document ingestion, full-text retrieval, memory.

MVP uses SQLite FTS5 (full-text) with a documented path to Qdrant/OpenSearch
at scale. Every record carries source, license, hash and provenance.
Retrieval data is kept separate from any future training pipeline.
"""
from __future__ import annotations

import hashlib

from ..db import Database


class KnowledgeStore:
    def __init__(self, db: Database):
        self.db = db

    def ingest(self, title: str, content: str, source: str = "user-upload",
               kind: str = "text", license_: str = "user-provided") -> dict:
        doc_id = self.db.add_document(title, source, kind, content, license_)
        return {"id": doc_id, "title": title, "source": source, "kind": kind,
                "license": license_,
                "hash": hashlib.sha256(content.encode()).hexdigest()[:16]}

    def search(self, query: str, limit: int = 10) -> list[dict]:
        # FTS5 MATCH needs sanitized input; fall back to LIKE on syntax errors.
        safe = " ".join(w.strip('"') for w in query.split() if w.strip())
        return self.db.search_documents(safe or query, limit)

    def list(self, limit: int = 50) -> list[dict]:
        return self.db.list_documents(limit)

    # -- memory ----------------------------------------------------------
    def remember(self, key: str, value: str, kind: str = "preference",
                 source: str = "user", reliability: float = 0.8) -> dict:
        mid = self.db.set_memory(kind, key, value, source, reliability)
        return {"id": mid, "kind": kind, "key": key, "reliability": reliability}

    def recall(self, query: str, limit: int = 10) -> list[dict]:
        return self.db.search_memories(query, limit)
