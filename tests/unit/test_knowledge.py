from skyla.knowledge.store import KnowledgeStore


def test_ingest_and_search(db):
    store = KnowledgeStore(db)
    doc = store.ingest("Battery notes", "Solid-state batteries promise higher energy density.")
    assert doc["id"].startswith("doc_")
    results = store.search("batteries")
    assert results, "FTS search must find ingested content"
    assert results[0]["title"] == "Battery notes"


def test_memory_roundtrip(db):
    store = KnowledgeStore(db)
    store.remember("preferred_language", "English", owner_id="t1", reliability=0.9)
    hits = store.recall("preferred_language", owner_id="t1")
    assert hits and hits[0]["value"] == "English"
    # v0.3.0: memory is tenant-scoped -- another tenant sees nothing.
    assert store.recall("preferred_language", owner_id="t2") == []


def test_memory_requires_tenant(db):
    store = KnowledgeStore(db)
    try:
        store.remember("k", "v", owner_id="")
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("empty tenant must be rejected")
