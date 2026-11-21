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
    store.remember("preferred_language", "English", reliability=0.9)
    hits = store.recall("preferred_language")
    assert hits and hits[0]["value"] == "English"
