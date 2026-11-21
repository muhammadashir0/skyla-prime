"""Cross-tenant memory isolation (A-05). Every endpoint x every method.

Mutation: removing the `AND owner_id=?` predicate in db.py makes these FAIL.
"""
import uuid

import pytest
from fastapi.testclient import TestClient

from skyla.api.app import app, auth

client = TestClient(app)


@pytest.fixture()
def users():
    def make(prefix, role="operator"):
        name = f"{prefix}_{uuid.uuid4().hex[:8]}"
        auth.create_user(name, "Tenant-Pass-2026", role)
        r = client.post("/api/auth/login",
                        json={"username": name, "password": "Tenant-Pass-2026"})
        assert r.status_code == 200, r.text
        return {"name": name, "token": r.json()["token"],
                "id": r.json()["user"]["id"]}
    return make


def hdr(u):
    return {"Authorization": f"Bearer {u['token']}"}


def test_owner_is_recorded_on_write(users):
    a = users("alice")
    r = client.post("/api/knowledge/memory",
                    json={"key": "k1", "value": "v1"}, headers=hdr(a))
    assert r.status_code == 200, r.text
    assert r.json()["owner_id"] == a["id"]


def test_cannot_read_other_tenants_memory_by_id(users):
    a, b = users("alice"), users("bob")
    mid = client.post("/api/knowledge/memory", json={"key": "secret", "value": "ALICE-SECRET"},
                      headers=hdr(a)).json()["id"]
    r = client.get(f"/api/knowledge/memory/{mid}", headers=hdr(b))
    assert r.status_code == 404, "foreign memory must be invisible, not forbidden"


def test_cannot_search_other_tenants_memory(users):
    a, b = users("alice"), users("bob")
    client.post("/api/knowledge/memory", json={"key": "secret", "value": "ALICE-SECRET"},
                headers=hdr(a))
    r = client.get("/api/knowledge/memory", params={"q": "ALICE-SECRET"}, headers=hdr(b))
    assert r.status_code == 200
    assert r.json() == [], f"leaked: {r.json()}"


def test_cannot_list_other_tenants_memory(users):
    a, b = users("alice"), users("bob")
    client.post("/api/knowledge/memory", json={"key": "secret", "value": "ALICE-SECRET"},
                headers=hdr(a))
    assert client.get("/api/knowledge/memory", headers=hdr(b)).json() == []


def test_cannot_delete_other_tenants_memory(users):
    a, b = users("alice"), users("bob")
    mid = client.post("/api/knowledge/memory", json={"key": "secret", "value": "x"},
                      headers=hdr(a)).json()["id"]
    assert client.delete(f"/api/knowledge/memory/{mid}", headers=hdr(b)).status_code == 404
    # and Alice's record is untouched
    assert client.get(f"/api/knowledge/memory/{mid}", headers=hdr(a)).status_code == 200


def test_cannot_update_other_tenants_memory(users):
    a, b = users("alice"), users("bob")
    mid = client.post("/api/knowledge/memory", json={"key": "secret", "value": "original"},
                      headers=hdr(a)).json()["id"]
    r = client.patch(f"/api/knowledge/memory/{mid}", json={"value": "TAMPERED"}, headers=hdr(b))
    assert r.status_code == 404
    val = client.get(f"/api/knowledge/memory/{mid}", headers=hdr(a)).json()["value"]
    assert val == "original"


def test_cannot_enumerate_other_tenants_memory_ids(users):
    a, b = users("alice"), users("bob")
    for i in range(3):
        client.post("/api/knowledge/memory", json={"key": f"k{i}", "value": "v"},
                    headers=hdr(a))
    b_ids = set()
    for suffix in ("", "-export"):
        path = "/api/knowledge/memory" + suffix
        r = client.get(path, headers=hdr(b))
        if r.status_code == 200:
            body = r.json()
            rows = body.get("memories", []) if isinstance(body, dict) else body
            b_ids |= {row["id"] for row in rows}
    assert b_ids == set(), f"enumerated foreign ids: {b_ids}"


def test_export_is_tenant_scoped(users):
    a, b = users("alice"), users("bob")
    client.post("/api/knowledge/memory", json={"key": "k", "value": "ALICE"}, headers=hdr(a))
    e = client.get("/api/knowledge/memory-export", headers=hdr(b))
    assert e.status_code == 200
    assert e.json()["count"] == 0
    assert e.json()["memories"] == []


def test_admin_access_follows_documented_policy(users):
    """Policy (documented in MEMORY_TENANT_ISOLATION.md): memory is ALWAYS
    tenant-private, including for administrators. Admins manage principals and
    cannot read user memory content; there is no override path."""
    a = users("alice")
    admin = users("root", role="admin")
    mid = client.post("/api/knowledge/memory", json={"key": "k", "value": "ALICE-PRIVATE"},
                      headers=hdr(a)).json()["id"]
    assert client.get(f"/api/knowledge/memory/{mid}", headers=hdr(admin)).status_code == 404
    assert client.get("/api/knowledge/memory", params={"q": "ALICE-PRIVATE"},
                      headers=hdr(admin)).json() == []


def test_missing_tenant_identity_is_denied(users):
    """A principal without an id cannot touch memory at all."""
    from skyla.knowledge.store import KnowledgeStore
    from skyla.api.app import db
    store = KnowledgeStore(db)
    for call in (lambda: store.remember("k", "v", owner_id=""),
                 lambda: store.recall("k", owner_id=""),
                 lambda: store.forget("mem_x", owner_id=""),
                 lambda: db.export_memories("")):
        with pytest.raises(ValueError):
            call()


def test_unauthenticated_access_denied():
    for method, path in (("get", "/api/knowledge/memory"),
                         ("get", "/api/knowledge/memory/mem_x"),
                         ("post", "/api/knowledge/memory"),
                         ("patch", "/api/knowledge/memory/mem_x"),
                         ("delete", "/api/knowledge/memory/mem_x"),
                         ("get", "/api/knowledge/memory-export")):
        r = getattr(client, method)(path, **({"json": {}} if method in ("post", "patch") else {}))
        assert r.status_code in (401, 422), f"{method} {path} -> {r.status_code}"
