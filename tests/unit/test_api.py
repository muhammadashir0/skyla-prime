from fastapi.testclient import TestClient

from skyla.api.app import app
from tests.conftest import AUTH

client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "local" in r.json()["providers"]
    assert r.json()["version"] == "0.2.0"


def test_auth_required():
    assert client.get("/api/tasks").status_code == 401
    assert client.get("/api/tasks", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_dashboard_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "SKYLA" in r.text


def test_task_flow():
    r = client.post("/api/tasks", json={"instruction": "Summarize the quarterly results", "autonomy_level": 0}, headers=AUTH)
    assert r.status_code == 200
    tid = r.json()["id"]
    for _ in range(20):
        t = client.get(f"/api/tasks/{tid}", headers=AUTH).json()
        if t["status"] in ("completed", "failed"):
            break
    assert t["status"] == "completed"
    assert t["result"]


def test_task_idempotency():
    body = {"instruction": "Idempotent task", "autonomy_level": 0, "idempotency_key": "key-1"}
    r1 = client.post("/api/tasks", json=body, headers=AUTH)
    r2 = client.post("/api/tasks", json=body, headers=AUTH)
    assert r1.json()["id"] == r2.json()["id"]
    assert r2.json()["status"] == "duplicate"


def test_autonomy_ceiling_enforced():
    r = client.post("/api/tasks", json={"instruction": "x", "autonomy_level": 4}, headers=AUTH)
    assert r.status_code == 403


def test_connectors_listed():
    r = client.get("/api/connectors", headers=AUTH)
    assert r.status_code == 200
    names = {c["name"] for c in r.json()}
    assert {"gmail", "google-calendar", "telegram"} <= names


def test_models_registry():
    r = client.get("/api/models", headers=AUTH)
    assert r.status_code == 200
    assert any(m["model_id"] == "skyla-mock-0.1" for m in r.json()["registry"])


def test_knowledge_roundtrip():
    r = client.post("/api/knowledge/documents",
                    json={"title": "API test doc", "content": "Quantum sensors improve navigation accuracy."}, headers=AUTH)
    assert r.status_code == 200
    r2 = client.get("/api/knowledge/search", params={"q": "Quantum"}, headers=AUTH)
    assert r2.status_code == 200
    assert any(d["title"] == "API test doc" for d in r2.json())


def test_workflows_mock_mode():
    r = client.post("/api/workflows/inbox", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["mode"] == "mock"
    r = client.post("/api/workflows/meeting", json={"attendee": "professor@example.edu"}, headers=AUTH)
    assert r.status_code == 200
    assert r.json()["proposed_slots"]
    r = client.post("/api/workflows/telegram", json={"text": "status"}, headers=AUTH)
    assert r.status_code == 200
    assert r.json()["mode"] == "mock"


def test_metrics_endpoint():
    r = client.get("/api/metrics", headers=AUTH)
    assert r.status_code == 200
    assert "counters" in r.json()


def test_providers_health():
    r = client.get("/api/providers/health", headers=AUTH)
    assert r.status_code == 200
    assert any(p["provider"] == "local" for p in r.json())
