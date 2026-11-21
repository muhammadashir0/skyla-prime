from fastapi.testclient import TestClient

from skyla.api.app import app

client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "local" in r.json()["providers"]


def test_dashboard_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "SKYLA" in r.text


def test_task_flow():
    r = client.post("/api/tasks", json={"instruction": "Summarize the quarterly results", "autonomy_level": 0})
    assert r.status_code == 200
    tid = r.json()["id"]
    # background task may still be running; poll briefly
    for _ in range(20):
        t = client.get(f"/api/tasks/{tid}").json()
        if t["status"] in ("completed", "failed"):
            break
    assert t["status"] == "completed"
    assert t["result"]


def test_autonomy_ceiling_enforced():
    r = client.post("/api/tasks", json={"instruction": "x", "autonomy_level": 4})
    assert r.status_code == 403


def test_connectors_listed():
    r = client.get("/api/connectors")
    assert r.status_code == 200
    names = {c["name"] for c in r.json()}
    assert {"gmail", "google-calendar", "telegram"} <= names


def test_models_registry():
    r = client.get("/api/models")
    assert r.status_code == 200
    assert any(m["model_id"] == "skyla-mock-0.1" for m in r.json()["registry"])


def test_knowledge_roundtrip():
    r = client.post("/api/knowledge/documents",
                    json={"title": "API test doc", "content": "Quantum sensors improve navigation accuracy."})
    assert r.status_code == 200
    r2 = client.get("/api/knowledge/search", params={"q": "Quantum"})
    assert r2.status_code == 200
    assert any(d["title"] == "API test doc" for d in r2.json())


def test_workflows_mock_mode():
    r = client.post("/api/workflows/inbox")
    assert r.status_code == 200
    assert r.json()["mode"] == "mock"
    r = client.post("/api/workflows/meeting", json={"attendee": "professor@example.edu"})
    assert r.status_code == 200
    assert r.json()["proposed_slots"]
    r = client.post("/api/workflows/telegram", json={"text": "status"})
    assert r.status_code == 200
    assert r.json()["mode"] == "mock"
