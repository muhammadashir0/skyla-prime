"""Audit regression tests (v0.1.0 independent audit, 2026-11-21)."""
from fastapi.testclient import TestClient

from skyla.api.app import app
from skyla.execution.sandbox import run_python

client = TestClient(app)


def test_sandbox_honesty_filesystem_not_blocked():
    """Documents the audited limitation: filesystem is NOT blocked.
    If this ever changes (container isolation), update docs + this test."""
    result = run_python("print(open('/etc/hostname').read().strip())")
    assert result["ok"]  # limitation documented, not a security claim


def test_sandbox_memory_and_timeout_enforced():
    assert not run_python("x = bytearray(2*1024*1024*1024)", memory_mb=256)["ok"]
    assert not run_python("while True: pass", timeout_s=1)["ok"]


def test_execute_api_reports_not_isolated():
    r = client.post("/api/execute/python", json={"code": "print(1)"})
    assert r.status_code == 200
    assert r.json()["isolated"] is False
    assert "NOT a security boundary" in r.json()["warning"]


def test_memory_delete_roundtrip():
    r = client.post("/api/knowledge/memory",
                    json={"key": "audit_del", "value": "to be deleted"})
    mid = r.json()["id"]
    d = client.delete(f"/api/knowledge/memory/{mid}")
    assert d.status_code == 200
    assert client.delete(f"/api/knowledge/memory/{mid}").status_code == 404


def test_auth_enforced_when_token_set(monkeypatch):
    from skyla.api import app as appmod
    monkeypatch.setattr(appmod.settings, "api_token", "test-token-123")
    assert client.get("/api/tasks").status_code == 401
    assert client.get("/api/tasks", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/tasks", headers={"Authorization": "Bearer test-token-123"}).status_code == 200
