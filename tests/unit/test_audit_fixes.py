"""Audit regression tests (v0.1.0 audit + v0.2.0 hardening)."""
from fastapi.testclient import TestClient

from skyla.api.app import app
from skyla.execution.sandbox import run_python
from tests.conftest import AUTH

client = TestClient(app)


def test_sandbox_honesty_filesystem_not_blocked():
    """Restricted provider documents its limitation (not a security claim)."""
    result = run_python("print(open('/etc/hostname').read().strip())")
    assert result["ok"]  # limitation documented, not a security claim


def test_sandbox_memory_and_timeout_enforced():
    assert not run_python("x = bytearray(2*1024*1024*1024)", memory_mb=256)["ok"]
    assert not run_python("while True: pass", timeout_s=1)["ok"]


def test_execute_api_reports_provider_honestly():
    r = client.post("/api/execute/python", json={"code": "print(1)"}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert "provider" in body and "isolated" in body
    if body["provider"] == "restricted":
        assert body["isolated"] is False
        assert "NOT a security boundary" in body["warning"]


def test_memory_delete_roundtrip():
    r = client.post("/api/knowledge/memory",
                    json={"key": "audit_del", "value": "to be deleted"}, headers=AUTH)
    mid = r.json()["id"]
    d = client.delete(f"/api/knowledge/memory/{mid}", headers=AUTH)
    assert d.status_code == 200
    assert client.delete(f"/api/knowledge/memory/{mid}", headers=AUTH).status_code == 404
