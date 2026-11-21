"""WS2 auth tests: RBAC, sessions, MFA, scoped tokens, cross-user isolation."""
import uuid

from fastapi.testclient import TestClient

from skyla.api.app import app, auth
from skyla.auth import hash_password, new_mfa_secret, totp, verify_password, verify_totp

client = TestClient(app)


def _make_user(username, password, role):
    """Create a uniquely-named user; returns (username, user_row)."""
    name = f"{username}_{uuid.uuid4().hex[:8]}"
    return name, auth.create_user(name, password, role)


def _login(username, password, mfa=None):
    return client.post("/api/auth/login",
                       json={"username": username, "password": password, "mfa_code": mfa})


def _token(username, password, mfa=None):
    r = _login(username, password, mfa)
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_password_hashing():
    h = hash_password("correct horse")
    assert verify_password("correct horse", h)
    assert not verify_password("wrong", h)
    assert "correct horse" not in h


def test_totp_roundtrip():
    secret = new_mfa_secret()
    assert verify_totp(secret, totp(secret))
    assert not verify_totp(secret, "000000")


def test_login_and_session():
    name, _ = _make_user("alice", "pw-alice-123", "operator")
    token = _token(name, "pw-alice-123")
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/tasks", headers=h).status_code == 200
    client.post("/api/auth/logout", headers=h)
    assert client.get("/api/tasks", headers=h).status_code == 401  # session revoked


def test_wrong_password_rejected():
    name, _ = _make_user("bob", "pw-bob-123", "operator")
    assert _login(name, "wrong").status_code == 401
    assert _login("no-such-user", "pw-bob-123").status_code == 401


def test_mfa_enforced():
    name, user = _make_user("carol", "pw-carol-123", "operator")
    secret = auth.enable_mfa(user["id"])
    assert _login(name, "pw-carol-123").status_code == 401          # password only: denied
    assert _login(name, "pw-carol-123", "999999").status_code == 401  # bad code: denied
    assert _login(name, "pw-carol-123", totp(secret)).status_code == 200


def test_rbac_viewer_cannot_create_tasks():
    name, _ = _make_user("dave", "pw-dave-123", "viewer")
    h = {"Authorization": f"Bearer {_token(name, 'pw-dave-123')}"}
    assert client.get("/api/tasks", headers=h).status_code == 200   # read allowed
    assert client.post("/api/tasks", json={"instruction": "x"},
                       headers=h).status_code == 403                # write denied


def test_rbac_operator_cannot_create_users():
    name, _ = _make_user("erin", "pw-erin-123", "operator")
    h = {"Authorization": f"Bearer {_token(name, 'pw-erin-123')}"}
    r = client.post("/api/auth/users",
                    json={"username": "mallory", "password": "pw-mallory-123", "role": "admin"},
                    headers=h)
    assert r.status_code == 403


def test_scoped_token_least_privilege():
    _, user = _make_user("frank", "pw-frank-123", "operator")
    token = auth.create_api_token(user["id"], ["tasks:read"])
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/tasks", headers=h).status_code == 200
    assert client.post("/api/tasks", json={"instruction": "x"}, headers=h).status_code == 403


def test_scoped_token_revocation():
    _, user = _make_user("grace", "pw-grace-123", "operator")
    token = auth.create_api_token(user["id"], ["tasks:read"])
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/tasks", headers=h).status_code == 200
    auth.revoke_api_token(token)
    assert client.get("/api/tasks", headers=h).status_code == 401


def test_cross_user_isolation():
    n1, _ = _make_user("heidi", "pw-heidi-123", "operator")
    n2, _ = _make_user("ivan", "pw-ivan-123", "operator")
    h1 = {"Authorization": f"Bearer {_token(n1, 'pw-heidi-123')}"}
    h2 = {"Authorization": f"Bearer {_token(n2, 'pw-ivan-123')}"}
    tid = client.post("/api/tasks", json={"instruction": "Heidi secret task"},
                      headers=h1).json()["id"]
    # Ivan cannot see Heidi's task: 404, no existence leak
    assert client.get(f"/api/tasks/{tid}", headers=h2).status_code == 404
    assert client.get(f"/api/tasks/{tid}", headers=h1).status_code == 200
    # Ivan's task list must not contain Heidi's task
    assert tid not in [t["id"] for t in client.get("/api/tasks", headers=h2).json()]


def test_admin_sees_all_tasks():
    from tests.conftest import AUTH
    n1, _ = _make_user("judy", "pw-judy-123", "operator")
    h1 = {"Authorization": f"Bearer {_token(n1, 'pw-judy-123')}"}
    tid = client.post("/api/tasks", json={"instruction": "Judy task"}, headers=h1).json()["id"]
    assert client.get(f"/api/tasks/{tid}", headers=AUTH).status_code == 200


# ---- per-agent / per-connector permissions (WS2) ----
def test_per_agent_permission_is_separately_grantable_and_revocable():
    name, user = _make_user("percy", "pw-percy-123", "operator")
    auth.revoke_agent(user["id"], "research")
    h = {"Authorization": f"Bearer {_token(name, 'pw-percy-123')}"}
    # A research task now needs agent:research:run -> denied
    r = client.post("/api/tasks", json={"instruction": "Research the market landscape"}, headers=h)
    assert r.status_code == 403
    assert "research" in r.json()["detail"].lower()
    auth.grant_agent(user["id"], "research")
    r2 = client.post("/api/tasks", json={"instruction": "Research the market landscape"}, headers=h)
    assert r2.status_code == 200


def test_viewer_has_no_agent_run_capability():
    name, _ = _make_user("vera", "pw-vera-123", "viewer")
    h = {"Authorization": f"Bearer {_token(name, 'pw-vera-123')}"}
    assert client.post("/api/tasks", json={"instruction": "Research x"}, headers=h).status_code == 403


def test_connector_write_requires_per_connector_capability():
    name, user = _make_user("carl", "pw-carl-123", "operator")
    auth.revoke_connector(user["id"], "telegram")
    h = {"Authorization": f"Bearer {_token(name, 'pw-carl-123')}"}
    r = client.post("/api/workflows/telegram", json={"text": "status"}, headers=h)
    assert r.status_code == 403
    assert "connector:telegram:write" in r.json()["detail"]
    auth.grant_connector(user["id"], "telegram", write=True)
    assert client.post("/api/workflows/telegram",
                       json={"text": "status"}, headers=h).status_code == 200


def test_scoped_token_cannot_exceed_its_scopes_even_for_admin():
    _, user = _make_user("sam", "pw-sam-123", "admin")
    token = auth.create_api_token(user["id"], ["tasks:read"])
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/tasks", headers=h).status_code == 200
    assert client.post("/api/tasks", json={"instruction": "x"}, headers=h).status_code == 403
    assert client.post("/api/workflows/telegram",
                       json={"text": "x"}, headers=h).status_code == 403


def test_grants_are_persisted():
    _, user = _make_user("gil", "pw-gil-123", "operator")
    auth.revoke_agent(user["id"], "engineering")
    assert "agent:engineering:run" not in auth.grants(user["id"])
    auth.grant_agent(user["id"], "engineering")
    assert "agent:engineering:run" in auth.grants(user["id"])
