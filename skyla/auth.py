"""Identity, sessions, MFA, RBAC and scoped API tokens (WS2).

- Passwords: PBKDF2-HMAC-SHA256 (200k iterations, per-user salt).
- MFA: TOTP (RFC 6238) via stdlib hmac.
- Sessions + API tokens stored as SHA-256 hashes; raw tokens shown once.
- RBAC roles: admin > operator > viewer, with capability sets.
- Legacy SKYLA_API_TOKEN still accepted as an admin token (migration path).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
import uuid

# role -> capabilities
# Per-agent execution capability: an agent may only run for a principal that holds
# "agent:<name>:run". Connector writes need "connector:<name>:write". Both are real,
# separately grantable capabilities -- a scoped token can hold one without the other.
_AGENT_RUN = {f"agent:{name}:run" for name in
              ("executive", "research", "engineering", "operations", "verification")}
_CONNECTOR_WRITE = {f"connector:{name}:write" for name in
                    ("gmail", "google-calendar", "telegram")}

ROLE_CAPABILITIES: dict[str, set[str]] = {
    "admin": {"*"},
    "operator": {"tasks:create", "tasks:read", "knowledge:write", "knowledge:read",
                 "execute", "workflows:run", "connectors:read", "models:read",
                 "agents:read", "audit:read", "memory:write",
                 *_AGENT_RUN, *_CONNECTOR_WRITE},
    "viewer": {"tasks:read", "knowledge:read", "connectors:read", "models:read",
               "agents:read", "audit:read"},
}

ALL_AGENT_RUN = _AGENT_RUN
ALL_CONNECTOR_WRITE = _CONNECTOR_WRITE


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False


# A fixed, valid hash used to make "unknown user" cost the same as "wrong
# password" (audit finding A-12: 3 ms vs 77 ms was a 25x enumeration signal).
_DUMMY_HASH = ("pbkdf2_sha256$200000$00000000000000000000000000000000$"
               "0000000000000000000000000000000000000000000000000000000000000000")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def totp(secret_b32: str, at: float | None = None, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper())
    counter = struct.pack(">Q", int((at or time.time()) // 30))
    hm = hmac.new(key, counter, hashlib.sha1).digest()
    o = hm[-1] & 0x0F
    code = struct.unpack(">I", hm[o:o + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_step(at: float | None = None) -> int:
    return int((at or time.time()) // 30)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    """Stateless verification. Retained for tests/diagnostics only.

    Authentication MUST use AuthService.verify_totp_once(), which additionally
    rejects replays of a code that was already accepted (audit finding A-10).
    """
    now = time.time()
    return any(hmac.compare_digest(totp(secret_b32, now + d * 30), code)
               for d in range(-window, window + 1))


def verify_totp_step(secret_b32: str, code: str, window: int = 1) -> int | None:
    """Return the time-step that matched, or None. Caller enforces monotonicity."""
    now = time.time()
    for d in range(-window, window + 1):
        candidate_at = now + d * 30
        if hmac.compare_digest(totp(secret_b32, candidate_at), code):
            return totp_step(candidate_at)
    return None


def new_mfa_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


class AuthService:
    """User/session/token management on top of Database."""

    def __init__(self, db):
        self.db = db

    # -- users ---------------------------------------------------------
    def create_user(self, username: str, password: str, role: str = "operator") -> dict:
        if role not in ROLE_CAPABILITIES:
            raise ValueError(f"Unknown role: {role}")
        uid = f"user_{uuid.uuid4().hex[:10]}"
        self.db.execute(
            "INSERT INTO users (id,username,password_hash,role,created_at) VALUES (?,?,?,?,?)",
            (uid, username, hash_password(password), role, time.time()))
        return {"id": uid, "username": username, "role": role}

    def get_user(self, username: str) -> dict | None:
        r = self.db.query_one("SELECT * FROM users WHERE username=?", (username,))
        return dict(r) if r else None

    def authenticate(self, username: str, password: str, mfa_code: str | None = None,
                     *, throttle=None, remote: str = "") -> dict | None:
        """Verify credentials, with throttling and MFA replay protection.

        Returns the user row on success, None on any failure. Failures look
        identical to the caller (no user enumeration), and unknown users still
        pay a hash-verification cost so timing does not distinguish them (A-12).
        """
        if throttle is not None:
            throttle.check(username, remote)

        user = self.get_user(username)
        if user is None:
            # Constant-work path: verify against a dummy hash so a missing user
            # costs the same as a wrong password.
            verify_password(password, _DUMMY_HASH)
            if throttle is not None:
                throttle.record_failure(username, remote)
            return None

        if not verify_password(password, user["password_hash"]):
            if throttle is not None:
                throttle.record_failure(username, remote)
            return None

        if user["mfa_enabled"]:
            if not mfa_code:
                if throttle is not None:
                    throttle.record_failure(username, remote)
                return None
            step = verify_totp_step(user["mfa_secret"], mfa_code)
            if step is None:
                if throttle is not None:
                    throttle.record_failure(username, remote)
                return None
            # Replay protection: a code may be used once, and only forward in time.
            if not self._claim_totp_step(user["id"], step):
                self.db.audit(user["username"], "auth.mfa.replay_rejected",
                              f"step={step}")
                if throttle is not None:
                    throttle.record_failure(username, remote)
                return None

        if throttle is not None:
            throttle.record_success(username, remote)
        return user

    def _claim_totp_step(self, user_id: str, step: int) -> bool:
        """Atomically accept a TOTP step only if it is newer than the last used.

        Implemented as a conditional UPDATE: the database decides, so two
        concurrent logins cannot both consume the same code.
        """
        cur = self.db.execute(
            "UPDATE users SET mfa_last_step=? WHERE id=? AND mfa_last_step < ?",
            (step, user_id, step))
        return cur.rowcount == 1

    def enable_mfa(self, user_id: str) -> str:
        secret = new_mfa_secret()
        self.db.execute("UPDATE users SET mfa_secret=?, mfa_enabled=1 WHERE id=?",
                        (secret, user_id))
        return secret

    # -- sessions ------------------------------------------------------
    def create_session(self, user_id: str, ttl_s: int = 8 * 3600) -> str:
        token = "sess_" + secrets.token_urlsafe(32)
        self.db.execute(
            "INSERT INTO sessions (id,user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?,?)",
            (f"sessrec_{uuid.uuid4().hex[:10]}", user_id, _hash_token(token),
             time.time() + ttl_s, time.time()))
        return token

    def resolve_session(self, token: str) -> dict | None:
        r = self.db.query_one(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id"
            " WHERE s.token_hash=? AND s.revoked=0 AND s.expires_at>?",
            (_hash_token(token), time.time()))
        return dict(r) if r else None

    def revoke_session(self, token: str) -> None:
        self.db.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?",
                        (_hash_token(token),))

    # -- scoped API tokens ---------------------------------------------
    def create_api_token(self, user_id: str, scopes: list[str], ttl_s: int = 30 * 86400) -> str:
        token = "skt_" + secrets.token_urlsafe(32)
        self.db.execute(
            "INSERT INTO api_tokens (id,user_id,token_hash,scopes,expires_at,created_at)"
            " VALUES (?,?,?,?,?,?)",
            (f"tok_{uuid.uuid4().hex[:10]}", user_id, _hash_token(token),
             json.dumps(scopes), time.time() + ttl_s, time.time()))
        return token

    def resolve_api_token(self, token: str) -> tuple[dict, list[str]] | None:
        r = self.db.query_one(
            "SELECT u.*, t.scopes AS scopes FROM api_tokens t JOIN users u ON u.id=t.user_id"
            " WHERE t.token_hash=? AND t.revoked=0 AND t.expires_at>?",
            (_hash_token(token), time.time()))
        if not r:
            return None
        d = dict(r)
        return d, json.loads(d.pop("scopes") or "[]")

    def revoke_api_token(self, token: str) -> None:
        self.db.execute("UPDATE api_tokens SET revoked=1 WHERE token_hash=?",
                        (_hash_token(token),))

    # -- per-agent / per-connector permissions ---------------------------
    def grant_agent(self, user_id: str, agent: str) -> None:
        """Grant one agent's run capability (least privilege, per agent)."""
        self._grant(user_id, f"agent:{agent}:run")

    def revoke_agent(self, user_id: str, agent: str) -> None:
        self._revoke(user_id, f"agent:{agent}:run")

    def grant_connector(self, user_id: str, connector: str, write: bool = False) -> None:
        """Grant connector access. `write` is required for external side effects."""
        self._grant(user_id, f"connector:{connector}:write" if write
                    else f"connector:{connector}:read")

    def revoke_connector(self, user_id: str, connector: str) -> None:
        self._revoke(user_id, f"connector:{connector}:write")
        self._revoke(user_id, f"connector:{connector}:read")

    def grants(self, user_id: str) -> list[str]:
        r = self.db.query_one("SELECT grants FROM users WHERE id=?", (user_id,))
        return json.loads(r["grants"] or "[]") if r else []

    # Entries prefixed with "-" are explicit DENIALS. They exist because a role
    # grant would otherwise make per-agent revocation impossible: removing an
    # entry that the role still provides has no effect. An explicit deny always
    # wins over a role grant, so least privilege is truly enforceable.
    def _grant(self, user_id: str, grant: str) -> None:
        current = set(self.grants(user_id))
        current.discard(f"-{grant}")
        current.add(grant)
        self.db.execute("UPDATE users SET grants=? WHERE id=?",
                        (json.dumps(sorted(current)), user_id))

    def _revoke(self, user_id: str, grant: str) -> None:
        current = set(self.grants(user_id))
        current.discard(grant)
        current.add(f"-{grant}")
        self.db.execute("UPDATE users SET grants=? WHERE id=?",
                        (json.dumps(sorted(current)), user_id))

    # -- authorization ---------------------------------------------------
    @staticmethod
    def has_capability(user: dict, capability: str, token_scopes: list[str] | None = None) -> bool:
        """Effective permission = role capability (plus explicit per-agent/connector
        grants, minus explicit denials) AND, for scoped tokens, the token's own
        scope list. An explicit denial always overrides a role or wildcard grant."""
        raw = user.get("grants")
        if isinstance(raw, str):  # value straight from the DB row is JSON text
            try:
                raw = json.loads(raw or "[]")
            except ValueError:
                raw = []
        stored = set(raw or [])
        denied = {g[1:] for g in stored if g.startswith("-")}
        if capability in denied or "*" in denied:
            return False
        caps = set(ROLE_CAPABILITIES.get(user.get("role", ""), set()))
        caps |= {g for g in stored if not g.startswith("-")}
        allowed_by_role = "*" in caps or capability in caps
        if not allowed_by_role:
            return False
        if token_scopes is not None:
            return capability in token_scopes or "*" in token_scopes
        return True


def bootstrap_admin(db, auth: AuthService) -> dict | None:
    """Create the first admin user if none exists. Password from
    SKYLA_ADMIN_PASSWORD env, else a generated one returned once."""
    import os
    if db.query_one("SELECT id FROM users LIMIT 1"):
        return None
    supplied = os.getenv("SKYLA_ADMIN_PASSWORD")
    password = supplied or secrets.token_urlsafe(16)
    user = auth.create_user(os.getenv("SKYLA_ADMIN_USER", "admin"), password, "admin")
    user["generated_password"] = None if supplied else password
    if not supplied:
        # A generated credential must reach the operator out-of-band, never via
        # application logs (logs are shipped, indexed and often shared).
        user["credential_delivery"] = "generated_credential_file"
    return user
