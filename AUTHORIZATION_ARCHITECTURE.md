# AUTHORIZATION ARCHITECTURE — SKYLA PRIME v0.2.0

**Status:** implemented and tested (`tests/unit/test_auth.py`, 19 tests).
**Scope:** Workstream 2 — identity, sessions, MFA, RBAC, capability authorization,
per-agent / per-connector permissions, scoped tokens, audit, cross-user isolation.

---

## 1. What v0.1.0 had, and why it was insufficient

v0.1.0 authenticated with **one shared bearer token** (`SKYLA_API_TOKEN`). Consequences found in
the audit:

- No identity: the audit log could not attribute an action to a person.
- No authorization: holding the token meant *every* capability, including code execution.
- No revocation: rotating the token required a redeploy and invalidated every client.
- No isolation: every record was visible to every holder.
- No expiry, no MFA, no per-integration limits.

v0.2.0 replaces this with real principals. The legacy token still works — deliberately — but it is
mapped to a named admin principal so it is at least **attributable** and can be retired per
deployment (`SKYLA_API_TOKEN` empty = no legacy access).

## 2. Identity and credential storage

| Concern | Implementation |
|---|---|
| Password hashing | PBKDF2-HMAC-SHA256, 200 000 iterations, per-user 16-byte salt, stored as `pbkdf2_sha256$iters$salt$dk` |
| Password comparison | `hmac.compare_digest` (constant time) |
| MFA | TOTP (RFC 6238), 30 s step, ±1 window, base32 secret, stdlib only (no new dependency) |
| Session token | `sess_` + 32 bytes `secrets.token_urlsafe`; **stored as SHA-256 hash**, never plaintext |
| Session lifetime | 8 h default, `expires_at` enforced in SQL |
| Session revocation | `revoked=1` on logout — immediate, server-side |
| API token | `skt_` + 32 bytes; SHA-256 hash stored; per-token **scope list**; 30-day default expiry; individually revocable |
| Bootstrap admin | created once; password from `SKYLA_ADMIN_PASSWORD`, else generated and written to `data/bootstrap_admin_credential.txt` mode `0600` — **never to the log stream** |

Passwords are never logged, never returned by any endpoint, and never included in audit details.
`skyla/observability.py` additionally redacts `Bearer …`, `api_key=…`, `password=…`, `token=…`
patterns from any log line as defence in depth.

## 3. Roles and capabilities

Roles are *bundles*; the enforcement unit is a **capability string**.

| Capability | admin | operator | viewer |
|---|:--:|:--:|:--:|
| `tasks:read` | ✓ | ✓ | ✓ |
| `tasks:create` | ✓ | ✓ | — |
| `knowledge:read` / `knowledge:write` | ✓ | ✓ / ✓ | ✓ / — |
| `memory:write` | ✓ | ✓ | — |
| `execute` (run code) | ✓ | ✓ | — |
| `workflows:run` | ✓ | ✓ | — |
| `connectors:read`, `models:read`, `agents:read`, `audit:read` | ✓ | ✓ | ✓ |
| `agent:<name>:run` ×5 | ✓ | ✓ | — |
| `connector:<name>:write` ×3 | ✓ | ✓ | — |
| user management (`*`) | ✓ | — | — |

`admin` holds `{"*"}`. New roles can be added only by editing `ROLE_CAPABILITIES` — no role is
created at runtime from user input (an unknown role raises `ValueError`).

## 4. Per-agent and per-connector permissions

Two reason strings, not role names:

```
agent:executive:run  agent:research:run  agent:engineering:run
agent:operations:run agent:verification:run
connector:gmail:write  connector:google-calendar:write  connector:telegram:write
```

- **Agent enforcement (real, not decorative):** before a task is created, the API plans it
  (`plan_task`) and checks `agent:<name>:run` for **every agent in the plan**. An identity without
  `agent:research:run` cannot launch a research task — it gets `403 Agent 'research' is not
  permitted for this identity`, before any model call is made.
- **Connector enforcement:** every endpoint with an external side effect
  (`/api/workflows/gmail/draft`, `/api/workflows/meeting`, `/api/workflows/telegram`) calls
  `_require_connector_write(...)` and returns 403 without the matching `connector:<name>:write`.

**Explicit denies.** Grants are stored per user as a JSON list. An entry prefixed `-` is a denial
and **always wins over a role or wildcard grant**. This exists because otherwise revocation is
impossible for permissions the role itself provides (a real defect caught by the test suite):
removing an entry the role still grants changed nothing. Now `revoke_agent("research")` inserts
`-agent:research:run`, and the effective check consults denials first.

```
effective(cap) = NOT denied(cap or "*")
                 AND (role_caps ∋ cap or role_caps ∋ "*" or grants ∋ cap)
                 AND (token is unscoped OR token_scopes ∋ cap or ∋ "*")
```

## 5. Scoped API tokens — intersection, never escalation

A scoped token grants the **intersection** of (a) the owner's effective permissions and (b) the
token's own scope list. `test_scoped_token_cannot_exceed_its_scopes_even_for_admin` verifies that an
**admin's** token scoped to `["tasks:read"]` can read tasks but is refused task creation and refused
Telegram sends. Tokens are separately revocable and expire.

## 6. Enforcement is server-side, on every protected route

Every non-public route begins with `_require(authorization, capability)` (or
`_resolve_user` + `_require(..., scopes)` where the scope list is needed downstream). There is no
client-side-only check, and no route relies on the UI hiding a control.

Public routes are exactly: `GET /api/health`, `POST /api/auth/login`, `GET /` and `/static/*`.
Everything else returns **401 without a valid credential** — verified in
`test_auth_required` and by probing the running server (`GET /api/tasks` → 401).

Denials are written to the audit log as `authz.denied` with the capability name, so a 403 is
observable, not silent.

## 7. Cross-user data isolation

Owned tables (`tasks`, `documents`, `memories`) carry `owner_id` (migration 3).

- Non-admin principals see and mutate only rows where `owner_id == their user id`.
- Requests for another user's record return **404, not 403** — no existence leak
  (`test_cross_user_isolation`).
- Admins see all rows (operational necessity: incident response, audit).
- Pre-v0.2.0 rows are backfilled to `owner_id='admin'` so nothing becomes unreachable.

## 8. Audit logging

`audit_log` records `ts, actor, action, detail, autonomy_level`. Actor is the **username**, not a
shared token. Recorded events include: `auth.login`, `auth.logout`, `auth.token.revoke`,
`authz.denied`, `task.create`, `execute.python`, `workflow.*`, `idempotency.replay`,
`idempotency.conflict`, `provider.*`.

Secrets are never written to `detail`. Free-text user content is truncated (e.g. 80 chars for
Telegram text) to limit accidental PII retention.

## 9. Threat tests (all passing)

| Attempt | Result |
|---|---|
| No token / wrong token | 401 |
| Valid operator creating an admin user | 403 |
| Viewer creating a task | 403 |
| Viewer reading tasks | 200 (read-only is intended) |
| Operator without `agent:research:run` launching research | 403, named capability in message |
| Operator without `connector:telegram:write` sending Telegram | 403 |
| Admin's narrowly-scoped token attempting a write | 403 |
| Reading another user's task | 404 |
| Revoked session reused | 401 |
| Revoked API token reused | 401 |
| Wrong password / unknown user | 401 (same message, no enumeration) |
| MFA enabled, password only | 401 |
| MFA enabled, wrong code | 401 |
| Legacy shared token | admin, attributable as `legacy-admin` |

## 10. Known limitations (declared, not hidden)

1. **Password policy** is not enforced beyond non-empty — no minimum length/breach-list check yet.
2. **No login rate limiting / lockout.** Should be added at the reverse proxy or in `login()`.
3. **MFA secret storage** is plaintext in the DB (deliberate: TOTP needs the secret to verify).
   Encryption at rest is a deployment concern (disk encryption / managed Postgres).
4. **No refresh-token rotation**; sessions are re-established by logging in again after 8 h.
5. **No SSO/OIDC.** Not implemented; no document claims it.
6. **Legacy token maps to admin** — a deliberate migration affordance. Production deployments must
   unset `SKYLA_API_TOKEN` and use real users; this is called out in the release manifest.

## 11. Decision record

- **ADR-2.1** PBKDF2 over Argon2/scrypt: stdlib-only, no new dependency, adequate at 200k iterations.
  Revisit if `argon2-cffi` is accepted as a dependency.
- **ADR-2.2** Opaque random tokens (hashed at rest) over JWT: instant server-side revocation matters
  more than statelessness at this scale.
- **ADR-2.3** Capability strings over role checks in route code: roles change, capability checks at
  the route do not.
- **ADR-2.4** Explicit-deny grants, so per-agent/per-connector revocation actually works.
- **ADR-2.5** 404 for foreign records to avoid an existence oracle.
