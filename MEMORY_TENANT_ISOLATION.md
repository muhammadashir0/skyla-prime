# PRIME CONTAINMENT — Memory Tenant Isolation

**Scope:** Mission 2, audit finding **A-05** (cross-user memory access).
**Status:** **PASS** at the API, store and SQL layers. 11 adversarial API tests + mutation proof.

---

## 1. The finding

v0.2.0 stored memories as `(id, kind, key, value, source, reliability)` with no owner. `recall()` had no notion of who was asking, and the API returned whatever matched. The independent audit created a memory as user A and retrieved it as user B, then deleted it as B. There was no identifier to constrain, so no amount of API-layer filtering could have fixed it.

---

## 2. The model

### Identity

Every authenticated principal has a stable `users.id`. That id — not the username, not a session id — is the **tenant identity** for memory.

```
memory.owner_id  ->  users.id   (NOT NULL, enforced by schema)
```

`owner_id` is set server-side, once, from the authenticated principal. There is no code path that accepts an owner from the request body, a header, or a query parameter. A client cannot express "act as another tenant".

### The tenant rule

```python
def _require_tenant(user) -> str:
    tid = user.get("id")
    if not tid:
        raise HTTPException(403, "No tenant identity on this principal")
    return tid
```

Empty, missing or falsy identity is **denied**, never defaulted. At the store/db layer the same rule applies as a `ValueError`, so a caller that somehow bypasses the API still cannot write an ownerless record:

```python
def _require_tenant(self, owner_id: str) -> str:
    if not owner_id:
        raise ValueError("tenant isolation: owner_id is required")
    return owner_id
```

### Enforcement in SQL, not in Python

This is the part that the finding demands. Every operation puts the constraint in the `WHERE` clause:

```sql
-- read/list/search
SELECT * FROM memories WHERE owner_id = ? AND (value LIKE ? OR key LIKE ?) ORDER BY reliability DESC LIMIT ?
SELECT * FROM memories WHERE owner_id = ? ORDER BY updated_at DESC LIMIT ?
SELECT * FROM memories WHERE id = ? AND owner_id = ?
-- mutate
UPDATE memories SET value = ? WHERE id = ? AND owner_id = ?
DELETE FROM memories WHERE id = ? AND owner_id = ?
```

There is **no** `SELECT * FROM memories` followed by a Python-side filter anywhere in the codebase. A general query that is later filtered in application memory would be one refactor away from leaking, and would also fail the "apply tenant constraints in DB operations" requirement.

Consequence: `rowcount == 0` means either the row does not exist **or** it belongs to someone else, and the two are indistinguishable to the caller — which is exactly what §4 requires.

---

## 3. Endpoint coverage

Every memory endpoint, every method, is scoped and tested.

| Method | Path | Scope applied | Foreign-id behaviour |
|---|---|---|---|
| POST | `/api/knowledge/memory` | `owner_id` from principal | n/a |
| GET | `/api/knowledge/memory?q=` | `WHERE owner_id=?` | other tenants' rows absent |
| GET | `/api/knowledge/memory` | `WHERE owner_id=?` | other tenants' rows absent |
| GET | `/api/knowledge/memory/{id}` | `WHERE id=? AND owner_id=?` | **404** |
| PATCH | `/api/knowledge/memory/{id}` | `WHERE id=? AND owner_id=?` | **404**, record unmodified |
| DELETE | `/api/knowledge/memory/{id}` | `WHERE id=? AND owner_id=?` | **404**, record intact |
| GET | `/api/knowledge/memory-export` | `WHERE owner_id=?` | other tenants' rows absent |

`PATCH` and `GET /{id}` and the export endpoint did not exist before; they were added so that the isolation surface is complete rather than only covering the endpoints the old code happened to have.

---

## 4. Errors must not reveal existence

A `403` on a foreign id would be an oracle: it confirms the record exists. The API returns **404 with an identical body** for "does not exist" and "belongs to another tenant".

Verified by `test_cannot_read_other_tenants_memory_by_id`, `..._update_...`, `..._delete_...`, which assert the status code is 404 and then re-read the record as its owner to confirm it is untouched.

Denials are still audited (`memory.update.denied`, `memory.delete.denied`) with the acting username, so an operator can see the attempt without the attacker learning anything.

---

## 5. Administrator policy (documented, as required)

**Memory is always tenant-private, including for administrators. There is no override.**

Rationale: memory holds user preferences, facts and instructions — personal content, not operational metadata. An admin override would recreate A-05 with a different actor and would make "zero cross-tenant access" untestable. Administrators retain the powers they need — creating users, roles, granting scopes, revoking tokens, viewing audit — and none of those require reading another user's memory *content*.

`user:manage` is a `SYSTEM`-floor action; `memory:read` of another tenant has **no floor at all** — it is not expressible.

Verified by `test_admin_access_follows_documented_policy`, which creates an admin and asserts 404 on a user's memory id and `[]` on a search for its content.

---

## 6. Migration and legacy data

`MIGRATIONS` v5 adds the column and backfills:

```sql
ALTER TABLE memories ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
UPDATE memories SET owner_id = 'admin' WHERE owner_id = '' OR owner_id IS NULL;
```

Pre-existing rows are attributed to the bootstrap administrator account, because on an un-upgraded database the only principal that could have created them through the API was the bootstrap admin. This is recorded here because it is an assumption, not a proof; an operator upgrading a database that was shared in some other way should re-attribute rows before serving traffic.

Fresh databases get `owner_id TEXT NOT NULL` with no default, so an unscoped insert is rejected by SQLite itself.

---

## 7. Assumptions and limits

* **The tenant id is per-user, not per-organisation.** Users who should share memory need an explicit shared tenant; that feature is deliberately not added (no new capability during remediation).
* **The audit log is not tenant-scoped** — it is an administrative record, visible to admins. This is a documented exception, not an oversight.
* **Search is case-insensitive `LIKE`,** so a tenant can search only its own rows; the scoping is orthogonal to the matching strategy.
* **No cross-tenant inference protection.** A tenant cannot read another's rows, but timing or volume side channels on a shared SQLite file are not modelled. Single-file SQLite is a documented deployment constraint (A-29 remains open for multi-process).
