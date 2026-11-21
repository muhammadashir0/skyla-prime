# THREAT MODEL — SKYLA PRIME v0.2.1

**Assessment:** v0.2.1 PRIME ASSURANCE — independent adversarial validation of v0.2.0
**Date:** 2026-11-21
**Method:** source review + live adversarial execution against a running instance.
**Status vocabulary:** PASS · FAIL · NOT VERIFIED (definitions in `PRIME_ASSURANCE_REPORT.md` §2)

---

## 1. System under assessment

| Component | Trust level |
|---|---|
| HTTP API (`skyla/api/app.py`) | **Trusted**, internet-reachable |
| Auth service (`skyla/auth.py`) | **Trusted** |
| Database (`skyla/db.py`, SQLite) | **Trusted** |
| Agent orchestration + 5 agents | **Trusted code**, untrusted *inputs* |
| Execution provider (namespace) | **Boundary** — must contain untrusted code |
| Model providers (HTTP) | **Untrusted** responses |
| Connectors (Gmail/Calendar/Telegram) | **Untrusted** content, credentialed egress |
| Fetched web content | **Untrusted** |
| Uploaded documents / memory | **Untrusted**, user-supplied |
| Operator-supplied task instructions | **Untrusted** in content, trusted in intent |

### 1.1 The critical trust boundary

The only place untrusted *code* crosses into the host is `POST /api/execute/python`. Everything else
is untrusted *data* flowing into prompts and stores. This assessment therefore separates:

- **Administrative actions** (user management, token minting, MFA enrolment) — trusted principals only.
- **Workload execution** (arbitrary Python) — untrusted, must be contained.
- **Untrusted content** (documents, email, web) — never a control channel.

## 2. Assets

1. Host filesystem and other tenants' data.
2. Credentials: provider API keys, OAuth refresh tokens, Telegram bot token, session/API tokens.
3. The SQLite database (users, password hashes, MFA secrets, ledger, audit log).
4. Integrity of external side effects (an email/event/message must not duplicate or forge).
5. Availability of the API (single-process, single-host).
6. User privacy across accounts.

## 3. Adversaries

| ID | Adversary | Capability assumed |
|---|---|---|
| A1 | Authenticated low-privilege user (viewer) | valid session, attempts escalation / cross-tenant access |
| A2 | Authenticated operator submitting malicious code | `execute` capability |
| A3 | Remote unauthenticated attacker | network access to the API |
| A4 | Malicious content author | controls a document, email, web page or model response |
| A5 | Compromised integration credential | stolen OAuth/bot token |
| A6 | Malicious or malfunctioning agent | a task instruction crafted to make agents act wrongly |
| A7 | Operator error / disk fault | corrupts or truncates the database |
| A8 | Resource-exhaustion attacker | floods endpoints or workloads |

## 4. Threat catalogue and results

Severity: **C**ritical / **H**igh / **M**edium / **L**ow.
Result: **PASS** / **FAIL** / **NOT VERIFIED**.

### T-01 Malicious Python execution — host escape
| | |
|---|---|
| Adversary | A2 |
| Vector | code run via `/api/execute/python` reading host paths |
| Tested | host `/tmp` canary, `/etc/passwd`, `/` listing, bind-mount of host path |
| Result | **PASS** — chroot hides host FS; canary and `/etc/passwd` unreachable; bind mount of a host path fails `ENOENT` |
| Residual | isolation is chroot+namespaces, **not** a hardware boundary; shared kernel |

### T-02 Malicious Python — privilege retention (capabilities)
| | |
|---|---|
| Adversary | A2 |
| Vector | abuse retained Linux capabilities inside the namespace |
| Tested | `/proc/self/status` CapEff; `libc.mount()`; `mknod` |
| Observed | `CapEff: 000001ffffffffff` (**all 41 capabilities**), `NoNewPrivs: 0`, uid 0 |
| Result | **FAIL — HIGH.** `libc.mount()` returned **rc 0**, i.e. CAP_SYS_ADMIN is genuinely usable. v0.2.0 documentation claims "dropped capabilities"; **none are dropped**. No `no_new_privs`, no capability bounding-set reduction. Containment survives only because chroot has already removed paths to exploit and the mount namespace is private (`--make-rprivate`). Any future bug that keeps a host path reachable becomes critical. |
| Remediation | `--bounding-set=-all`-equivalent: drop caps via a small `execve` wrapper (`capset(0,0,0,0)`), set `PR_SET_NO_NEW_PRIVS`, add a seccomp allowlist, and run as a non-zero uid inside the user namespace. |

### T-03 Malicious Python — process exhaustion
| | |
|---|---|
| Adversary | A2, A8 |
| Vector | unbounded `fork()` |
| Tested | controlled 40-child fork farm; then an unbounded fork storm |
| Observed | 40 concurrent children created with **no limit**; the unbounded storm drove host **load average to 13 989** and the test harness was killed |
| Result | **FAIL — HIGH.** `RLIMIT_NPROC` is documented but **never set** (the provider only calls `ulimit -v`). A single operator request can take down the host. |
| Remediation | `setrlimit(RLIMIT_NPROC)` in the child **and** cgroup v2 `pids.max`; cgroup `memory.max`/`cpu.max` are the correct control points, not `ulimit`. |

### T-04 Malicious Python — memory exhaustion / host OOM
| | |
|---|---|
| Adversary | A2, A8 |
| Vector | allocate beyond the advertised 512 MB |
| Tested | 2 GB and 3 GB allocations; then the OOM sequence above |
| Observed | in-sandbox `MemoryError` (PASS for the allocating process) **but** the running API server was later killed with **exit code 137 (SIGKILL/OOM)** |
| Result | **FAIL — HIGH.** `ulimit -v` constrains only the child. Concurrency is uncapped, so aggregate memory across parallel sandboxes (plus a 300 MB workspace write) is unbounded and the OOM killer selects the *server*. Availability of the whole platform is attacker-controlled. |
| Remediation | cgroup v2 per-execution `memory.max` + `memory.swap.max` bound to the **provider**, not the child; a global concurrency semaphore; never rely on `ulimit -v` alone. |

### T-05 Malicious Python — unkillable / orphaned processes
| | |
|---|---|
| Adversary | A2 |
| Vector | fork a grandchild that outlives the timeout |
| Tested | parent spawns child that sleeps 300 s, then loops until timeout |
| Observed | timeout fired at 4 s, **yet `python3 /workspace/script.py` (pid 38614, ppid=1, state R) was still running afterwards**; a second orphan followed it |
| Result | **FAIL — HIGH.** `subprocess.run(timeout=…)` kills only the direct child. There is no process-group / PID-namespace kill. Orphans persist indefinitely, burning CPU and memory. |
| Remediation | `start_new_session=True` + `os.killpg`, or better `SIGKILL` to the PID namespace init; cgroup `cgroup.kill` is the reliable mechanism. |

### T-06 Malicious Python — network egress
| | |
|---|---|
| Adversary | A2, A5 |
| Vector | exfiltrate to the internet, reach internal services |
| Tested | TCP to `1.1.1.1:53`, DNS resolution, connect to a real host listener, `/var/run/docker.sock` |
| Result | **PASS** — `errno 101` (network unreachable), `gaierror` for DNS, host listener never accepted a connection, no sockets/`/run` visible |

### T-07 ptrace / procfs / sysfs / device access
| | |
|---|---|
| Adversary | A2 |
| Tested | `PTRACE_ATTACH` on pid 1, `/proc` PID enumeration, `/sys/class/net/lo/address`, `/dev/mem`, shm |
| Result | **PASS (mitigated)** — ptrace `EPERM`, only 1 PID visible, no `/dev/mem`, shm blocked. *Caveat:* PASS is a consequence of chroot + private namespaces, not of capability stripping (see T-02). |

### T-08 Working directory / fd leakage / mount propagation
| | |
|---|---|
| Adversary | A2 |
| Tested | inherited fds, `cwd`, `/proc/mounts`, host tmp visibility |
| Result | **PASS** — no host fds, cwd is `/workspace`, mounts private (`--make-rprivate`), `/tmp` is a fresh tmpfs (`[]`) |

### T-09 Host environment / secret exposure
| | |
|---|---|
| Adversary | A2 |
| Tested | enumerate `os.environ` in the sandbox |
| Result | **PASS** — child env is a fixed minimal set; no `SKYLA_API_TOKEN`, no provider keys |

### T-10 Resource: CPU
| | |
|---|---|
| Adversary | A2, A8 |
| Tested | deliberate 5 s CPU burn inside the sandbox |
| Result | **FAIL — MEDIUM.** No `RLIMIT_CPU` and no cpu cgroup; CPU consumption is bounded only by the wall-clock timeout, and concurrent sandboxes can multiply it without limit. (Documentation claims `RLIMIT_CPU`.) |

### T-11 Resource: disk / workspace quota
| | |
|---|---|
| Adversary | A2, A8 |
| Tested | write 300 MB into `/workspace` |
| Result | **FAIL — MEDIUM.** Succeeds; no `RLIMIT_FSIZE`, no tmpfs `size=` bound, no quota. Disk can be filled to exhaustion. |

### T-12 Prompt injection via task instruction
| | |
|---|---|
| Adversary | A4, A6 |
| Tested | instruction containing a classic injection, via `POST /api/tasks` |
| Observed | task **accepted and queued** (`status: queued`) with `injection_flags` populated |
| Result | **FAIL — HIGH.** Detection is *advisory only*: flags are returned to the caller and the task executes. There is **no enforcement gate** anywhere in the request path. |
| Remediation | Treat flags as a policy input: block, require human approval, or downgrade autonomy; never merely report. |

### T-13 Prompt-injection detector evasion
| | |
|---|---|
| Adversary | A4 |
| Tested | 12 payload families (paraphrase, role-play, delimiter spoof, tool-output spoof, authority claim, homoglyph, zero-width split, base64, markdown exfil) |
| Result | **FAIL — MEDIUM.** 8 of 12 evaded a 7-regex denylist (only literal "ignore previous instructions" / "system prompt" / "disregard…" matched). A denylist is not a control; the real control must be architectural (untrusted content never becomes instruction). |

### T-14 Hostile uploaded document
| | |
|---|---|
| Adversary | A4 |
| Tested | ingest a document containing injection text, then retrieve it |
| Observed | stored verbatim, fully searchable and returned to any caller, with no quarantine or label |
| Result | **FAIL — MEDIUM.** Poisoned content persists and is re-served to the model/other agents. No provenance-based trust label is applied at retrieval. |

### T-15 Malicious website (SSRF / injection)
| | |
|---|---|
| Adversary | A4, A3 |
| Tested | `fetch_url` has no private-range guard and `follow_redirects=True`; attempted `http://127.0.0.1:8000/api/health` |
| Result | **NOT VERIFIED** for the live fetch (the server was down at that moment and the environment's egress is restricted), but **source review is unambiguous: no `ipaddress` check, no redirect re-validation.** Classified **FAIL — HIGH (by inspection)**: an authenticated operator can direct the server to internal endpoints/metadata services. Fetched text is then stored and flagged-only (T-12). |
| Remediation | resolve and reject private/loopback/link-local/CGNAT ranges, re-validate each redirect hop, cap redirects, and egress via an allowlisting proxy. |

### T-16 Unauthorized API requests
| | |
|---|---|
| Adversary | A3 |
| Tested | unauthenticated calls to every protected route |
| Result | **PASS** — 401 without a credential; legacy token mapped to an attributable `legacy-admin`; denials audited as `authz.denied` |

### T-17 Privilege escalation (viewer → operator)
| | |
|---|---|
| Adversary | A1 |
| Tested | viewer creating tasks, creating users, minting `execute`/`*` scoped tokens |
| Result | **PASS** — 403 on task creation and user creation; a viewer-minted `["execute","tasks:create","*"]` token was still refused (role∩scope correctly enforced) |

### T-18 Credential minting by a read-only principal
| | |
|---|---|
| Adversary | A1 |
| Tested | viewer calls `POST /api/auth/tokens` |
| Result | **FAIL — MEDIUM.** A **viewer** can mint 30-day API tokens (constrained to viewer capabilities, so not an escalation, but it is unaudited issuance of durable credentials by a read-only principal). Should require an admin-only capability. |

### T-19 Cross-user data access
| | |
|---|---|
| Adversary | A1 |
| Tested | Bob reads/queries/deletes Alice's tasks, documents, memories |
| Observed | tasks **PASS** (0 visible, 404 on direct fetch); documents **PASS** (`[]`); **memories FAIL** — Bob received Alice's memory value `ALICE-PRIVATE-CONTENT-9931` in full, and `DELETE` returned **200** (destroyed her record) |
| Result | **FAIL — HIGH.** `GET /api/knowledge/memory` and `DELETE /api/knowledge/memory/{id}` omit ownership filtering, and `remember()` never stamps `owner_id`, so every memory is owned by `admin` and visible to everyone. |
| Remediation | stamp `owner_id` on write; filter `recall` by owner; enforce ownership on delete (404 for foreign ids). |

### T-20 TOTP / MFA replay
| | |
|---|---|
| Adversary | A5, A3 |
| Tested | reuse the same TOTP code repeatedly |
| Result | **FAIL — MEDIUM.** The same code validated 5/5 times; no `last_used_step` tracking. Combined with the ~90 s tolerance window (`window=1`), a phished code is reusable. |
| Remediation | persist the last accepted time-step per user and reject any step ≤ it. |

### T-21 Credential brute force
| | |
|---|---|
| Adversary | A3 |
| Tested | 12 consecutive failed logins; timing of non-existent vs. real user |
| Result | **FAIL — MEDIUM.** No throttling, no lockout, no backoff (12×401). Username enumeration is possible by timing: **3 ms** (unknown user) vs **77 ms** (real user, PBKDF2 executed) — a 25× signal. |
| Remediation | constant-time-ish dummy hash for unknown users, per-IP + per-account rate limiting, exponential lockout, and a `Retry-After`. |

### T-22 Compromised integration credential
| | |
|---|---|
| Adversary | A5 |
| Tested | inspection of connector hardening, token storage, revocation surface |
| Result | **NOT VERIFIED** — no live credentials exist in this environment, so the blast radius of a stolen OAuth/bot token could not be measured. Note by inspection: connectors hold long-lived refresh tokens with no per-connector revocation endpoint and no scoping to a test recipient. |

### T-23 Duplicate external operations
| | |
|---|---|
| Adversary | A6, A7 |
| Tested | repeat Gmail-draft / Calendar / Telegram writes with the same key; different payload same key; in-flight duplicate; crash-left `pending` |
| Result | **PASS** — duplicates replay the recorded provider result, fingerprint mismatch → 409, in-flight → 409, `pending` → `unknown` at startup and blind retry refused. A route-table test asserts every write endpoint has a key. |
| Residual | automatic provider-side reconciliation of `unknown` is **not implemented** (documented). |

### T-24 Database corruption
| | |
|---|---|
| Adversary | A7 |
| Tested | DB replaced with 8 KB NULs; DB header smashed; DB truncated to 0 bytes |
| Observed | NUL/header damage → refuses to start (good). **Truncated to 0 bytes → starts cleanly, reports `schema_version: 4`, zero users, and silently re-bootstraps an admin account.** |
| Result | **FAIL — HIGH.** No `PRAGMA integrity_check` at startup and no "did this DB exist before?" check. A zero-length file (a classic result of a crash during creation, or an operator mistake) is indistinguishable from a fresh install, so **silent total data loss is reported as a healthy system**. |
| Remediation | run `PRAGMA integrity_check` and assert a non-empty `schema_version` when the file already existed; refuse to auto-bootstrap over an existing-but-empty DB; require an explicit `--init` flag for first-run creation. |

### T-25 Backup / restore integrity
| | |
|---|---|
| Adversary | A7 |
| Tested | naive `cp` of a live WAL database vs. the online-backup API |
| Observed | naive copy → `no such table: users` (**a torn, useless backup that looks like a file**); online-backup → users 1, audit 1, `integrity_check ok` |
| Result | **FAIL — MEDIUM.** No automated backup exists in the codebase; the only documented procedure is a hand-run `sqlite3 .backup`, and the obvious `cp` produces a silently corrupt backup. |
| Remediation | scheduled online-backup job, restore verification (open + `integrity_check` + row counts + `schema_version`), retention, and an alarm when the last good backup is stale. |

### T-26 Provider outage
| | |
|---|---|
| Adversary | — (fault) |
| Tested | provider chain inspection; mock-only deployment |
| Result | **PASS (partial)** — routing falls back in quality order and terminates at the labelled mock provider, so a task degrades instead of failing; `/api/health` exposes configured providers. **NOT VERIFIED** for a real 429/5xx outage (no key). |

### T-27 Malicious agent behaviour / autonomy abuse
| | |
|---|---|
| Adversary | A6 |
| Tested | autonomy levels `-1, 0, 2, 3, 4, 99` |
| Result | **FAIL — LOW/MEDIUM.** Ceiling enforced above `max_autonomy` (3, 4, 99 → 403) but **negative levels are accepted** (`-1` → 200) — no range validation. Agent *result* trust (an agent declaring its own success) is not independently verified beyond the existing verification pass. |

### T-28 Malicious model response / tool-output spoofing
| | |
|---|---|
| Adversary | A4 |
| Tested | malformed provider response handling; `<tool_result>` spoof payload |
| Result | **PASS** for malformed responses (`ProviderError` normalised); **FAIL** for tool-output spoofing — the detector misses `<tool_result>{…}</tool_result>` (T-13), and model output is trusted as agent output by construction. |

## 5. Trust-boundary violations found

| # | Violation | Severity |
|---|---|---|
| 1 | Untrusted code runs with **all capabilities** and uid 0 inside the namespace | High |
| 2 | Untrusted code can exhaust host CPU/PID/disk and **kill the API** | High |
| 3 | Untrusted content marked "injection detected" **still executes** | High |
| 4 | Untrusted memory records are readable and destroyable across users | High |
| 5 | An authenticated principal can direct server-side fetches at internal networks | High |
| 6 | A truncated database is treated as a fresh install (silent total loss) | High |

## 6. Out of scope for this assessment

TLS termination, host/OS patching, network perimeter, physical security, supply-chain integrity of
PyPI packages, and the security of the live model providers themselves. No live external
communication was made; no real mailbox or calendar was touched.

## 7. Prioritised remediation order

1. **T-02, T-03, T-04, T-05** — capability dropping, cgroup v2 (`pids.max`, `memory.max`, `cpu.max`, `cgroup.kill`), global concurrency semaphore. One change set: *"the sandbox must not be able to harm the host."*
2. **T-24** — startup integrity gate + explicit first-run initialisation.
3. **T-19** — ownership on memories (write, read, delete).
4. **T-12/T-15** — enforcement, not reporting, for injection; SSRF guard on fetch.
5. **T-20, T-21, T-18** — MFA replay tracking, login throttling, token-mint capability.
6. **T-10, T-11, T-25** — remaining resource quotas and automated verified backups.
