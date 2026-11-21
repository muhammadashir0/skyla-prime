# Security Policy — SKYLA PRIME

## Reporting a vulnerability

Open a private security advisory on the GitHub repository, or contact the
maintainer directly. Please include: affected version/commit, reproduction
steps, and impact assessment. Do not open public issues for vulnerabilities.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ Security fixes |
| < 0.1 | ❌ |

## Known security limitations (v0.1.0, audited 2026-11-21)

1. **Python execution is NOT a security sandbox.** `/api/execute/python`
   enforces timeout + memory limits only; filesystem, network and
   subprocess access are not blocked. Do not execute untrusted code in
   production until container-level isolation lands (Phase 5).
2. **Authentication is a single shared Bearer token** (`SKYLA_API_TOKEN`).
   No MFA, no per-user RBAC yet. Deploy behind a reverse proxy with TLS.
3. **Connectors run in mock mode** without credentials; live Gmail/
   Calendar/Telegram operations are not yet live-tested.
4. **SQLite** is suitable for single-instance deployments only.

See `docs/SECURITY_ARCHITECTURE.md` and `docs/AUDIT_REPORT_v0.1.0.md`
for the full independent audit.
