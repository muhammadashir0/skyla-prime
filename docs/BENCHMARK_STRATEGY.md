# SKYLA PRIME — Benchmark Strategy

## Public benchmarks (tracked, not claimed)

Artificial Analysis Intelligence Index, SWE-bench Verified, Terminal-Bench,
GPQA Diamond, Humanity's Last Exam, OSWorld, MMMU, AILuminate. Vendor-
reported scores are recorded with version/date/config in the research
register; SKYLA PRIME never compares scores across incompatible configs.

## Internal acceptance targets (proposed, not yet measured)

| Category | Target |
|---|---|
| Audited research claims supported by sources | 95% |
| Correct citation references | 99% |
| Held-out memory retrieval quality | 90% |
| Tested multi-step task completion | 85% |
| Controlled failure recovery | 90% |
| Unauthorized successful actions | 0 |
| Critical credential exposure | 0 |

Targets require sufficiently large samples + confidence intervals before
any claim of achievement.

## Integration acceptance (Phase 3)

Search Gmail · retrieve thread · draft reply · send authorized test email ·
verify provider record · calendar availability · create test event · invite
attendee · create video meeting · update PM task · create document · send
Telegram notification · revoke authorization · confirm access rejected.
Idempotency + post-failure reconciliation required.

## Current test evidence

31 unit/API tests passing (tests/). Model-quality benchmarks are pending
provider keys — the mock provider is excluded from all quality claims.
