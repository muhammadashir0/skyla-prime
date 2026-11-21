"""MFA replay protection and login throttling (A-10, A-11, A-12)."""
import time
import uuid

import pytest

from skyla.auth import AuthService, totp, verify_totp_step
from skyla.throttle import LoginBlocked, LoginThrottle


@pytest.fixture()
def svc(db):
    return AuthService(db)


def mfa_user(svc, secret="JBSWY3DPEHPK3PXP"):
    name = f"mfa_{uuid.uuid4().hex[:8]}"
    u = svc.create_user(name, "Mfa-Pass-2026", "operator")
    svc.db.execute("UPDATE users SET mfa_secret=?, mfa_enabled=1 WHERE id=?",
                   (secret, u["id"]))
    return name, secret


# ------------------------------------------------------------- replay (A-10)
def test_totp_code_cannot_be_reused(svc):
    """THE A-10 FINDING. Mutation: drop the mfa_last_step claim -> FAIL."""
    name, secret = mfa_user(svc)
    code = totp(secret)
    first = svc.authenticate(name, "Mfa-Pass-2026", code)
    assert first is not None, "valid code must authenticate"
    second = svc.authenticate(name, "Mfa-Pass-2026", code)
    assert second is None, "the SAME code was accepted twice (replay)"


def test_older_code_cannot_be_used_after_newer(svc):
    name, secret = mfa_user(svc)
    assert svc.authenticate(name, "Mfa-Pass-2026", totp(secret)) is not None
    # Going back in time must not be possible either.
    past = totp(secret, time.time() - 30)
    assert svc.authenticate(name, "Mfa-Pass-2026", past) is None


def test_concurrent_replay_allows_exactly_one(svc):
    """Two simultaneous logins with the same code: exactly one may succeed."""
    import threading
    name, secret = mfa_user(svc)
    code = totp(secret)
    results = []

    def attempt():
        results.append(svc.authenticate(name, "Mfa-Pass-2026", code))

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wins = [r for r in results if r is not None]
    assert len(wins) == 1, f"{len(wins)} logins consumed one TOTP code"


def test_replay_rejection_is_audited(svc):
    name, secret = mfa_user(svc)
    code = totp(secret)
    svc.authenticate(name, "Mfa-Pass-2026", code)
    svc.authenticate(name, "Mfa-Pass-2026", code)
    rows = svc.db.query(
        "SELECT action FROM audit_log WHERE action LIKE 'auth.mfa.%' ORDER BY ts DESC LIMIT 5")
    assert any("replay" in r["action"] for r in rows), "no audit event for replay"


def test_wrong_code_still_fails(svc):
    name, secret = mfa_user(svc)
    assert svc.authenticate(name, "Mfa-Pass-2026", "000000") is None


def test_password_still_required_with_mfa(svc):
    name, secret = mfa_user(svc)
    assert svc.authenticate(name, "wrong-password", totp(secret)) is None


def test_verify_totp_step_reports_matched_step():
    secret = "JBSWY3DPEHPK3PXP"
    step = verify_totp_step(secret, totp(secret))
    assert step is not None and abs(step - int(time.time() // 30)) <= 1


# ---------------------------------------------------------- throttling (A-11)
def test_repeated_failures_are_throttled(svc):
    """Mutation: remove the throttle -> unlimited guesses -> FAIL."""
    name = f"thr_{uuid.uuid4().hex[:8]}"
    svc.create_user(name, "Throttle-Pass-2026", "operator")
    throttle = LoginThrottle(max_per_account=3, lockout_s=60)
    for _ in range(3):
        assert svc.authenticate(name, "bad", throttle=throttle) is None
    with pytest.raises(LoginBlocked):
        svc.authenticate(name, "Throttle-Pass-2026", throttle=throttle)


def test_lockout_blocks_before_credential_check():
    """Once locked, even the CORRECT password is refused."""
    t = LoginThrottle(max_per_account=2, lockout_s=60)
    for _ in range(2):
        t.record_failure("victim", "")
    with pytest.raises(LoginBlocked) as exc:
        t.check("victim", "")
    assert exc.value.retry_after_s > 0


def test_per_remote_throttle():
    t = LoginThrottle(max_per_account=100, max_per_remote=3, lockout_s=60)
    for i in range(3):
        t.record_failure(f"user{i}", "203.0.113.9")
    with pytest.raises(LoginBlocked):
        t.check("somebody-else", "203.0.113.9")


def test_success_resets_the_counter():
    t = LoginThrottle(max_per_account=3, lockout_s=60)
    for _ in range(2):
        t.record_failure("u", "")
    t.record_success("u", "")
    for _ in range(2):
        t.record_failure("u", "")
    t.check("u", "")   # must not raise


def test_unknown_user_costs_the_same_as_a_wrong_password(svc):
    """A-12: timing enumeration. An unknown user must not return 25x faster."""
    known = f"known_{uuid.uuid4().hex[:8]}"
    svc.create_user(known, "Timing-Pass-2026", "operator")

    def timeit(fn, n=5):
        start = time.perf_counter()
        for _ in range(n):
            fn()
        return (time.perf_counter() - start) / n

    t_unknown = timeit(lambda: svc.authenticate("no-such-user-xyz", "whatever"))
    t_wrong = timeit(lambda: svc.authenticate(known, "wrong-password"))
    # Allow generous noise; the point is that they are the same order of magnitude.
    assert t_unknown > t_wrong * 0.25, (
        f"unknown-user path is {t_wrong / max(t_unknown, 1e-9):.1f}x faster "
        f"({t_unknown:.4f}s vs {t_wrong:.4f}s) -> enumeration oracle")
