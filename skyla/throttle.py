"""Login throttling and account lockout (v0.3.0, audit finding A-11).

v0.2.0 accepted unlimited password guesses. Twelve rapid failures produced twelve
401s with no delay.

Two independent counters are kept:
  * per-username  -> account lockout (protects one account from being guessed)
  * per-remote    -> per-source throttling (slows distributed guessing by one host)

Both are in-process. That is sufficient for a single-instance deployment and is
documented as such; a multi-instance deployment needs a shared store (A-29).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


class LoginBlocked(PermissionError):
    """Raised when a login attempt must be refused before credential checking."""

    def __init__(self, retry_after_s: int, reason: str):
        self.retry_after_s = max(1, int(retry_after_s))
        self.reason = reason
        super().__init__(f"{reason}; retry after {self.retry_after_s}s")


@dataclass
class _Bucket:
    failures: list[float] = field(default_factory=list)
    locked_until: float = 0.0


class LoginThrottle:
    def __init__(self, *, window_s: int = 900, max_per_account: int = 5,
                 max_per_remote: int = 20, lockout_s: int = 900,
                 enabled: bool = True):
        self.window_s = window_s
        self.max_per_account = max_per_account
        self.max_per_remote = max_per_remote
        self.lockout_s = lockout_s
        self.enabled = enabled
        self._accounts: dict[str, _Bucket] = {}
        self._remotes: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._blocked_total = 0

    # -- internal ------------------------------------------------------
    def _prune(self, bucket: _Bucket, now: float) -> None:
        cutoff = now - self.window_s
        bucket.failures = [t for t in bucket.failures if t >= cutoff]

    # -- public --------------------------------------------------------
    def check(self, username: str, remote: str = "") -> None:
        """Raise LoginBlocked if this attempt must be refused."""
        if not self.enabled:
            return
        now = time.time()
        with self._lock:
            acct = self._accounts.setdefault(username.lower(), _Bucket())
            self._prune(acct, now)
            if acct.locked_until > now:
                self._blocked_total += 1
                raise LoginBlocked(acct.locked_until - now, "account temporarily locked")
            if len(acct.failures) >= self.max_per_account:
                acct.locked_until = now + self.lockout_s
                self._blocked_total += 1
                raise LoginBlocked(self.lockout_s, "account temporarily locked")

            if remote:
                rem = self._remotes.setdefault(remote, _Bucket())
                self._prune(rem, now)
                if rem.locked_until > now:
                    self._blocked_total += 1
                    raise LoginBlocked(rem.locked_until - now, "too many attempts from this address")
                if len(rem.failures) >= self.max_per_remote:
                    rem.locked_until = now + self.lockout_s
                    self._blocked_total += 1
                    raise LoginBlocked(self.lockout_s, "too many attempts from this address")

    def record_failure(self, username: str, remote: str = "") -> None:
        if not self.enabled:
            return
        now = time.time()
        with self._lock:
            acct = self._accounts.setdefault(username.lower(), _Bucket())
            self._prune(acct, now)
            acct.failures.append(now)
            if len(acct.failures) >= self.max_per_account:
                acct.locked_until = now + self.lockout_s
            if remote:
                rem = self._remotes.setdefault(remote, _Bucket())
                self._prune(rem, now)
                rem.failures.append(now)
                if len(rem.failures) >= self.max_per_remote:
                    rem.locked_until = now + self.lockout_s

    def record_success(self, username: str, remote: str = "") -> None:
        if not self.enabled:
            return
        with self._lock:
            self._accounts.pop(username.lower(), None)
            if remote:
                self._remotes.pop(remote, None)

    def stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "tracked_accounts": len(self._accounts),
                "tracked_remotes": len(self._remotes),
                "blocked_total": self._blocked_total,
                "max_per_account": self.max_per_account,
                "max_per_remote": self.max_per_remote,
                "lockout_s": self.lockout_s,
            }

    def reset(self, username: str | None = None) -> None:
        """Administrative unlock."""
        with self._lock:
            if username is None:
                self._accounts.clear()
                self._remotes.clear()
            else:
                self._accounts.pop(username.lower(), None)


login_throttle = LoginThrottle()
