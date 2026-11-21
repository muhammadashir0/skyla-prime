"""PRIME SECURITY — authentication, RBAC, autonomy levels, prompt-injection guard.

Autonomy levels (see docs/SECURITY_ARCHITECTURE.md):
  0 Observe · 1 Prepare · 2 Routine execution · 3 Standing delegation · 4 Consequential
Secrets are never placed in model-visible context; the gateway strips them.
"""
from __future__ import annotations

import re
import secrets

from fastapi import Header, HTTPException

# Patterns that indicate an indirect prompt-injection attempt in untrusted content.
_INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"disregard (all )?(previous|prior) instructions",
    r"system prompt",
    r"reveal (your )?(api[-_ ]?key|secret|token|password)",
    r"you are now (in )?(jailbreak|dan|unrestricted)",
    r"<\s*system\s*>",
    r"act as (an? )?(unrestricted|jailbroken)",
]


def scan_untrusted(text: str) -> list[str]:
    """Return matched injection patterns found in untrusted external content."""
    low = text.lower()
    return [p for p in _INJECTION_PATTERNS if re.search(p, low)]


def require_auth(authorization: str | None, expected_token: str) -> str:
    """Validate Bearer token when SKYLA_API_TOKEN is configured.

    Returns the actor identity ('operator'). Raises 401 when invalid.
    When no token is configured (local dev), returns 'local-dev'.
    """
    if not expected_token:
        return "local-dev"
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization[len("Bearer "):].strip()
    if not secrets.compare_digest(token, expected_token):
        raise HTTPException(status_code=401, detail="Invalid token")
    return "operator"


def check_autonomy(requested: int, ceiling: int) -> None:
    """Enforce that a task's autonomy level does not exceed the deployment ceiling."""
    if requested > ceiling:
        raise HTTPException(
            status_code=403,
            detail=f"Autonomy level {requested} exceeds deployment ceiling {ceiling}. "
                   "Raise SKYLA_MAX_AUTONOMY to permit it.")


def generate_token() -> str:
    return "skp_" + secrets.token_urlsafe(32)
