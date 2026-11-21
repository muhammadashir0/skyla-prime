"""Live web research — SSRF-guarded fetch (v0.3.0, audit finding A-08).

Every hop is validated through `netguard.validate_url`, resolution happens at the
connection boundary, and redirects are followed manually so each target is
re-vetted before the request is made.
"""
from __future__ import annotations

import re

import httpx

from ..config import get_settings
from ..netguard import SSRFBlocked, validate_url
from ..trust import Provenance, TrustedText


def _extract_text(html: str) -> str:
    html = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


async def fetch_url(url: str, max_redirects: int = 3) -> dict:
    """Fetch a public http(s) URL with SSRF protection on every hop.

    Fetched content is returned as UNTRUSTED web provenance: it can be read,
    summarized and quoted, but never authorizes an action.
    """
    s = get_settings()
    current = url
    hops = 0
    async with httpx.AsyncClient(
        timeout=s.research_timeout_s,
        headers={"User-Agent": s.research_user_agent},
        follow_redirects=False,
    ) as client:
        while True:
            vetted = validate_url(current)          # resolves + vets this hop
            resp = await client.get(vetted.url)
            if resp.is_redirect:
                hops += 1
                if hops > max_redirects:
                    raise SSRFBlocked(f"too many redirects (>{max_redirects})")
                location = resp.headers.get("location", "")
                from urllib.parse import urljoin
                current = urljoin(current, location)
                continue
            resp.raise_for_status()
            raw = resp.content[: s.research_max_bytes]
            break

    text = _extract_text(raw.decode("utf-8", errors="ignore"))
    trusted = TrustedText(text=text[:20000], provenance=Provenance.WEB_CONTENT,
                          source=vetted.host)
    return {
        "url": vetted.url,
        "status": resp.status_code,
        "text": trusted.text,
        "provenance": int(trusted.provenance),
        "trust_label": trusted.label,
        "anomalies": trusted.anomalies,
        "trusted": trusted.trusted,
        "truncated": len(raw) >= s.research_max_bytes,
    }
