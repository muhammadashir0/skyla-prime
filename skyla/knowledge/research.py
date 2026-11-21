"""Live web research — fetch + extract text from permitted public sources.

Only http(s) URLs are fetched; responses are size-capped; fetched content is
treated as untrusted (injection-scanned) and stored with provenance.
Search-engine scraping is intentionally NOT implemented (ToS/legality);
use official search APIs or direct URLs.
"""
from __future__ import annotations

import re

import httpx

from ..config import get_settings
from ..security import scan_untrusted


def _extract_text(html: str) -> str:
    html = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text


async def fetch_url(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        raise ValueError("Only http(s) URLs are permitted")
    s = get_settings()
    async with httpx.AsyncClient(timeout=s.research_timeout_s,
                                 headers={"User-Agent": s.research_user_agent},
                                 follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        raw = resp.content[: s.research_max_bytes]
    text = _extract_text(raw.decode("utf-8", errors="ignore"))
    return {
        "url": url, "status": resp.status_code, "text": text[:20000],
        "injection_flags": scan_untrusted(text),
        "truncated": len(raw) >= s.research_max_bytes,
    }
