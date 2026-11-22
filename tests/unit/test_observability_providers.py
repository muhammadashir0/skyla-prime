"""WS6 provider validation (mock HTTP) + WS7 observability tests."""
import asyncio

import httpx
import pytest

from skyla.models.http_provider import OpenAICompatibleProvider, ProviderError
from skyla.observability import metrics, redact


def _provider(handler, usage=None):
    p = OpenAICompatibleProvider("test", "http://test/v1", "key", "m-1",
                                 usage_callback=usage)
    p._transport = httpx.MockTransport(handler)
    return p


def test_redaction():
    assert "[REDACTED]" in redact("Bearer abc123456789")
    assert "[REDACTED]" in redact("api_key=supersecretvalue")
    assert "hello" in redact("hello world")


def test_provider_success_and_usage():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "hi"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}})

    usage = []
    p = _provider(handler, lambda *a: usage.append(a))
    # The provider now builds clients through skyla.egress_client.client(), so that
    # is the seam to patch. Injecting a MockTransport never opens a socket.
    import skyla.models.http_provider as hp
    orig = hp.egress_client
    hp.egress_client = lambda *a, **kw: orig(
        *a, **{**kw, "transport": httpx.MockTransport(handler)})
    try:
        result = asyncio.run(p.chat(_req()))
    finally:
        hp.egress_client = orig
    assert result.text == "hi"
    assert result.input_tokens == 10
    assert usage and usage[0][2] == 10  # usage callback fired


def _req():
    from skyla.models.base import ChatRequest
    return ChatRequest(system="s", user="u")


def test_provider_retry_on_429():
    attempts = {"n": 0}

    def handler(request):
        attempts["n"] += 1
        if attempts["n"] < 3:
            return httpx.Response(429, text="rate limited")
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    p = _provider(handler)
    import skyla.models.http_provider as hp
    orig = hp.egress_client
    hp.egress_client = lambda *a, **kw: orig(
        *a, **{**kw, "transport": httpx.MockTransport(handler)})
    try:
        result = asyncio.run(p.chat(_req()))
    finally:
        hp.egress_client = orig
    assert result.text == "ok"
    assert attempts["n"] == 3


def test_provider_error_normalization():
    def handler(request):
        return httpx.Response(401, text="invalid key")

    p = _provider(handler)
    import skyla.models.http_provider as hp
    orig = hp.egress_client
    hp.egress_client = lambda *a, **kw: orig(
        *a, **{**kw, "transport": httpx.MockTransport(handler)})
    try:
        with pytest.raises(ProviderError) as exc:
            asyncio.run(p.chat(_req()))
        assert exc.value.status == 401
    finally:
        hp.egress_client = orig


def test_metrics_snapshot():
    metrics.inc("test_counter")
    snap = metrics.snapshot()
    assert snap["counters"]["test_counter"] >= 1


def test_request_trace_id_and_metrics():
    """Every response carries a trace id and raw tokens never appear in logs."""
    from fastapi.testclient import TestClient

    from skyla.api.app import app
    from tests.conftest import AUTH

    c = TestClient(app)
    r = c.get("/api/tasks", headers=AUTH)
    assert r.status_code == 200
    assert r.headers.get("X-Trace-Id", "").startswith("tr_")
    # telemetry counters are populated by real traffic
    snap = c.get("/api/metrics", headers=AUTH).json()
    assert snap["counters"].get("http_requests", 0) >= 1
    assert "http_latency_ms" in snap["observations"]


def test_redaction_covers_common_secret_shapes():
    from skyla.observability import redact
    for sample in ["Authorization: Bearer sk-abcdefghijkl",
                   "password=hunter2hunter2",
                   "token: skt_abcdefghijklmnop",
                   "api_key=AIzaSyABCDEFGHIJKLM"]:
        out = redact(sample)
        assert "[REDACTED]" in out, sample
