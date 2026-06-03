"""GAP-1 regression: the ``--endpoint`` preflight against FastAPI targets.

Background
----------
A FastAPI ``/chat`` endpoint that declares a required body model returns
``422 Unprocessable Entity`` when the scanner POSTs an empty body. Before
the GAP-1 fix the scanner already counted any HTTP response as reachable,
but the empty-body POST also kicked Cloud Run cold starts past the 2s
timeout twice in a row, mis-classifying live targets as
``EXIT_TARGET_UNREACHABLE``. The fix:

* Send a minimal ``{"input": "ping"}`` JSON body by default (so most agent
  endpoints reply 200 instead of 422 on the preflight).
* Accept a ``sample_body`` override for contract-driven scans that already
  know the on-wire shape.
* Treat *any* HTTP response (including 422) as "reachable, schema-protected"
  — only transport-level connect/timeout failures across both attempts mark
  the target down.
* Bump the timeout to 5s so Cloud Run cold starts are absorbed.

The three test cases below pin those guarantees.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from agent_guardian._endpoint_preflight import _classify_endpoint_health
from agent_guardian.cli import _endpoint_reachability_preflight

ENDPOINT = "https://target.example.com/finbot/chat"


@respx.mock
@pytest.mark.asyncio
async def test_empty_body_422_is_reachable() -> None:
    """A FastAPI endpoint that would 422 on empty body must NOT be marked unreachable.

    Even with the new default (``{"input": "ping"}``) some endpoints may still
    reject the body shape and reply 422. That is "reachable, schema-protected"
    — the listener is up, it just doesn't like our payload. Preflight must
    return True so the scan proceeds (and the real adapter call gets a
    clearer error downstream).
    """
    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            422,
            json={"detail": [{"loc": ["body"], "msg": "field required", "type": "missing"}]},
        ),
    )
    reachable = await _endpoint_reachability_preflight(ENDPOINT)
    assert reachable is True
    assert route.called


@respx.mock
@pytest.mark.asyncio
async def test_ping_body_200_is_reachable() -> None:
    """The default ``{"input": "ping"}`` body should make most agent endpoints reply 200."""
    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "pong"}}),
    )
    reachable = await _endpoint_reachability_preflight(ENDPOINT)
    assert reachable is True
    assert route.called
    # The body we POSTed must be the de-facto convention so FastAPI targets
    # that declare ``{"input": str}`` accept it without schema errors.
    sent = route.calls.last.request
    assert b'"input"' in sent.content
    assert b'"ping"' in sent.content


@respx.mock
@pytest.mark.asyncio
async def test_contract_sample_body_overrides_default() -> None:
    """If the caller passes a ``sample_body`` (e.g. from a contract), preflight uses it verbatim."""
    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "ok"}}),
    )
    reachable = await _endpoint_reachability_preflight(
        ENDPOINT,
        sample_body={"messages": [{"role": "user", "content": "ping"}], "model": "stub"},
    )
    assert reachable is True
    sent = route.calls.last.request
    assert b'"messages"' in sent.content
    assert b'"model"' in sent.content
    # The default ping body must not leak through when a sample is provided.
    assert b'"input":"ping"' not in sent.content.replace(b" ", b"")


@respx.mock
@pytest.mark.asyncio
async def test_connect_error_marks_unreachable() -> None:
    """A genuine connect failure (DNS / TLS / listener down) across both attempts is unreachable."""
    route = respx.post(ENDPOINT).mock(side_effect=httpx.ConnectError("connection refused"))
    reachable = await _endpoint_reachability_preflight(ENDPOINT)
    assert reachable is False
    # Two attempts before giving up.
    # 3 attempts with progressive timeout backoff (5s / 10s / 15s) tolerate
    # Cloud Run cold starts; only exhaust marks unreachable.
    assert route.call_count == 3


@respx.mock
@pytest.mark.asyncio
async def test_read_timeout_marks_unreachable() -> None:
    """A read timeout across both attempts is unreachable (target accepted the connection but never replied)."""
    route = respx.post(ENDPOINT).mock(side_effect=httpx.ReadTimeout("read timed out"))
    reachable = await _endpoint_reachability_preflight(ENDPOINT)
    assert reachable is False
    # 3 attempts with progressive timeout backoff (5s / 10s / 15s) tolerate
    # Cloud Run cold starts; only exhaust marks unreachable.
    assert route.call_count == 3


@respx.mock
@pytest.mark.asyncio
async def test_5xx_is_reachable() -> None:
    """A 500 / 503 from the target proves the listener is up — preflight must accept it as reachable."""
    route = respx.post(ENDPOINT).mock(return_value=httpx.Response(503, text="upstream down"))
    reachable = await _endpoint_reachability_preflight(ENDPOINT)
    assert reachable is True
    assert route.called


@respx.mock
@pytest.mark.asyncio
async def test_cold_start_recovers_on_attempt_two() -> None:
    """Cloud Run cold start: 1st POST times out (container booting), 2nd POST succeeds.

    Regression: the previous 5s x 2 budget false-positived UNREACHABLE on
    healthy testbenches whose first POST after idle exceeded 5s. The 3-attempt
    progressive-backoff budget must recover cleanly on attempt 2 without the
    operator needing to retry the whole scan.
    """
    route = respx.post(ENDPOINT).mock(
        side_effect=[
            httpx.ConnectTimeout("cold start"),
            httpx.Response(200, json={"output": {"text": "pong"}}),
        ]
    )
    reachable = await _endpoint_reachability_preflight(ENDPOINT)
    assert reachable is True
    assert route.call_count == 2


@respx.mock
@pytest.mark.asyncio
async def test_cold_start_recovers_on_attempt_three() -> None:
    """Long-tail cold start: first 2 POSTs time out, 3rd succeeds. Must still be reachable."""
    route = respx.post(ENDPOINT).mock(
        side_effect=[
            httpx.ConnectTimeout("cold start 1"),
            httpx.ReadTimeout("cold start 2"),
            httpx.Response(200, json={"output": {"text": "pong"}}),
        ]
    )
    reachable = await _endpoint_reachability_preflight(ENDPOINT)
    assert reachable is True
    assert route.call_count == 3


# --------------------------------------------------------------------------- #
# Status-aware classification: the preflight must validate a real response, not
# just connectivity. A 2xx is healthy; 401/403 is an auth failure (box is up,
# our creds are wrong); other 4xx is a client error; 5xx is a server error;
# connect/timeout is transport-unreachable.
# --------------------------------------------------------------------------- #


@respx.mock
@pytest.mark.asyncio
async def test_classify_healthy_2xx() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"output": "pong"}))
    health = await _classify_endpoint_health(ENDPOINT)
    assert health.classification == "healthy"
    assert health.healthy is True
    assert health.reachable is True
    assert health.status_code == 200


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_classify_auth_failure(status: int) -> None:
    """401/403 is its own bucket: reachable, but credentials/headers are wrong."""
    respx.post(ENDPOINT).mock(return_value=httpx.Response(status, text="forbidden"))
    health = await _classify_endpoint_health(ENDPOINT)
    assert health.classification == "auth_failed"
    assert health.reachable is True
    assert health.healthy is False
    assert health.status_code == status


@respx.mock
@pytest.mark.asyncio
async def test_classify_client_error_4xx() -> None:
    """A 404/422 (not 401/403) is a client error — reachable but request rejected."""
    respx.post(ENDPOINT).mock(return_value=httpx.Response(404, text="not found"))
    health = await _classify_endpoint_health(ENDPOINT)
    assert health.classification == "client_error"
    assert health.reachable is True
    assert health.status_code == 404


@respx.mock
@pytest.mark.asyncio
async def test_classify_server_error_5xx() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(503, text="upstream down"))
    health = await _classify_endpoint_health(ENDPOINT)
    assert health.classification == "server_error"
    assert health.reachable is True
    assert health.status_code == 503


@respx.mock
@pytest.mark.asyncio
async def test_classify_unreachable_on_connect_error() -> None:
    respx.post(ENDPOINT).mock(side_effect=httpx.ConnectError("connection refused"))
    health = await _classify_endpoint_health(ENDPOINT)
    assert health.classification == "unreachable"
    assert health.reachable is False
    assert health.status_code is None
