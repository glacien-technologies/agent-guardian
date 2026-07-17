"""Tests for GeminiClient (AI Studio API) using respx.

Covers the request-shaping rules (``systemInstruction`` split, ``assistant``
→ ``model`` role rename, stop sequences in ``generationConfig``), the
error hierarchy mapping, and the happy-path response parse.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from httpx import Response

from agent_guardian.core.budget import BudgetEnvelope, BudgetLedger, tokens_to_usd
from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.budget_admission import BudgetAdmissionLLM
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTransientError,
)
from agent_guardian.llm.gemini import GeminiClient
from agent_guardian.llm.usage_tracking import UsageTrackingLLM

_HAPPY_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro-preview:generateContent"
)


def _req(content: str = "hi", model: str = "gemini-3.1-pro-preview") -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content=content)], model=model)


def _happy_body(text: str = "Hello from Gemini") -> dict[str, object]:
    return {
        "candidates": [
            {
                "content": {"parts": [{"text": text}], "role": "model"},
                "finishReason": "STOP",
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 5,
            "candidatesTokenCount": 4,
            "totalTokenCount": 9,
        },
        "modelVersion": "gemini-3.1-pro-preview",
    }


@respx.mock
async def test_gemini_complete_happy_path() -> None:
    route = respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    llm = GeminiClient(api_key="test-key")
    resp = await llm.complete(_req())
    assert resp.text == "Hello from Gemini"
    assert resp.provider == "gemini"
    assert resp.usage.total_tokens == 9
    assert resp.usage.prompt_tokens == 5
    assert resp.usage.completion_tokens == 4
    assert resp.finish_reason == "stop"
    # The API key travels as a query parameter, not a header.
    assert route.called
    sent_url = urlparse(str(route.calls.last.request.url))
    assert parse_qs(sent_url.query)["key"] == ["test-key"]
    await llm.aclose()


@respx.mock
async def test_gemini_complete_includes_thinking_tokens_in_completion_usage() -> None:
    body = _happy_body()
    usage = body["usageMetadata"]
    assert isinstance(usage, dict)
    usage.update(
        {
            "promptTokenCount": 10,
            "candidatesTokenCount": 3,
            "thoughtsTokenCount": 17,
            "totalTokenCount": 30,
        }
    )
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=body))
    llm = GeminiClient(api_key="k", rate_limiter=None)

    response = await llm.complete(_req())

    assert response.usage.prompt_tokens == 10
    assert response.usage.completion_tokens == 20
    assert response.usage.total_tokens == 30
    await llm.aclose()


@respx.mock
async def test_budget_settlement_prices_gemini_thinking_tokens() -> None:
    model = "gemini-3.5-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    body = _happy_body()
    body["modelVersion"] = model
    usage = body["usageMetadata"]
    assert isinstance(usage, dict)
    usage.update(
        {
            "promptTokenCount": 10,
            "candidatesTokenCount": 3,
            "thoughtsTokenCount": 17,
            "totalTokenCount": 30,
        }
    )
    respx.post(url).mock(return_value=Response(200, json=body))
    inner = GeminiClient(api_key="k", rate_limiter=None)
    tracked = UsageTrackingLLM(inner)
    ledger = BudgetLedger(BudgetEnvelope(usd_cap=1.0, token_cap=10_000, wallclock_cap_s=60.0))
    llm = BudgetAdmissionLLM(tracked, ledger=ledger, agent_id="evaluator")

    await llm.complete(_req(model=model))

    assert ledger.spent_usd == pytest.approx(tokens_to_usd(model, 10, 20))
    assert tracked.counter.priced_cost_usd == pytest.approx(tokens_to_usd(model, 10, 20))
    await inner.aclose()


@respx.mock
async def test_gemini_split_system_into_systemInstruction() -> None:
    route = respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    req = LLMRequest(
        messages=[
            LLMMessage(role="system", content="You are terse."),
            LLMMessage(role="system", content="No emojis."),
            LLMMessage(role="user", content="hello"),
            LLMMessage(role="assistant", content="hi"),
            LLMMessage(role="user", content="again?"),
        ],
        model="gemini-3.1-pro-preview",
    )
    llm = GeminiClient(api_key="k")
    await llm.complete(req)
    body = json.loads(route.calls.last.request.content)
    # System messages were coalesced into the dedicated field…
    assert body["systemInstruction"]["parts"][0]["text"] == "You are terse.\n\nNo emojis."
    # …and the chat history was preserved with assistant → model rename.
    contents = body["contents"]
    assert [c["role"] for c in contents] == ["user", "model", "user"]
    assert contents[0]["parts"][0]["text"] == "hello"
    assert contents[1]["parts"][0]["text"] == "hi"
    assert contents[2]["parts"][0]["text"] == "again?"
    await llm.aclose()


@respx.mock
async def test_gemini_stop_sequences_serialised_to_generation_config() -> None:
    route = respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="gemini-3.1-pro-preview",
        stop=["</end>", "STOP"],
        max_tokens=512,
        temperature=0.2,
    )
    llm = GeminiClient(api_key="k")
    await llm.complete(req)
    body = json.loads(route.calls.last.request.content)
    assert body["generationConfig"]["stopSequences"] == ["</end>", "STOP"]
    assert body["generationConfig"]["maxOutputTokens"] == 512
    assert body["generationConfig"]["temperature"] == pytest.approx(0.2)
    await llm.aclose()


@respx.mock
async def test_gemini_auth_401_raises_llm_auth_error() -> None:
    respx.post(_HAPPY_URL).mock(
        return_value=Response(401, json={"error": {"status": "UNAUTHENTICATED"}})
    )
    llm = GeminiClient(api_key="bad")
    with pytest.raises(LLMAuthError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_auth_403_raises_llm_auth_error() -> None:
    respx.post(_HAPPY_URL).mock(
        return_value=Response(403, json={"error": {"status": "PERMISSION_DENIED"}})
    )
    llm = GeminiClient(api_key="forbidden")
    with pytest.raises(LLMAuthError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_rate_limit_429_with_retry_after_eventually_succeeds() -> None:
    route = respx.post(_HAPPY_URL).mock(
        side_effect=[
            Response(429, headers={"retry-after": "0"}, json={"error": "rate"}),
            Response(200, json=_happy_body("ok")),
        ]
    )
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.text == "ok"
    assert route.call_count == 2
    await llm.aclose()


@respx.mock
async def test_gemini_rate_limit_persists_raises() -> None:
    respx.post(_HAPPY_URL).mock(
        return_value=Response(429, headers={"retry-after": "0"}, json={"error": "rate"})
    )
    llm = GeminiClient(api_key="k")
    with pytest.raises(LLMRateLimitError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_transient_503_retries_then_succeeds() -> None:
    respx.post(_HAPPY_URL).mock(
        side_effect=[
            Response(503, json={"error": "service unavailable"}),
            Response(200, json=_happy_body("later")),
        ]
    )
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.text == "later"
    await llm.aclose()


@respx.mock
async def test_gemini_transient_500_persists_raises_transient_error() -> None:
    respx.post(_HAPPY_URL).mock(return_value=Response(500, json={"error": "boom"}))
    llm = GeminiClient(api_key="k")
    with pytest.raises(LLMTransientError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_permanent_400_no_retry() -> None:
    route = respx.post(_HAPPY_URL).mock(
        return_value=Response(400, json={"error": {"status": "INVALID_ARGUMENT"}})
    )
    llm = GeminiClient(api_key="k")
    with pytest.raises(LLMPermanentError):
        await llm.complete(_req())
    assert route.call_count == 1
    await llm.aclose()


@respx.mock
async def test_gemini_malformed_response_raises_format_error() -> None:
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json={"unexpected": "shape"}))
    llm = GeminiClient(api_key="k")
    with pytest.raises(LLMResponseFormatError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_thought_only_candidate_returns_empty_text() -> None:
    # #133 — a thinking model (gemini-2.5-pro+) that spends the whole
    # maxOutputTokens budget on internal reasoning returns a candidate whose
    # ``content`` has NO ``parts``. That is a valid-but-empty response, not a
    # malformed one: it must parse to empty text with finish_reason="length"
    # so callers run their empty-output fallbacks instead of the whole attack
    # lane dying on an LLMResponseFormatError.
    body = {
        "candidates": [
            {
                "content": {"role": "model"},
                "finishReason": "MAX_TOKENS",
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 12,
            "totalTokenCount": 812,
            "thoughtsTokenCount": 800,
        },
        "modelVersion": "gemini-2.5-pro",
    }
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=body))
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.text == ""
    assert resp.finish_reason == "length"
    await llm.aclose()


@respx.mock
async def test_gemini_empty_candidate_warn_split_by_finish_reason(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Issue #197 — the empty-candidate WARN must reflect the *actual* upstream
    failure mode, not blanket-blame ``max_output_tokens``.

    Pre-fix every ``text == ""`` response produced the same WARN body asserting
    that a thinking model "likely consumed the whole maxOutputTokens budget on
    reasoning" — true for ``finishReason=STOP`` with ``thoughtsTokenCount > 0``
    but misleading for ``MALFORMED_FUNCTION_CALL`` (structural failure, no
    token tuning helps) and ``SAFETY``/``RECITATION`` (provider safety filter,
    caller's fallback IS the right path, not a bug).

    Locks the four-way dispatch: the operator triaging these logs reads the
    correct remediation each time.
    """

    async def _capture(payload: dict[str, object]) -> tuple[str, str]:
        respx.post(_HAPPY_URL).mock(return_value=Response(200, json=payload))
        llm = GeminiClient(api_key="k")
        caplog.clear()
        with caplog.at_level("INFO", logger="agent_guardian.llm.gemini"):
            await llm.complete(_req())
        await llm.aclose()
        # Find the empty-candidate record; the parser may emit additional
        # debug records before/after it, so filter by message substring.
        for rec in caplog.records:
            if "empty candidate text" in rec.getMessage():
                return rec.levelname, rec.getMessage()
        return "(absent)", "(absent)"

    # STOP with thoughtsTokenCount>0 → the real budget-exhaustion case.
    level, msg = await _capture(
        {
            "candidates": [{"content": {"role": "model"}, "finishReason": "STOP"}],
            "usageMetadata": {"thoughtsTokenCount": 800, "promptTokenCount": 5},
        }
    )
    assert level == "WARNING"
    assert "thoughtsTokenCount=800" in msg
    assert "raise max_output_tokens" in msg

    # MALFORMED_FUNCTION_CALL — structural, no token tuning helps.
    level, msg = await _capture(
        {
            "candidates": [
                {"content": {"role": "model"}, "finishReason": "MALFORMED_FUNCTION_CALL"}
            ],
            "usageMetadata": {"thoughtsTokenCount": 0, "promptTokenCount": 5},
        }
    )
    assert level == "WARNING"
    assert "MALFORMED_FUNCTION_CALL" in msg
    assert "will NOT help" in msg
    # The misleading "thinking model consumed budget" framing must not appear
    # on the structural-failure path.
    assert "thinking model" not in msg

    # SAFETY — provider filter, downgraded to INFO so the caller's fallback
    # path doesn't read as a bug worth paging on.
    level, msg = await _capture(
        {
            "candidates": [{"content": {"role": "model"}, "finishReason": "SAFETY"}],
            "usageMetadata": {"promptTokenCount": 5},
        }
    )
    assert level == "INFO"
    assert "SAFETY" in msg
    assert "safety" in msg.lower()

    # Unknown finishReason → generic WARN fallback (don't silently swallow).
    level, msg = await _capture(
        {
            "candidates": [{"content": {"role": "model"}, "finishReason": "OTHER"}],
            "usageMetadata": {"promptTokenCount": 5},
        }
    )
    assert level == "WARNING"
    assert "OTHER" in msg
    assert "unrecognised" in msg.lower() or "unrecognized" in msg.lower()


@respx.mock
async def test_gemini_missing_content_returns_empty_text() -> None:
    # Sibling shape: candidate with no ``content`` key at all (seen on some
    # SAFETY/MAX_TOKENS terminations). Same tolerance as the Vertex parser.
    body = {
        "candidates": [{"finishReason": "MAX_TOKENS"}],
        "usageMetadata": {"promptTokenCount": 3, "totalTokenCount": 3},
    }
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=body))
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.text == ""
    assert resp.finish_reason == "length"
    await llm.aclose()


@respx.mock
async def test_gemini_finish_reason_max_tokens_maps_to_length() -> None:
    body = _happy_body()
    body["candidates"][0]["finishReason"] = "MAX_TOKENS"  # type: ignore[index]
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=body))
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.finish_reason == "length"
    await llm.aclose()


@respx.mock
async def test_gemini_finish_reason_safety_maps_to_content_filter() -> None:
    body = _happy_body()
    body["candidates"][0]["finishReason"] = "SAFETY"  # type: ignore[index]
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=body))
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.finish_reason == "content_filter"
    await llm.aclose()


@respx.mock
async def test_gemini_custom_base_url() -> None:
    respx.post("https://proxy.example.com/v1beta/models/gemini-3.5-flash:generateContent").mock(
        return_value=Response(200, json=_happy_body("via proxy"))
    )
    llm = GeminiClient(api_key="k", base_url="https://proxy.example.com/v1beta")
    resp = await llm.complete(_req(model="gemini-3.5-flash"))
    assert resp.text == "via proxy"
    await llm.aclose()


def test_gemini_concurrency_default() -> None:
    llm = GeminiClient(api_key="k")
    # PRD §14.3 default for paid providers without a higher OpenAI-style cap.
    assert llm._semaphore._value == 5


@respx.mock
async def test_gemini_seed_forwarded_to_generation_config() -> None:
    """Deterministic-replay seed must reach ``generationConfig.seed``.

    Without this, swarm replay against Gemini silently falls back to
    same-prompt-same-temperature determinism — and quietly loses the
    reproducibility guarantee promised in :class:`LLMRequest`.
    """
    route = respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="gemini-3.1-pro-preview",
        seed=4242,
    )
    llm = GeminiClient(api_key="k")
    await llm.complete(req)
    body = json.loads(route.calls.last.request.content)
    assert body["generationConfig"]["seed"] == 4242
    await llm.aclose()


@respx.mock
async def test_gemini_seed_omitted_when_none() -> None:
    """When ``seed`` is None we must NOT emit the field — Gemini rejects nulls."""
    route = respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    llm = GeminiClient(api_key="k")
    await llm.complete(_req())
    body = json.loads(route.calls.last.request.content)
    assert "seed" not in body["generationConfig"]
    await llm.aclose()


@respx.mock
async def test_gemini_emits_structured_info_call_line(caplog: pytest.LogCaptureFixture) -> None:
    """QA-068 — the model-call narration is one structured INFO line.

    The pre-QA-068 code emitted a DEBUG dump of every kwarg (temperature /
    seed / system / tool defs). We now emit one INFO one-liner with the
    just-the-essentials shape ``model call: gemini-<model> (msgs=N, max_tok=M)``
    so the operator's swarm-board narrates each LLM call without drowning
    in DEBUG noise. The shared ``log_model_request`` helper owns this line.
    """
    import logging

    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    llm = GeminiClient(api_key="k")
    with caplog.at_level(logging.INFO, logger="agent_guardian.llm.gemini"):
        await llm.complete(_req())
    matching = [r for r in caplog.records if r.message.startswith("model call: gemini-")]
    assert matching, (
        f"expected one INFO 'model call:' line, got {[r.message for r in caplog.records]}"
    )
    # Exactly one narration line per call — provider+model is stamped once, not
    # repeated on the response line.
    assert len(matching) == 1, f"expected exactly one INFO 'model call:' line, got {matching}"
    last = matching[-1]
    # The structured shape includes msgs= and max_tok= tokens.
    assert "msgs=" in last.message
    assert "max_tok=" in last.message
    # Raw kwargs (temperature / seed / system / tool defs) must NOT leak into INFO.
    assert "temperature=" not in last.message
    assert "seed=" not in last.message
    await llm.aclose()


@respx.mock
async def test_gemini_logs_readable_request_and_full_response_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """At DEBUG we log the ACTUAL prompt content (readably) and the ACTUAL full response.

    Replaces the old ``text[:80]`` truncation: a real prompt and a real
    response must both be readable in the log, not clipped to 80 chars. The
    request is shown as the message content (the newest conversation tail), not
    the raw provider payload dict — the full payload dump is opt-in (see the
    AGENT_GUARDIAN_LOG_FULL_PROMPTS test below).
    """
    import logging

    long_text = "FULL_RESPONSE_BODY " * 20  # well past the old 80-char clip
    body = _happy_body()
    body["candidates"][0]["content"]["parts"][0]["text"] = long_text
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=body))
    llm = GeminiClient(api_key="k")
    with caplog.at_level(logging.DEBUG, logger="agent_guardian.llm.gemini"):
        await llm.complete(_req())
    messages = [r.message for r in caplog.records]
    # Request out: the actual prompt content is logged readably (the _req() user
    # message is "hi"), NOT the raw payload dict.
    req_lines = [m for m in messages if m.startswith("request out")]
    assert req_lines, messages
    assert "hi" in req_lines[-1]
    assert "generationConfig" not in req_lines[-1]  # raw payload is not dumped by default
    # Response in: the FULL text is present, plus token usage + finish reason.
    resp_lines = [m for m in messages if m.startswith("response in:")]
    assert resp_lines, messages
    assert long_text.strip() in resp_lines[-1]
    assert "tokens=" in resp_lines[-1]
    assert "finish=" in resp_lines[-1]
    await llm.aclose()


@respx.mock
async def test_gemini_full_prompts_env_dumps_raw_payload(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AGENT_GUARDIAN_LOG_FULL_PROMPTS=1 restores the full raw-payload dump."""
    import logging

    monkeypatch.setenv("AGENT_GUARDIAN_LOG_FULL_PROMPTS", "1")
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    llm = GeminiClient(api_key="k")
    with caplog.at_level(logging.DEBUG, logger="agent_guardian.llm.gemini"):
        await llm.complete(_req())
    req_lines = [r.message for r in caplog.records if r.message.startswith("request out")]
    assert req_lines, [r.message for r in caplog.records]
    # The full dump includes the raw provider payload keys.
    assert any("generationConfig" in m for m in req_lines), req_lines
    await llm.aclose()


@respx.mock
async def test_gemini_surfaces_safety_block_at_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A SAFETY finishReason maps to content_filter and is logged at WARNING."""
    import logging

    body = _happy_body()
    body["candidates"][0]["finishReason"] = "SAFETY"
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=body))
    llm = GeminiClient(api_key="k")
    with caplog.at_level(logging.DEBUG, logger="agent_guardian.llm.gemini"):
        await llm.complete(_req())
    blocked = [r for r in caplog.records if r.levelno == logging.WARNING and "blocked" in r.message]
    assert blocked, [r.message for r in caplog.records]
    assert "finish=content_filter" in blocked[-1].message
    await llm.aclose()
