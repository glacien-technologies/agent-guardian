"""Phase C.C4c — HttpAdapter ships probe attachments inline when present.

Covers the multimodal body shape, the configurable key-map override,
the supports_vision guard, and the no-attachment baseline regression.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.llm.errors import LLMPermanentError
from agent_guardian.models.multimodal import ProbeAttachment

_TINY_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\rIDATx\x9cc\xfc\xff\xff?\x03\x00\x06\x04\x02\xfeb\x0e\xb2\x9d\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _attachment() -> ProbeAttachment:
    return ProbeAttachment.from_bytes(
        _TINY_PNG_BYTES, mime_type="image/png", alt_text="tiny test png"
    )


@pytest.mark.anyio
class TestAttachmentDispatch:
    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    async def test_no_attachments_preserves_baseline_body(self) -> None:
        endpoint = "https://example.test/chat"
        with respx.mock(base_url="https://example.test") as mock:
            route = mock.post("/chat").mock(return_value=httpx.Response(200, json={"output": "ok"}))
            adapter = HttpAdapter(
                endpoint=endpoint,
                shape="generic",
                request_template='{"input": "{prompt}"}',
                response_jsonpath="$.output",
            )
            try:
                text = await adapter.call("hello")
            finally:
                await adapter.aclose()
            assert text == "ok"
            assert route.call_count == 1
            body = json.loads(route.calls[0].request.content)
            assert body == {"input": "hello"}
            # Baseline regression: no attachments key sneaks in.
            assert "attachments" not in body

    async def test_attachments_appear_under_default_key_map(self) -> None:
        endpoint = "https://example.test/finbot/chat"
        with respx.mock(base_url="https://example.test") as mock:
            route = mock.post("/finbot/chat").mock(
                return_value=httpx.Response(200, json={"output": "saw it"})
            )
            adapter = HttpAdapter(
                endpoint=endpoint,
                shape="generic",
                request_template='{"input": "{prompt}"}',
                response_jsonpath="$.output",
                supports_vision=True,
            )
            try:
                text = await adapter.call("what's in this image?", attachments=(_attachment(),))
            finally:
                await adapter.aclose()
            assert text == "saw it"
            assert route.call_count == 1
            body = json.loads(route.calls[0].request.content)
            assert body["input"] == "what's in this image?"
            assert isinstance(body["attachments"], list)
            assert len(body["attachments"]) == 1
            att_body = body["attachments"][0]
            # Default key map: b64 (not b64_payload), alt (not alt_text).
            assert att_body["mime_type"] == "image/png"
            assert att_body["b64"] == base64.b64encode(_TINY_PNG_BYTES).decode("ascii")
            assert att_body["alt"] == "tiny test png"
            assert att_body["size_bytes"] == len(_TINY_PNG_BYTES)

    async def test_custom_key_map_renames_fields(self) -> None:
        # Different upstream that expects {"image", "data", "label"} keys.
        with respx.mock(base_url="https://other.test") as mock:
            route = mock.post("/v1").mock(return_value=httpx.Response(200, json={"output": "ok"}))
            adapter = HttpAdapter(
                endpoint="https://other.test/v1",
                shape="generic",
                request_template='{"input": "{prompt}"}',
                response_jsonpath="$.output",
                supports_vision=True,
                attachments_key_map={
                    "mime_type": "image",
                    "b64_payload": "data",
                    "alt_text": "label",
                },
            )
            try:
                await adapter.call("describe", attachments=(_attachment(),))
            finally:
                await adapter.aclose()
            body = json.loads(route.calls[0].request.content)
            att_body = body["attachments"][0]
            assert att_body["image"] == "image/png"
            assert "data" in att_body
            assert att_body["label"] == "tiny test png"

    async def test_custom_attachments_field_name(self) -> None:
        with respx.mock(base_url="https://example.test") as mock:
            route = mock.post("/v2").mock(return_value=httpx.Response(200, json={"output": "ok"}))
            adapter = HttpAdapter(
                endpoint="https://example.test/v2",
                shape="generic",
                request_template='{"input": "{prompt}"}',
                response_jsonpath="$.output",
                supports_vision=True,
                attachments_field="media",
            )
            try:
                await adapter.call("describe", attachments=(_attachment(),))
            finally:
                await adapter.aclose()
            body = json.loads(route.calls[0].request.content)
            assert "attachments" not in body
            assert isinstance(body["media"], list)


@pytest.mark.anyio
class TestSupportsVisionGuard:
    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    async def test_attachments_without_supports_vision_raises(self) -> None:
        adapter = HttpAdapter(
            endpoint="https://example.test/x",
            shape="generic",
            request_template='{"input": "{prompt}"}',
            response_jsonpath="$.output",
        )
        try:
            with pytest.raises(LLMPermanentError, match="supports_vision=False"):
                await adapter.call("x", attachments=(_attachment(),))
        finally:
            await adapter.aclose()

    async def test_supports_vision_default_is_false(self) -> None:
        adapter = HttpAdapter(
            endpoint="https://example.test/x",
            shape="generic",
            request_template='{"input": "{prompt}"}',
            response_jsonpath="$.output",
        )
        try:
            assert adapter.supports_vision is False
        finally:
            await adapter.aclose()


@pytest.mark.anyio
class TestTargetErrorLabeling:
    """QA #109 issue 1 — target HTTP faults must NOT read as LLM-provider
    faults. The adapter raises ``Target*`` error subclasses so the shared
    retry log line ("retry N/3 (<ClassName>: …)") names the target, while the
    subclassing keeps the retry/backoff behaviour identical."""

    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    async def test_network_error_raises_target_transient(self) -> None:
        from agent_guardian.llm.errors import LLMTransientError, TargetTransientError

        with respx.mock(base_url="https://unreachable.test") as mock:
            mock.post("/chat").mock(side_effect=httpx.ConnectError("getaddrinfo failed"))
            adapter = HttpAdapter(
                endpoint="https://unreachable.test/chat",
                shape="generic",
                request_template='{"input": "{prompt}"}',
                response_jsonpath="$.output",
                max_retries=0,  # no backoff sleep in the test
            )
            try:
                with pytest.raises(TargetTransientError) as caught:
                    await adapter.call("hi")
            finally:
                await adapter.aclose()
            # Still retryable (the wrapper keys off LLMTransientError).
            assert isinstance(caught.value, LLMTransientError)
            assert type(caught.value).__name__ == "TargetTransientError"
            assert "http: network error" in str(caught.value)

    async def test_timeout_raises_target_timeout(self) -> None:
        from agent_guardian.llm.errors import LLMTimeoutError, TargetTimeoutError

        with respx.mock(base_url="https://slow.test") as mock:
            mock.post("/chat").mock(side_effect=httpx.ConnectTimeout("slow"))
            adapter = HttpAdapter(
                endpoint="https://slow.test/chat",
                shape="generic",
                request_template='{"input": "{prompt}"}',
                response_jsonpath="$.output",
                max_retries=0,
            )
            try:
                with pytest.raises(TargetTimeoutError) as caught:
                    await adapter.call("hi")
            finally:
                await adapter.aclose()
            assert isinstance(caught.value, LLMTimeoutError)
            assert type(caught.value).__name__ == "TargetTimeoutError"

    async def test_5xx_raises_target_transient(self) -> None:
        from agent_guardian.llm.errors import LLMTransientError, TargetTransientError

        with respx.mock(base_url="https://down.test") as mock:
            mock.post("/chat").mock(return_value=httpx.Response(503, text="down"))
            adapter = HttpAdapter(
                endpoint="https://down.test/chat",
                shape="generic",
                request_template='{"input": "{prompt}"}',
                response_jsonpath="$.output",
                max_retries=0,
            )
            try:
                with pytest.raises(TargetTransientError) as caught:
                    await adapter.call("hi")
            finally:
                await adapter.aclose()
            assert isinstance(caught.value, LLMTransientError)
