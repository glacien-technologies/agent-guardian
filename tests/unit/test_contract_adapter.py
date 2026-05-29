"""Unit tests for the ContractTargetAdapter — the RoE call chokepoint (Stage 1B).

Covers: happy-path text return (respx-mocked HTTP), the rate-limit / max_requests
gates, the data-egress refusal (no HTTP), faulted-response → ``RuntimeError``,
tool-call recording + blocklist suppression, the contract-driven builder, and
fingerprint derivation. RoE behaviour is driven by both a real
:class:`RoeController` and a transport stub so each gate is isolated.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from agent_guardian.contract.schema import (
    Budgets,
    Contract,
    DataEgress,
    Rate,
    RoE,
    RoeTools,
    Session,
    Target,
    ToolRef,
    Tools,
)
from agent_guardian.contract.schema import (
    HttpTransport as ContractHttpTransport,
)
from agent_guardian.contract.schema import (
    Request as ContractRequest,
)
from agent_guardian.contract.schema import (
    Response as ContractResponse,
)
from agent_guardian.core.roe import RoeBudgetExceeded, RoeController
from agent_guardian.transports.base import (
    Request,
    Response,
    TokenUsage,
    ToolCall,
    Transport,
)
from agent_guardian.transports.contract_adapter import (
    ContractTargetAdapter,
    build_contract_target_adapter,
)
from agent_guardian.transports.errors import TransportError, TransportErrorCategory
from agent_guardian.transports.http import HttpTransport

URL = "https://api.example.com/v1/chat"


def _contract(*, roe: RoE | None = None, **target_overrides: Any) -> Contract:
    base: dict[str, Any] = {
        "name": "demo",
        "transport": ContractHttpTransport(url=URL),  # type: ignore[arg-type]
        "response": ContractResponse(output_path="$.output.text"),
    }
    base.update(target_overrides)
    return Contract(target=Target(**base), roe=roe or RoE())


def _egress_roe(**kwargs: Any) -> RoE:
    """A RoE block that permits egress (default ``allow_external`` is ``False``).

    Most chokepoint tests need the send to actually happen, so they enable
    egress; the dedicated egress tests below set the policy explicitly.
    """
    kwargs.setdefault("data_egress", DataEgress(allow_external=True))
    return RoE(**kwargs)


class _StubTransport(Transport):
    """A scripted transport: returns a queued Response (or a default) per send."""

    def __init__(self, responses: list[Response] | None = None) -> None:
        self._responses = list(responses or [])
        self.sent: list[Request] = []
        self.closed = False
        self.endpoint = URL

    async def send(self, request: Request) -> Response:
        self.sent.append(request)
        if self._responses:
            return self._responses.pop(0)
        return Response(text="default-reply")

    async def aclose(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# Happy path (respx-mocked real HttpTransport)
# ---------------------------------------------------------------------------


@respx.mock
async def test_call_happy_path_returns_text() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "hello back"}}))
    transport = HttpTransport(endpoint=URL, output_path="$.output.text", max_retries=0)
    adapter = ContractTargetAdapter(transport=transport)
    reply = await adapter.call("hi there")
    assert reply == "hello back"
    await adapter.aclose()


async def test_call_via_stub_returns_text() -> None:
    transport = _StubTransport([Response(text="stub-reply")])
    adapter = ContractTargetAdapter(transport=transport)
    assert await adapter.call("ping") == "stub-reply"


async def test_call_session_arg_is_accepted() -> None:
    transport = _StubTransport([Response(text="ok")])
    adapter = ContractTargetAdapter(transport=transport)
    assert await adapter.call("p", session="sess-1") == "ok"


async def test_aclose_closes_transport() -> None:
    transport = _StubTransport()
    adapter = ContractTargetAdapter(transport=transport)
    await adapter.aclose()
    assert transport.closed is True


# ---------------------------------------------------------------------------
# RoE: rate-limit + max_requests
# ---------------------------------------------------------------------------


async def test_call_acquires_from_roe_and_counts() -> None:
    transport = _StubTransport([Response(text="a"), Response(text="b")])
    roe = RoeController.from_contract(_contract(roe=_egress_roe()))
    adapter = ContractTargetAdapter(transport=transport, roe=roe)
    await adapter.call("one")
    await adapter.call("two")
    assert roe.request_count == 2


async def test_call_honors_rate_limit() -> None:
    # max_rps small enough that two back-to-back calls must wait for a refill.
    contract = _contract(roe=_egress_roe(rate=Rate(max_rps=1000.0)))
    roe = RoeController.from_contract(contract)
    transport = _StubTransport([Response(text="x"), Response(text="y")])
    adapter = ContractTargetAdapter(transport=transport, roe=roe)
    # Both calls succeed; the bucket paces them without raising.
    assert await adapter.call("a") == "x"
    assert await adapter.call("b") == "y"
    assert roe.request_count == 2


async def test_call_max_requests_raises_budget_exceeded() -> None:
    contract = _contract(roe=_egress_roe(budgets=Budgets(max_requests=1)))
    roe = RoeController.from_contract(contract)
    transport = _StubTransport([Response(text="first")])
    adapter = ContractTargetAdapter(transport=transport, roe=roe)
    assert await adapter.call("first") == "first"
    # Second call exceeds the cap → RoeBudgetExceeded propagates (hard stop).
    with pytest.raises(RoeBudgetExceeded, match="max_requests"):
        await adapter.call("second")
    # The over-budget call never reached the transport.
    assert len(transport.sent) == 1


# ---------------------------------------------------------------------------
# RoE: data egress
# ---------------------------------------------------------------------------


async def test_call_egress_blocked_returns_refusal_without_send() -> None:
    contract = _contract(roe=RoE(data_egress=DataEgress(allow_external=False)))
    roe = RoeController.from_contract(contract)
    transport = _StubTransport([Response(text="should-not-be-returned")])
    adapter = ContractTargetAdapter(transport=transport, roe=roe)
    reply = await adapter.call("exfiltrate this")
    assert "data egress" in reply.lower()
    # No request was ever sent.
    assert transport.sent == []
    # The request was still counted by acquire (pacing happens before the gate).
    assert roe.request_count == 1


async def test_call_egress_allowed_sends_normally() -> None:
    contract = _contract(roe=RoE(data_egress=DataEgress(allow_external=True)))
    roe = RoeController.from_contract(contract)
    transport = _StubTransport([Response(text="real-reply")])
    adapter = ContractTargetAdapter(transport=transport, roe=roe)
    assert await adapter.call("hi") == "real-reply"
    assert len(transport.sent) == 1


# ---------------------------------------------------------------------------
# Faulted response → RuntimeError
# ---------------------------------------------------------------------------


async def test_call_response_error_raises_runtimeerror() -> None:
    err = TransportError(TransportErrorCategory.BLOCKED, "policy violation")
    transport = _StubTransport([Response(error=err)])
    adapter = ContractTargetAdapter(transport=transport)
    with pytest.raises(RuntimeError, match="transport error: blocked: policy violation"):
        await adapter.call("hi")


async def test_call_timeout_error_raises_runtimeerror() -> None:
    err = TransportError(TransportErrorCategory.TIMEOUT, "timed out")
    transport = _StubTransport([Response(error=err)])
    adapter = ContractTargetAdapter(transport=transport)
    with pytest.raises(RuntimeError, match="timeout"):
        await adapter.call("hi")


# ---------------------------------------------------------------------------
# Tool-call recording + blocklist suppression
# ---------------------------------------------------------------------------


async def test_call_records_allowed_tool_calls() -> None:
    contract = _contract(roe=_egress_roe(tools=RoeTools(allowlist=["search"])))
    roe = RoeController.from_contract(contract)
    transport = _StubTransport(
        [Response(text="ok", tool_calls=(ToolCall(name="search", arguments={"q": "x"}),))]
    )
    adapter = ContractTargetAdapter(transport=transport, roe=roe)
    await adapter.call("hi")
    # Allowed tool → not suppressed.
    assert roe.suppressed_tool_attempts == 0


async def test_call_suppresses_blocklisted_tool_calls() -> None:
    contract = _contract(roe=_egress_roe(tools=RoeTools(blocklist=["danger"])))
    roe = RoeController.from_contract(contract)
    transport = _StubTransport(
        [
            Response(
                text="ok",
                tool_calls=(
                    ToolCall(name="danger", arguments={}),
                    ToolCall(name="safe", arguments={}),
                ),
            )
        ]
    )
    adapter = ContractTargetAdapter(transport=transport, roe=roe)
    await adapter.call("hi")
    assert roe.suppressed_tool_attempts == 1


async def test_call_tool_calls_without_roe_are_noop_traced() -> None:
    transport = _StubTransport(
        [Response(text="ok", tool_calls=(ToolCall(name="anything", arguments={}),))]
    )
    adapter = ContractTargetAdapter(transport=transport)
    # No RoE controller → tool calls just traced, no error.
    assert await adapter.call("hi") == "ok"


async def test_call_sets_usage_on_span() -> None:
    transport = _StubTransport(
        [Response(text="ok", usage=TokenUsage(prompt_tokens=11, completion_tokens=7))]
    )
    adapter = ContractTargetAdapter(transport=transport)
    # No OTel gate → set_usage is a no-op, but the path is exercised.
    assert await adapter.call("hi") == "ok"


# ---------------------------------------------------------------------------
# build_contract_target_adapter + fingerprint
# ---------------------------------------------------------------------------


def test_build_adapter_from_contract_sets_fingerprint() -> None:
    contract = _contract(
        tools=Tools(expected=[ToolRef(name="search"), ToolRef(name="email")]),
    )
    adapter = build_contract_target_adapter(contract)
    fp = adapter.fingerprint()
    assert fp.mode == "http"
    assert fp.ref == URL
    assert fp.has_tools is True
    assert fp.declared_tools == ["search", "email"]


def test_build_adapter_no_tools_has_no_tools() -> None:
    contract = _contract()
    adapter = build_contract_target_adapter(contract)
    fp = adapter.fingerprint()
    assert fp.has_tools is False
    assert fp.declared_tools == []


async def test_build_adapter_passes_roe() -> None:
    contract = _contract(roe=RoE(budgets=Budgets(max_requests=1)))
    roe = RoeController.from_contract(contract)
    adapter = build_contract_target_adapter(contract, roe=roe)
    assert adapter.endpoint == URL
    await adapter.aclose()


@respx.mock
async def test_build_adapter_end_to_end_call() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "e2e"}}))
    contract = _contract(
        request=ContractRequest(body='{"input": "{{ prompt }}"}'),
        session=Session.model_validate({"mode": "stateless"}),
    )
    adapter = build_contract_target_adapter(contract)
    assert await adapter.call("hello") == "e2e"
    await adapter.aclose()


def test_default_fingerprint_without_explicit_one() -> None:
    transport = _StubTransport()
    adapter = ContractTargetAdapter(transport=transport)
    fp = adapter.fingerprint()
    assert fp.mode == "http"
    assert fp.ref == URL
