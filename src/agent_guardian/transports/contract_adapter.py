"""Contract-driven target adapter — the single global call chokepoint (Stage 1B).

:class:`ContractTargetAdapter` is the bridge between the existing swarm engine
and the contract-built transport. The agent loop only ever knows the
:class:`~agent_guardian.adapters.base.TargetAdapter` interface
(``await target.call(prompt, session=...)``); this adapter satisfies it by
driving a :class:`~agent_guardian.transports.base.Transport` (through a
:class:`~agent_guardian.transports.session.SessionMachine` when one is present)
and returning the response text.

Because **every** target call in a scan flows through this one ``call`` method,
it is the natural — and only — place to enforce the contract's Rules of
Engagement at request time, without touching the 1894-line orchestrator:

* **Rate limiting + request cap.** ``await roe.acquire()`` paces every send and
  enforces ``roe.budgets.max_requests``. A :class:`RoeBudgetExceeded` is allowed
  to propagate: the agent loop treats a raised ``target.call`` as terminating,
  which is the intended hard stop when a budget is blown.
* **Data egress.** When the contract forbids external egress, the prompt is not
  sent at all — a benign refusal string is returned so the agent observes a
  declined turn rather than a network call.
* **Tool-call screening.** Every tool call the target surfaces is recorded
  against the allow/block policy; disallowed calls are counted (suppressed) for
  the audit. Allowed calls open an ``execute_tool`` span.
* **Observability.** Each send is wrapped in a ``transport.send`` span and the
  response's token usage is stamped onto the current span. Both are no-ops when
  the OTel gate is closed, so the default install pays nothing.

A faulted :class:`~agent_guardian.transports.base.Response` (``error`` set) is
turned into a ``RuntimeError`` so the agent loop's existing ``try/except``
records the failed turn — the transport itself never raises for faults, but the
engine expects a callable that can.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.obs.otel import set_usage, tool_span, transport_span
from agent_guardian.transports.base import Request
from agent_guardian.transports.factory import (
    build_session_machine,
    build_transport,
)

if TYPE_CHECKING:
    from agent_guardian.contract.schema import Contract
    from agent_guardian.core.roe import RoeController
    from agent_guardian.transports.base import Response, Transport
    from agent_guardian.transports.session import SessionMachine

__all__ = [
    "ContractTargetAdapter",
    "build_contract_target_adapter",
]

# Returned (without sending) when the contract forbids external data egress, so
# the agent observes a declined turn instead of a network call.
_EGRESS_REFUSAL = (
    "[agent-guardian] request not sent: the contract's Rules of Engagement "
    "forbid external data egress (roe.data_egress.allow_external = false)."
)


class ContractTargetAdapter(TargetAdapter):
    """A :class:`TargetAdapter` over a contract-built transport — the RoE chokepoint."""

    mode = "http"

    def __init__(
        self,
        *,
        transport: Transport,
        session_machine: SessionMachine | None = None,
        roe: RoeController | None = None,
        fingerprint: TargetFingerprint | None = None,
    ) -> None:
        super().__init__()
        self._transport = transport
        self._session_machine = session_machine
        self._roe = roe
        # ``endpoint`` is exposed by HttpTransport; fall back gracefully for any
        # future transport that does not surface one.
        self._endpoint: str = str(getattr(transport, "endpoint", "transport"))
        self._fingerprint = fingerprint or TargetFingerprint(
            mode="http",
            ref=self._endpoint,
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    async def _send(self, prompt: str) -> Response:
        """Send one turn via the session machine when present, else directly."""
        if self._session_machine is not None:
            return await self._session_machine.send(prompt)
        return await self._transport.send(Request(prompt=prompt))

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        """Send one user-turn through the RoE chokepoint and return the reply text.

        ``session`` is accepted for interface compatibility with the engine; the
        contract's :class:`SessionMachine` owns conversation state, so the
        per-call session id is not threaded into the transport here (a future
        stage maps it onto ``session.id_send``).
        """
        # Pace + count this request and enforce the max_requests cap. A blown
        # budget raises RoeBudgetExceeded, which we deliberately let propagate.
        if self._roe is not None:
            await self._roe.acquire()
            # Data-egress gate: do not send the prompt at all when external
            # egress is forbidden — return a benign refusal instead.
            if not self._roe.egress_allowed(prompt):
                return _EGRESS_REFUSAL

        with transport_span(self._endpoint):
            response = await self._send(prompt)

            if response.error is not None:
                err = response.error
                raise RuntimeError(f"transport error: {err.category.value}: {err.message}")

            self._record_tool_calls(response)
            set_usage(
                input_tokens=response.usage.prompt_tokens,
                output_tokens=response.usage.completion_tokens,
            )
            return response.text

    def _record_tool_calls(self, response: Response) -> None:
        """Screen + trace each tool call the target surfaced in its reply.

        Every call is recorded against the RoE allow/block policy (which counts
        suppressions for the audit); allowed calls open an ``execute_tool`` span.
        When there is no RoE controller every observed call is simply traced.
        """
        for call in response.tool_calls:
            allowed = True
            if self._roe is not None:
                allowed = self._roe.record_tool_call(call.name)
            if allowed:
                with tool_span(call.name):
                    pass

    async def aclose(self) -> None:
        await self._transport.aclose()


def build_contract_target_adapter(
    contract: Contract,
    *,
    roe: RoeController | None = None,
) -> ContractTargetAdapter:
    """Wire a :class:`ContractTargetAdapter` straight from a contract.

    Builds the transport + session machine from the contract via the factory,
    derives the static :class:`TargetFingerprint` from the contract's declared
    tools, and hands the optional :class:`RoeController` to the adapter so RoE is
    enforced at the single call chokepoint.
    """
    transport = build_transport(contract)
    session_machine = build_session_machine(contract, transport)
    fingerprint = _fingerprint_from_contract(contract, str(getattr(transport, "endpoint", "")))
    return ContractTargetAdapter(
        transport=transport,
        session_machine=session_machine,
        roe=roe,
        fingerprint=fingerprint,
    )


def _fingerprint_from_contract(contract: Contract, endpoint: str) -> TargetFingerprint:
    """Derive the static attack-surface fingerprint from a contract.

    ``has_tools`` and ``declared_tools`` come from ``target.tools.expected`` when
    the contract declares any; everything else stays at the conservative
    black-box default the recon agent refines during phase 1.
    """
    tools = contract.target.tools
    declared_tools: list[str] = [t.name for t in tools.expected] if tools else []
    return TargetFingerprint(
        mode="http",
        ref=endpoint or contract.target.name,
        has_tools=bool(declared_tools),
        declared_tools=declared_tools,
        notes="Stage 1B — contract-driven HTTP transport.",
    )
