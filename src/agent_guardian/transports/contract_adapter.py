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

* **Data egress (checked first).** When the contract forbids external egress and
  the prompt names an external sink, the turn is **not sent** and an
  :class:`~agent_guardian.core.roe.EgressRefused` is raised so the agent loop
  records the turn as *not tested* (and excludes it from clean verdicts). The
  refused turn is counted in ``roe.egress_refused_turns`` but does **not**
  consume the ``max_requests`` budget — it never left the process — so the gate
  is evaluated before :meth:`RoeController.acquire`.
* **Rate limiting + request cap.** ``await roe.acquire()`` paces every *sent*
  turn and enforces ``roe.budgets.max_requests``. A :class:`RoeBudgetExceeded`
  is allowed to propagate: the agent loop treats a raised ``target.call`` as
  terminating, which is the intended hard stop when a budget is blown.
* **Adaptive rate limiting.** Every response is fed to
  :meth:`RoeController.observe_response`, so an observed ``429`` backs the pacing
  off (AIMD) — *even when the contract set no ``roe.rate.max_rps``* (default-on).
* **Tool-call screening (observe-only on HTTP/cloud).** Every tool call the
  target surfaces is recorded against the allow/block policy; disallowed calls
  are counted (and their names recorded) for the audit. **For HTTP / cloud
  transports this is post-hoc**: the target has already executed the tool by the
  time it surfaces in the reply, so recording it here is an audit/scoring signal,
  not a live block. Only :class:`~agent_guardian.transports.mcp.McpTransport`
  refuses a blocklisted tool *before* it executes (via the live tool gate wired
  in :func:`build_contract_target_adapter`). Allowed calls open an
  ``execute_tool`` span.
* **Observability.** Each send is wrapped in a ``transport.send`` span and the
  response's token usage is stamped onto the current span. Both are no-ops when
  the OTel gate is closed, so the default install pays nothing.
* **Session isolation.** When the contract sets ``session.isolate_per_scenario``,
  each distinct ``session`` id passed to :meth:`ContractTargetAdapter.call` gets
  its own :class:`~agent_guardian.transports.session.SessionMachine`, so
  conversation state does not bleed across adversarial scenarios.

A faulted :class:`~agent_guardian.transports.base.Response` (``error`` set) is
turned into a ``RuntimeError`` so the agent loop's existing ``try/except``
records the failed turn — the transport itself never raises for faults, but the
engine expects a callable that can.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.core.roe import EgressRefused
from agent_guardian.obs.otel import set_usage, tool_span, transport_span
from agent_guardian.transports.base import Request
from agent_guardian.transports.factory import (
    build_session_machine,
    build_transport,
)
from agent_guardian.transports.mcp import McpTransport

if TYPE_CHECKING:
    from agent_guardian.contract.schema import Contract
    from agent_guardian.core.roe import RoeController
    from agent_guardian.transports.base import Response, Transport
    from agent_guardian.transports.session import SessionMachine

__all__ = [
    "ContractTargetAdapter",
    "build_contract_target_adapter",
]


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
        isolate_per_scenario: bool = False,
    ) -> None:
        super().__init__()
        self._transport = transport
        self._session_machine = session_machine
        self._roe = roe
        # When the contract asks for per-scenario isolation, each distinct
        # ``session`` id seen at ``call`` gets its own SessionMachine forked off
        # the template one (same transport + mode, fresh state), so conversation
        # state never bleeds across adversarial scenarios. Disabled (or absent
        # session machine) → the single shared machine is used for every turn.
        self._isolate_per_scenario = isolate_per_scenario and session_machine is not None
        self._scenario_machines: dict[str, SessionMachine] = {}
        # ``endpoint`` is exposed by HttpTransport; fall back gracefully for any
        # future transport that does not surface one.
        self._endpoint: str = str(getattr(transport, "endpoint", "transport"))
        # Precompute the bare host once so the observability seam never even
        # sees a URL that might carry an embedded ``?key=...`` API secret. The
        # ``transport_span`` helper redacts defensively, but parsing the host
        # here means a future obs change cannot accidentally re-leak the
        # credential through the span name. ``None`` for in-process sentinels.
        self._endpoint_host: str | None = urlparse(self._endpoint).hostname
        # When the transport screens tools *live* (an McpTransport with its
        # ``_tool_gate`` wired to ``roe.record_tool_call``), the gate has already
        # recorded every tool decision before the call returns. The post-hoc
        # ``_record_tool_calls`` path must then only *trace* the surfaced calls,
        # never re-record them — re-recording would double-count the audit.
        self._live_tool_gate = (
            isinstance(transport, McpTransport) and transport._tool_gate is not None
        )
        self._fingerprint = fingerprint or TargetFingerprint(
            mode="http",
            ref=self._endpoint,
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def _machine_for(self, session: str | None) -> SessionMachine | None:
        """Pick the SessionMachine for ``session``, forking one when isolating.

        Without per-scenario isolation (or with no session machine at all) the
        single shared machine — or ``None`` for a direct send — is used. With
        isolation on, each distinct ``session`` id gets its own machine (forked
        from the template via ``isolate_per_scenario``) so two scenarios never
        share conversation state. A ``None`` session id under isolation falls
        back to the shared machine (a scenario that opts out of an id).
        """
        if not self._isolate_per_scenario or session is None:
            return self._session_machine
        machine = self._scenario_machines.get(session)
        if machine is None:
            # ``self._session_machine`` is non-None here (guarded in __init__).
            assert self._session_machine is not None
            machine = self._session_machine.isolate_per_scenario()
            self._scenario_machines[session] = machine
        return machine

    async def _send(self, prompt: str, session: str | None) -> Response:
        """Send one turn via the (possibly per-scenario) session machine."""
        machine = self._machine_for(session)
        if machine is not None:
            return await machine.send(prompt)
        return await self._transport.send(Request(prompt=prompt))

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        """Send one user-turn through the RoE chokepoint and return the reply text.

        ``session`` selects the conversation: with ``session.isolate_per_scenario``
        each distinct id drives its own :class:`SessionMachine` so scenario state
        does not bleed (see :meth:`_machine_for`).

        Raises:
            EgressRefused: the contract forbids external egress and ``prompt``
                names an external sink. The turn is *not* sent and does not
                consume the request budget; the agent loop records it as not
                tested.
            RoeBudgetExceeded: admitting this send would exceed ``max_requests``.
            RuntimeError: the transport returned a faulted response.
        """
        # Data-egress gate FIRST — before acquire() — so a refused turn never
        # consumes the max_requests budget (#12). We raise EgressRefused rather
        # than fabricate a refusal string the judge would mis-score as clean.
        if self._roe is not None and not self._roe.egress_allowed(prompt):
            self._roe.note_egress_refused()
            raise EgressRefused(
                "request not sent: the contract's Rules of Engagement forbid "
                "external data egress (roe.data_egress.allow_external = false)"
            )

        # Pace + count this (actually-sent) request and enforce max_requests. A
        # blown budget raises RoeBudgetExceeded, which we deliberately propagate.
        if self._roe is not None:
            await self._roe.acquire()

        # The transport span wraps ONLY the network call; tool-call spans land
        # outside it so they are parented by the surrounding ``invoke_agent``
        # span (per GenAI semconv, ``execute_tool`` is sibling-of /
        # child-of-invoke_agent, never child-of-transport.send).
        with transport_span(self._endpoint, conversation_id=session):
            response = await self._send(prompt, session)

            # Adaptive rate limiting: feed EVERY response to the controller so an
            # observed 429 backs the pacing off — default-on even with no
            # configured max_rps. ``observe_response`` is a no-op for any
            # non-rate-limit response, so we blanket-feed without branching.
            if self._roe is not None:
                self._roe.observe_response(response)

            if response.error is not None:
                err = response.error
                raise RuntimeError(f"transport error: {err.category.value}: {err.message}")

            # set_usage routes through the ContextVar to the surrounding
            # ``invoke_agent`` span — NOT the transport span — even when called
            # from inside this ``with transport_span(...)`` block. Per GenAI
            # semconv, ``gen_ai.usage.*`` belongs on the agent span.
            set_usage(
                input_tokens=response.usage.prompt_tokens,
                output_tokens=response.usage.completion_tokens,
            )

        # Tool-call spans are opened AFTER the transport span has closed so
        # they are not parented by ``transport.send``. With an active
        # ``invoke_agent`` span in scope (set by ``make_otel_observer``) they
        # are correctly parented by it instead.
        self._record_tool_calls(response)
        return response.text

    def _record_tool_calls(self, response: Response) -> None:
        """Screen + trace each tool call the target surfaced in its reply.

        For HTTP / cloud transports the call is recorded against the RoE
        allow/block policy here (which counts suppressions + records the offered
        blocklisted tool names for the audit); allowed calls open an
        ``execute_tool`` span. When there is no RoE controller every observed
        call is simply traced.

        **This is observe-only on HTTP / cloud transports**: the target has
        already executed the tool by the time it appears in the reply, so a
        recorded suppression is post-hoc evidence the target *offered* a
        screened-out tool, not proof it was prevented from running. Only the live
        MCP tool gate (below) blocks pre-execution.

        For an MCP transport whose ``_tool_gate`` is wired live, the gate already
        recorded each decision *before* invocation (refusing a blocklisted tool
        before its ``tools/call``), so this path must not re-record — it only
        opens a span for the surfaced (allowed) calls to avoid double-counting the
        audit. A blocked MCP tool is suppressed by the gate and never executed, so
        the suppressed-attempt count is already correct.

        Span policy: a span is only opened for an *allowed* tool. A blocked
        tool gets no ``execute_tool`` span — emitting one would imply the tool
        ran, which is misleading observability. On the live-gate path the
        ``McpTransport`` has already recorded the blocked tool name in
        :attr:`RoeController.observed_blocklisted_tools` *before* this method
        runs (see :func:`McpTransport._send`), so we check membership there to
        decide whether to span.
        """
        for call in response.tool_calls:
            if self._live_tool_gate:
                # The MCP live gate ran ``record_tool_call`` for us already;
                # consult its outcome via the recorded blocklist set so we do
                # not span a tool that was actually blocked (a span here would
                # falsely imply the tool executed). ``self._roe`` is required
                # to wire the live gate, but ``getattr`` keeps the type-checker
                # happy and is a no-op when missing.
                blocked_names: frozenset[str] = (
                    self._roe.observed_blocklisted_tools if self._roe is not None else frozenset()
                )
                allowed = call.name not in blocked_names
            elif self._roe is not None:
                allowed = self._roe.record_tool_call(call.name)
            else:
                allowed = True
            if not allowed:
                continue
            with tool_span(call.name, arguments=call.arguments):
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

    **Live tool-block wiring.** When the built transport is an
    :class:`~agent_guardian.transports.mcp.McpTransport` and a
    :class:`RoeController` is present, the controller's
    :meth:`RoeController.record_tool_call` is installed as the transport's
    ``tool_gate``. That makes a blocklisted (or non-allowlisted) tool be
    *refused before* the ``tools/call`` executes — a live block — while
    ``record_tool_call`` still counts the suppression for the audit. The gate is
    handed as a plain ``Callable[[str], bool]`` so the transport never learns the
    :class:`RoeController` type (the decoupling rule). HTTP / cloud transports
    surface tool calls only after the fact, so they keep the post-hoc
    :meth:`ContractTargetAdapter._record_tool_calls` screening unchanged.
    """
    transport = build_transport(contract)
    if isinstance(transport, McpTransport) and roe is not None:
        # Plain callable, not the RoeController itself: the transport refuses a
        # destructive tool live (no tools/call) and the controller counts it.
        # ``_tool_gate`` is the field the transport's send() consults before any
        # tools/call; injecting it here keeps the transport decoupled from RoE.
        transport._tool_gate = roe.record_tool_call
    session_machine = build_session_machine(contract, transport)
    fingerprint = _fingerprint_from_contract(contract, str(getattr(transport, "endpoint", "")))
    return ContractTargetAdapter(
        transport=transport,
        session_machine=session_machine,
        roe=roe,
        fingerprint=fingerprint,
        isolate_per_scenario=contract.target.session.isolate_per_scenario,
    )


def _fingerprint_from_contract(contract: Contract, endpoint: str) -> TargetFingerprint:
    """Derive the static attack-surface fingerprint from a contract.

    ``has_tools`` and ``declared_tools`` come from ``target.tools.expected`` when
    the contract declares any; ``is_multi_agent`` honours the explicit contract
    declaration (``target.is_multi_agent: true`` — GAP-2) so a multi-agent
    orchestrator opens the ASI06/07/10 lanes from turn 0 without waiting for
    recon to observe a ``transfer_to_agent`` call. Everything else stays at the
    conservative black-box default the recon agent refines during phase 1.
    """
    tools = contract.target.tools
    declared_tools: list[str] = [t.name for t in tools.expected] if tools else []
    return TargetFingerprint(
        mode="http",
        ref=endpoint or contract.target.name,
        has_tools=bool(declared_tools),
        is_multi_agent=contract.target.is_multi_agent,
        multi_agent_detected=contract.target.is_multi_agent,
        declared_tools=declared_tools,
        notes="Stage 1B — contract-driven HTTP transport.",
    )
