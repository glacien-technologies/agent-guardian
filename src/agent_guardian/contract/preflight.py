"""Contract pre-flight — staged, payload-free validation of a target (Stage 1B).

``validate`` (and ``init``'s post-write check) drive :func:`run_preflight`, which
walks a contract through seven *non-adversarial* stages and stops at the first
failure. No attack payload is ever sent: the only prompts that leave the
perimeter are benign ("Hello, please introduce yourself") round-trips used to
prove the wiring works end-to-end before a real scan is authorised.

The seven stages mirror the operator's mental model of "can I even talk to this
thing, and am I allowed to?":

1. **resolve + lint** — load + validate the contract, print its redacted view.
2. **connect** — build the transport (+ session machine) from the contract
   primitives.
3. **authenticate / probe** — run :meth:`Transport.probe` (one benign turn,
   never raises) and classify the returned :class:`TransportError` category
   (auth → unreachable; provider-auth wording → LLM-provider exit code).
4. **benign round-trip** — print the probe's extracted reply text.
5. **session check** — for a stateful session, drive the session machine through
   two real turns and confirm the second turn continues (a stateless contract
   skips this with a note).
6. **capability report** — read :meth:`Transport.describe` and reconcile the RoE
   allow/block lists against the transport's discovered tool support / the
   contract's declared expected tools (a dangling ref is a config error).
7. **RoE echo** — print the budgets / environment / authorization_ref and refuse
   a ``prod`` scan with no ``authorization_ref`` (via :func:`authorization_gate`).

Every stage produces a :class:`StageResult`; the aggregate is a
:class:`PreflightReport` whose :attr:`PreflightReport.ok` is the AND of every
stage and whose :attr:`PreflightReport.first_failure` carries the exit code the
CLI should surface.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent_guardian.contract.errors import (
    ContractError,
    MigrationNeeded,
    SecretResolutionError,
    UnsupportedContractVersion,
)
from agent_guardian.contract.hashing import contract_sha256
from agent_guardian.contract.loader import load_contract
from agent_guardian.contract.secrets import redact
from agent_guardian.core.roe import RoeAuthorizationError, authorization_gate
from agent_guardian.transports.errors import TransportError, TransportErrorCategory
from agent_guardian.transports.factory import build_session_machine, build_transport

if TYPE_CHECKING:
    from agent_guardian.contract.schema import Contract
    from agent_guardian.transports.base import CapabilityReport, Transport
    from agent_guardian.transports.session import SessionMachine

_LOG = logging.getLogger(__name__)

__all__ = [
    "BENIGN_PROMPT",
    "PreflightReport",
    "StageResult",
    "run_preflight",
]

# Exit codes — mirrored from the CLI so preflight can be driven without a typer
# dependency (the CLI re-exports the same constants).
_EXIT_OK = 0
_EXIT_CONFIG = 2
_EXIT_TARGET_UNREACHABLE = 3
_EXIT_LLM_PROVIDER = 4

# The single benign probe prompt. Deliberately bland: it must never read as an
# attack so a pre-flight can run against a prod target the operator is merely
# checking connectivity for.
BENIGN_PROMPT = "Hello, please introduce yourself."
_BENIGN_FOLLOWUP = "Thank you. What did I just ask you?"

# Provider-auth fingerprints — substrings that mark an *LLM provider* auth
# failure (the operator's own key, not the target's). These map to
# EXIT_LLM_PROVIDER rather than EXIT_TARGET_UNREACHABLE.
_PROVIDER_AUTH_MARKERS = ("invalid api key", "incorrect api key", "authentication_error")


@dataclass(frozen=True)
class StageResult:
    """Outcome of one pre-flight stage.

    ``ok`` is the pass/fail bit. ``detail`` is a human-readable line printed for
    every stage (pass or fail). ``remediation`` is operator guidance attached to
    a failure. ``exit_code`` is the process exit code the CLI surfaces when this
    stage is the first failure (``EXIT_OK`` for a passing stage).
    """

    name: str
    ok: bool
    detail: str = ""
    remediation: str | None = None
    exit_code: int = _EXIT_OK


@dataclass
class PreflightReport:
    """The aggregate of every pre-flight stage that ran."""

    stages: list[StageResult] = field(default_factory=list)
    # The redacted contract view (stage 1) — printed by the CLI, included in
    # ``--json`` output. ``None`` until stage 1 succeeds.
    redacted_contract: dict[str, Any] | None = None
    contract_sha256: str | None = None

    @property
    def ok(self) -> bool:
        """True iff every stage that ran passed."""
        return all(stage.ok for stage in self.stages)

    @property
    def first_failure(self) -> StageResult | None:
        """The first failing stage, or ``None`` when every stage passed."""
        for stage in self.stages:
            if not stage.ok:
                return stage
        return None

    @property
    def exit_code(self) -> int:
        """The exit code to surface — the first failure's, else ``EXIT_OK``."""
        failure = self.first_failure
        return failure.exit_code if failure is not None else _EXIT_OK

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable mapping of the report."""
        return {
            "ok": self.ok,
            "exit_code": self.exit_code,
            "contract_sha256": self.contract_sha256,
            "redacted_contract": self.redacted_contract,
            "stages": [
                {
                    "name": stage.name,
                    "ok": stage.ok,
                    "detail": stage.detail,
                    "remediation": stage.remediation,
                    "exit_code": stage.exit_code,
                }
                for stage in self.stages
            ],
        }


def _classify_send_error(message: str) -> tuple[int, str]:
    """Classify a failed benign-probe error message into an exit code + remedy.

    A 401/403 (or auth-ish wording) against the *target* is a target-auth
    failure (EXIT_TARGET_UNREACHABLE). A recognised *LLM provider* auth marker
    maps to EXIT_LLM_PROVIDER so the operator knows to fix their own key.
    Everything else is treated as the target being unreachable.
    """
    lowered = message.lower()
    if any(marker in lowered for marker in _PROVIDER_AUTH_MARKERS):
        return (
            _EXIT_LLM_PROVIDER,
            "An LLM-provider credential looks wrong. Check the provider API key "
            "(this is your own key, not the target's auth).",
        )
    if "401" in lowered or "unauthor" in lowered or "403" in lowered or "forbidden" in lowered:
        return (
            _EXIT_TARGET_UNREACHABLE,
            "The target rejected the credential (401/403). Verify the contract's "
            "'auth' block and that the referenced secret resolves to a valid token.",
        )
    return (
        _EXIT_TARGET_UNREACHABLE,
        "The target could not be reached or returned a transport fault. Check the "
        "transport URL, network reachability, and the response 'output_path'.",
    )


def _classify_transport_error(error: TransportError) -> tuple[int, str]:
    """Classify a :class:`TransportError` into an exit code + remediation.

    Prefers the structured :class:`TransportErrorCategory` over string matching:
    an ``AUTH`` fault whose message carries a recognised *LLM provider* marker is
    an EXIT_LLM_PROVIDER (the operator's own key); any other fault is a target
    problem (EXIT_TARGET_UNREACHABLE). The message is still consulted for the
    provider-vs-target auth distinction the category alone cannot make.
    """
    message = error.message
    lowered = message.lower()
    if error.category is TransportErrorCategory.AUTH and any(
        marker in lowered for marker in _PROVIDER_AUTH_MARKERS
    ):
        return (
            _EXIT_LLM_PROVIDER,
            "An LLM-provider credential looks wrong. Check the provider API key "
            "(this is your own key, not the target's auth).",
        )
    if error.category is TransportErrorCategory.AUTH:
        return (
            _EXIT_TARGET_UNREACHABLE,
            "The target rejected the credential (401/403). Verify the contract's "
            "'auth' block and that the referenced secret resolves to a valid token.",
        )
    # Fall back to the message-based classifier for everything else so an LLM
    # provider marker surfacing under a non-AUTH category is still caught.
    return _classify_send_error(message)


# Canonical stage order — used to validate ``stop_after`` and to short-circuit
# the walk once the requested stage has run. Mirrors the ``name=`` values each
# stage records on its ``StageResult``.
PREFLIGHT_STAGE_ORDER: tuple[str, ...] = (
    "resolve+lint",
    "connect",
    "authenticate/probe",
    "benign-round-trip",
    "session-check",
    "capability-report",
    "roe-echo",
)


def _reached_stop(report: PreflightReport, stop_after: str | None) -> bool:
    """True once ``stop_after`` is set and that stage has been recorded.

    Checked right after each stage so the walk halts as soon as the requested
    stage completes — so ``--stage connect`` does NOT pay the cost of the slow,
    retrying probe stage that follows.
    """
    if not stop_after:
        return False
    return any(stage.name == stop_after for stage in report.stages)


async def run_preflight(contract_path: Path, *, stop_after: str | None = None) -> PreflightReport:
    """Run the seven-stage pre-flight against the contract at ``contract_path``.

    Stops at the first failing stage and returns a :class:`PreflightReport`. No
    attack payload is ever sent — the only egress is a benign introduce-yourself
    round-trip used to prove the wiring.

    When ``stop_after`` names a stage (one of :data:`PREFLIGHT_STAGE_ORDER`), the
    walk halts as soon as that stage has run — so a connectivity-only check
    (``stop_after="connect"``) never pays the cost of the slow probe/session
    stages. An unknown ``stop_after`` is ignored (the full walk runs).
    """
    report = PreflightReport()

    # --- Stage 1: resolve + lint -------------------------------------------
    contract = _stage_resolve(contract_path, report)
    if contract is None:
        return report
    if _reached_stop(report, stop_after):
        return report

    # --- Stage 2: connect (build the transport + session machine) ----------
    built = _stage_connect(contract, report)
    if built is None:
        return report
    transport, session_machine = built

    # Halt before the probe stage if the operator only asked to reach connect —
    # close the just-built transport so we don't leak the client.
    if _reached_stop(report, stop_after):
        await transport.aclose()
        return report

    try:
        # --- Stage 3: authenticate / probe (transport.probe) --------------
        first_reply = await _stage_probe(transport, report)
        if first_reply is None:
            return report
        if _reached_stop(report, stop_after):
            return report

        # --- Stage 4: benign round-trip (extract + print reply) -----------
        _stage_round_trip(first_reply, report)
        if not report.ok or _reached_stop(report, stop_after):
            return report

        # --- Stage 5: session check (2 real turns for stateful contracts) -
        await _stage_session(contract, session_machine, report)
        if not report.ok or _reached_stop(report, stop_after):
            return report
    finally:
        await transport.aclose()

    # --- Stage 6: capability report (transport.describe) -------------------
    _stage_capability(contract, transport, report)
    if not report.ok or _reached_stop(report, stop_after):
        return report

    # --- Stage 7: RoE echo + authorization gate ----------------------------
    _stage_roe(contract, report)
    return report


# ---------------------------------------------------------------------------
# Stage implementations
# ---------------------------------------------------------------------------


def _stage_resolve(contract_path: Path, report: PreflightReport) -> Contract | None:
    """Stage 1 — load + validate the contract and record its redacted view."""
    try:
        contract = load_contract(contract_path)
    except MigrationNeeded as exc:
        report.stages.append(
            StageResult(
                name="resolve+lint",
                ok=False,
                detail=f"contract requires migration: {exc}",
                remediation="Run `agent-guardian contract migrate <file> --write` first.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return None
    except UnsupportedContractVersion as exc:
        report.stages.append(
            StageResult(
                name="resolve+lint",
                ok=False,
                detail=f"unsupported contract version: {exc}",
                remediation="Author the contract against the current schema version, "
                "or upgrade AgentGuardian.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return None
    except SecretResolutionError as exc:
        report.stages.append(
            StageResult(
                name="resolve+lint",
                ok=False,
                detail=f"secret could not be resolved: {exc}",
                remediation="Provision the referenced secret (e.g. export the env var) "
                "before running the contract.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return None
    except ContractError as exc:
        report.stages.append(
            StageResult(
                name="resolve+lint",
                ok=False,
                detail=f"contract failed to load: {exc}",
                remediation="Fix the contract document; see the validation detail above.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return None

    redacted = redact(contract)
    sha = contract_sha256(contract)
    report.redacted_contract = redacted if isinstance(redacted, dict) else {"contract": redacted}
    report.contract_sha256 = sha
    report.stages.append(
        StageResult(
            name="resolve+lint",
            ok=True,
            detail=f"contract '{contract.target.name}' valid (sha256={sha[:12]}…).",
        )
    )
    return contract


def _stage_connect(
    contract: Contract, report: PreflightReport
) -> tuple[Transport, SessionMachine] | None:
    """Stage 2 — build the transport + session machine from the contract.

    Returns the live ``(transport, session_machine)`` pair so later stages can
    use the transport's :meth:`Transport.probe` / :meth:`Transport.describe`
    introspection surface and drive the session machine directly — no
    :class:`ContractTargetAdapter` (and therefore no RoE chokepoint) is built,
    because pre-flight sends only benign turns and enforces no budgets.
    """
    try:
        transport = build_transport(contract)
        session_machine = build_session_machine(contract, transport)
    except (NotImplementedError, ImportError) as exc:
        report.stages.append(
            StageResult(
                name="connect",
                ok=False,
                detail=f"transport not supported: {exc}",
                remediation="Check the transport kind is supported and any optional "
                "provider extra (e.g. agent-guardian[aws]) is installed.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return None
    except (ValueError, SecretResolutionError) as exc:
        report.stages.append(
            StageResult(
                name="connect",
                ok=False,
                detail=f"could not build transport: {exc}",
                remediation="Check the transport URL, auth block, and that secrets resolve.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return None

    endpoint = str(getattr(transport, "endpoint", transport.kind))
    report.stages.append(
        StageResult(
            name="connect",
            ok=True,
            detail=f"transport built for {endpoint}.",
        )
    )
    return transport, session_machine


async def _stage_probe(transport: Transport, report: PreflightReport) -> str | None:
    """Stage 3 — run :meth:`Transport.probe` and classify any fault.

    :meth:`Transport.probe` sends one benign turn and folds the result into a
    :class:`~agent_guardian.transports.base.ProbeResult` (it never raises for a
    transport fault). On failure we classify the carried
    :class:`~agent_guardian.transports.errors.TransportError` by category —
    structurally, not by string-matching the round-trip exception text. The
    probe's truncated reply is returned for the stage-4 round-trip echo.
    """
    try:
        result = await transport.probe()
    except Exception as exc:  # pragma: no cover - probe never raises for faults
        _LOG.debug("preflight probe raised unexpected %s", type(exc).__name__, exc_info=exc)
        report.stages.append(
            StageResult(
                name="authenticate/probe",
                ok=False,
                detail=f"benign probe raised {type(exc).__name__}: {exc}",
                remediation="Check transport reachability and the response extraction paths.",
                exit_code=_EXIT_TARGET_UNREACHABLE,
            )
        )
        return None

    if not result.ok:
        error = result.error or TransportError(
            TransportErrorCategory.UNKNOWN, "probe failed with no error detail"
        )
        exit_code, remediation = _classify_transport_error(error)
        report.stages.append(
            StageResult(
                name="authenticate/probe",
                ok=False,
                detail=f"benign probe failed [{error.category.value}]: {error.message}",
                remediation=remediation,
                exit_code=exit_code,
            )
        )
        return None

    report.stages.append(
        StageResult(
            name="authenticate/probe",
            ok=True,
            detail="benign probe accepted (no auth fault).",
        )
    )
    return result.detail


def _stage_round_trip(reply: str, report: PreflightReport) -> None:
    """Stage 4 — confirm a non-empty reply was extracted and echo a preview."""
    preview = reply.strip().replace("\n", " ")
    if not preview:
        report.stages.append(
            StageResult(
                name="benign-round-trip",
                ok=False,
                detail="the target returned an empty reply.",
                remediation="Check the response 'output_path' — it extracted no text.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return
    if len(preview) > 160:
        preview = preview[:157] + "…"
    report.stages.append(
        StageResult(
            name="benign-round-trip",
            ok=True,
            detail=f"reply extracted: {preview!r}",
        )
    )


async def _stage_session(
    contract: Contract,
    session_machine: SessionMachine,
    report: PreflightReport,
) -> None:
    """Stage 5 — for a stateful session, drive two real turns and confirm the 2nd.

    The stage-3 probe goes straight at the transport and leaves the session
    machine untouched, so to *genuinely* exercise a second turn we drive the
    machine itself: turn one establishes state (``server_session`` captures the
    server id; ``client_history`` records the first exchange), and turn two
    replays that state — proving capture/replay (server) or history threading
    (client) actually works. The machine's :meth:`SessionMachine.send` returns a
    :class:`~agent_guardian.transports.base.Response` (never raises for faults),
    so faults are classified by their :class:`TransportError` category.
    """
    mode = contract.target.session.mode
    if mode == "stateless":
        report.stages.append(
            StageResult(
                name="session-check",
                ok=True,
                detail="session mode 'stateless' — continuity check skipped.",
            )
        )
        return

    # Turn one: establish session state through the machine.
    first = await session_machine.send(BENIGN_PROMPT)
    if not first.ok:
        _append_session_fault(report, "first session turn", first.error)
        return

    # Turn two: a real second turn that should continue the conversation.
    second = await session_machine.send(_BENIGN_FOLLOWUP)
    if not second.ok:
        _append_session_fault(report, "second session turn", second.error)
        return

    if not second.text.strip():
        report.stages.append(
            StageResult(
                name="session-check",
                ok=False,
                detail="second session turn returned an empty reply.",
                remediation="The session may not be continuing; verify id_source / id_send.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return

    report.stages.append(
        StageResult(
            name="session-check",
            ok=True,
            detail=f"session mode {mode!r} — two turns sent; the second returned a reply.",
        )
    )


def _append_session_fault(
    report: PreflightReport, which: str, error: TransportError | None
) -> None:
    """Append a failing session-check stage for a faulted turn."""
    err = error or TransportError(
        TransportErrorCategory.UNKNOWN, "session turn failed with no error detail"
    )
    exit_code, remediation = _classify_transport_error(err)
    report.stages.append(
        StageResult(
            name="session-check",
            ok=False,
            detail=f"{which} failed [{err.category.value}]: {err.message}",
            remediation=remediation,
            exit_code=exit_code,
        )
    )


def _discovered_tools(transport: Transport) -> set[str]:
    """Return the live tool names a transport discovered, if it does discovery.

    An :class:`~agent_guardian.transports.mcp.McpTransport` enumerates the
    server's tools via ``tools/list`` during the benign probe (stage 3) and
    caches the names; we read that cache off its
    :attr:`~agent_guardian.transports.mcp.McpTransport.discovered_tools`
    property (a no-I/O read, safe after the transport has been closed). Any other
    transport reports no discovered tools — they have no live enumeration surface
    — so the RoE reconciliation falls back to the contract's declared
    ``expected`` set exactly as before.
    """
    names = getattr(transport, "discovered_tools", ())
    if isinstance(names, tuple | list | set):
        return {name for name in names if isinstance(name, str)}
    return set()


def _stage_capability(contract: Contract, transport: Transport, report: PreflightReport) -> None:
    """Stage 6 — read :meth:`Transport.describe` + reconcile the RoE tool lists.

    :meth:`Transport.describe` returns a static
    :class:`~agent_guardian.transports.base.CapabilityReport` (kind, streaming,
    tool support, session modes, auth scheme) without sending any traffic — we
    prefer it over inferring capabilities from a live round-trip.

    The *validation* set a RoE allow/block reference must be a subset of is the
    union of the contract's declared ``target.tools.expected`` **and** any tools
    the transport enumerated live. An MCP transport runs ``tools/list`` during
    the stage-3 probe, so by the time this stage runs it has a real discovered
    set (read via :func:`_discovered_tools`); an HTTP / cloud transport
    contributes nothing there, so the validation set is just ``expected`` exactly
    as before. A RoE allow/block entry naming a tool outside the validation set
    is a dangling reference and a config error. When neither source names any
    tool we note the transport's discovered capability rather than failing (the
    operator may legitimately block a tool they have not enumerated).
    """
    capability: CapabilityReport = transport.describe()
    tools = contract.target.tools
    expected = {t.name for t in tools.expected} if tools else set()
    discovered = _discovered_tools(transport)
    # Either source is authoritative: a RoE ref naming a declared-expected OR a
    # live-discovered tool is valid; anything outside both is dangling.
    validation_set = expected | discovered
    roe_tools = contract.roe.tools
    allowlist = set(roe_tools.allowlist or []) if roe_tools else set()
    blocklist = set(roe_tools.blocklist or []) if roe_tools else set()

    cap_note = (
        f"transport '{capability.kind}' "
        f"(tools={'yes' if capability.supports_tools else 'no'}, "
        f"streaming={'yes' if capability.streaming else 'no'}, "
        f"session_modes={list(capability.session_modes)})"
    )
    if discovered:
        cap_note += f"; {len(discovered)} discovered tool(s)"

    if not validation_set:
        note = f"{cap_note}; no declared expected tools"
        if allowlist or blocklist:
            note += (
                f"; RoE references {sorted(allowlist | blocklist)} but the contract "
                "declares no expected tools (not enforced as a dangling ref)."
            )
        report.stages.append(StageResult(name="capability-report", ok=True, detail=note))
        return

    dangling = sorted((allowlist | blocklist) - validation_set)
    if dangling:
        report.stages.append(
            StageResult(
                name="capability-report",
                ok=False,
                detail=f"RoE references tool(s) {dangling} not in the expected set "
                f"{sorted(validation_set)}.",
                remediation="Add the tool(s) to target.tools.expected or remove the "
                "dangling RoE allow/block reference.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return

    report.stages.append(
        StageResult(
            name="capability-report",
            ok=True,
            detail=f"{cap_note}; {len(validation_set)} expected tool(s); "
            "RoE allow/block lists are a subset.",
        )
    )


def _stage_roe(contract: Contract, report: PreflightReport) -> None:
    """Stage 7 — echo the RoE envelope and enforce the prod authorization gate."""
    try:
        authorization_gate(contract)
    except RoeAuthorizationError as exc:
        report.stages.append(
            StageResult(
                name="roe-echo",
                ok=False,
                detail=f"authorization required: {exc}",
                remediation="Set roe.authorization_ref to your authorization reference "
                "(e.g. a ticket id) before scanning a prod target.",
                exit_code=_EXIT_CONFIG,
            )
        )
        return

    roe = contract.roe
    budgets = roe.budgets
    detail = (
        f"environment={contract.target.environment} "
        f"authorization_ref={roe.authorization_ref or '<none>'} "
        f"budgets(tokens={budgets.max_tokens}, "
        f"wallclock_min={budgets.max_wallclock_minutes}, "
        f"requests={budgets.max_requests}) "
        f"egress_external={roe.data_egress.allow_external}"
    )
    report.stages.append(StageResult(name="roe-echo", ok=True, detail=detail))
