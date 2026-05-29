"""Contract pre-flight — staged, payload-free validation of a target (Stage 1B).

``validate`` (and ``init``'s post-write check) drive :func:`run_preflight`, which
walks a contract through seven *non-adversarial* stages and stops at the first
failure. No attack payload is ever sent: the only prompts that leave the
perimeter are benign ("Hello, please introduce yourself") round-trips used to
prove the wiring works end-to-end before a real scan is authorised.

The seven stages mirror the operator's mental model of "can I even talk to this
thing, and am I allowed to?":

1. **resolve + lint** — load + validate the contract, print its redacted view.
2. **connect** — build the transport from the contract primitives.
3. **authenticate / probe** — send one benign turn and classify auth failures
   (401/403 → unreachable; provider-auth → LLM-provider exit code).
4. **benign round-trip** — extract + print the model's reply text.
5. **session check** — for a stateful session, send a second benign turn and
   confirm continuity (a stateless contract skips this with a note).
6. **capability report** — reconcile the RoE allow/block lists against the
   contract's declared / expected tools (a dangling ref is a config error).
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
from agent_guardian.transports.contract_adapter import ContractTargetAdapter
from agent_guardian.transports.factory import build_session_machine, build_transport

if TYPE_CHECKING:
    from agent_guardian.contract.schema import Contract

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


async def run_preflight(contract_path: Path) -> PreflightReport:
    """Run the seven-stage pre-flight against the contract at ``contract_path``.

    Stops at the first failing stage and returns a :class:`PreflightReport`. No
    attack payload is ever sent — the only egress is a benign introduce-yourself
    round-trip used to prove the wiring.
    """
    report = PreflightReport()

    # --- Stage 1: resolve + lint -------------------------------------------
    contract = _stage_resolve(contract_path, report)
    if contract is None:
        return report

    # --- Stage 2: connect (build the transport) ----------------------------
    adapter = _stage_connect(contract, report)
    if adapter is None:
        return report

    try:
        # --- Stage 3: authenticate / probe (benign send) ------------------
        first_reply = await _stage_probe(adapter, report)
        if first_reply is None:
            return report

        # --- Stage 4: benign round-trip (extract + print reply) -----------
        _stage_round_trip(first_reply, report)
        if not report.ok:
            return report

        # --- Stage 5: session check (2nd turn for stateful contracts) -----
        await _stage_session(contract, adapter, report)
        if not report.ok:
            return report
    finally:
        await adapter.aclose()

    # --- Stage 6: capability report ----------------------------------------
    _stage_capability(contract, report)
    if not report.ok:
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


def _stage_connect(contract: Contract, report: PreflightReport) -> ContractTargetAdapter | None:
    """Stage 2 — build the transport + adapter from the contract primitives."""
    try:
        transport = build_transport(contract)
        session_machine = build_session_machine(contract, transport)
        adapter = ContractTargetAdapter(transport=transport, session_machine=session_machine)
    except NotImplementedError as exc:
        report.stages.append(
            StageResult(
                name="connect",
                ok=False,
                detail=f"transport not supported: {exc}",
                remediation="Only 'http' transports ship today; other kinds land in a later stage.",
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

    report.stages.append(
        StageResult(
            name="connect",
            ok=True,
            detail=f"transport built for {adapter.endpoint}.",
        )
    )
    return adapter


async def _stage_probe(adapter: ContractTargetAdapter, report: PreflightReport) -> str | None:
    """Stage 3 — send one benign turn and classify any failure."""
    try:
        reply = await adapter.call(BENIGN_PROMPT)
    except RuntimeError as exc:
        exit_code, remediation = _classify_send_error(str(exc))
        report.stages.append(
            StageResult(
                name="authenticate/probe",
                ok=False,
                detail=f"benign probe failed: {exc}",
                remediation=remediation,
                exit_code=exit_code,
            )
        )
        return None
    except Exception as exc:
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

    report.stages.append(
        StageResult(
            name="authenticate/probe",
            ok=True,
            detail="benign probe accepted (no auth fault).",
        )
    )
    return reply


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
    adapter: ContractTargetAdapter,
    report: PreflightReport,
) -> None:
    """Stage 5 — for a stateful session, send a 2nd turn to confirm continuity."""
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

    try:
        reply = await adapter.call(_BENIGN_FOLLOWUP)
    except RuntimeError as exc:
        exit_code, remediation = _classify_send_error(str(exc))
        report.stages.append(
            StageResult(
                name="session-check",
                ok=False,
                detail=f"second session turn failed: {exc}",
                remediation=remediation,
                exit_code=exit_code,
            )
        )
        return
    except Exception as exc:
        _LOG.debug("preflight session turn raised unexpected %s", type(exc).__name__, exc_info=exc)
        report.stages.append(
            StageResult(
                name="session-check",
                ok=False,
                detail=f"second session turn raised {type(exc).__name__}: {exc}",
                remediation="Check session id capture/replay (session.id_source / id_send).",
                exit_code=_EXIT_TARGET_UNREACHABLE,
            )
        )
        return

    if not reply.strip():
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
            detail=f"session mode {mode!r} — second turn returned a reply.",
        )
    )


def _stage_capability(contract: Contract, report: PreflightReport) -> None:
    """Stage 6 — reconcile the RoE allow/block lists with the declared tools.

    Without live tool discovery (HTTP has none today) the *expected* tool set is
    the contract's ``target.tools.expected``. A RoE allow/block entry that names
    a tool outside that expected set is a dangling reference and a config error;
    when the contract declares no expected tools at all we note "no tool
    discovery" rather than failing (the operator may legitimately block a tool
    they haven't enumerated).
    """
    tools = contract.target.tools
    expected = {t.name for t in tools.expected} if tools else set()
    roe_tools = contract.roe.tools
    allowlist = set(roe_tools.allowlist or []) if roe_tools else set()
    blocklist = set(roe_tools.blocklist or []) if roe_tools else set()

    if not expected:
        note = "no tool discovery for http transport"
        if allowlist or blocklist:
            note += (
                f"; RoE references {sorted(allowlist | blocklist)} but the contract "
                "declares no expected tools (not enforced as a dangling ref)."
            )
        report.stages.append(StageResult(name="capability-report", ok=True, detail=note))
        return

    dangling = sorted((allowlist | blocklist) - expected)
    if dangling:
        report.stages.append(
            StageResult(
                name="capability-report",
                ok=False,
                detail=f"RoE references tool(s) {dangling} not in the expected set "
                f"{sorted(expected)}.",
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
            detail=f"{len(expected)} expected tool(s); RoE allow/block lists are a subset.",
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
