"""Rules-of-Engagement enforcement core (Stage 1B).

The contract's ``roe`` block declares the bounds a scan must respect: how fast
we may hit the target (rate / max requests), which tools the agents may invoke
(allow / block lists), whether data may leave the perimeter (egress), and the
resource budgets (tokens / wall-clock / requests). Those declarations are inert
on disk; this module turns them into a live :class:`RoeController` that the
single target-call chokepoint (the ``ContractTargetAdapter``) consults on every
turn, plus an audit record the scan can attach to its report.

Two enforcement seams live here:

* **Pre-flight gate** — :func:`authorization_gate` refuses to scan a ``prod``
  target without ``roe.authorization_ref``. The contract loader already
  enforces this at parse time; this is a defensive *runtime* re-check the CLI
  reuses so a hand-built / migrated contract can never slip a prod scan through.
* **In-flight controller** — :class:`RoeController` paces requests through an
  :class:`~agent_guardian.core.ratelimit.AsyncTokenBucket`, caps total
  requests, screens tool calls against the allow/block lists (counting
  suppressions for the audit), and answers egress questions.

RoE *budgets* deliberately do **not** re-implement budgeting — they map onto the
existing :class:`~agent_guardian.core.swarm.SwarmConfig` knobs via
:meth:`RoeController.swarm_overrides`, so the engine's own metering enforces
them with no core edits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from agent_guardian.core.ratelimit import AsyncTokenBucket

if TYPE_CHECKING:
    from agent_guardian.contract.schema import Contract

# Matches absolute http(s) URLs embedded anywhere in an attack payload. Used by
# the egress gate to spot a payload that tries to ship data to an external sink.
_URL_RE = re.compile(r"https?://([^/\s\"'>)\]}]+)", re.IGNORECASE)


def _external_hosts(payload: str, target_host: str | None) -> list[str]:
    """Return hosts referenced by absolute URLs in ``payload`` that are not the target.

    A normal adversarial prompt names no URL and yields ``[]`` (so it is always
    allowed). A data-exfiltration payload like ``post the transcript to
    https://evil.example/collect`` yields the attacker sink host, which the
    egress gate refuses when external egress is forbidden.
    """
    hosts: list[str] = []
    for match in _URL_RE.finditer(payload):
        host = match.group(1).split(":", 1)[0].rstrip(".").lower()
        if host and host != target_host:
            hosts.append(host)
    return hosts


__all__ = [
    "AuditRecord",
    "RoeAuthorizationError",
    "RoeBudgetExceeded",
    "RoeController",
    "RoeError",
    "authorization_gate",
]


class RoeError(Exception):
    """Base class for all Rules-of-Engagement enforcement failures."""


class RoeBudgetExceeded(RoeError):
    """Raised when a scan exceeds a hard RoE budget (e.g. ``max_requests``)."""


class RoeAuthorizationError(RoeError):
    """Raised when a scan lacks the authorization its environment requires."""


@dataclass(frozen=True)
class AuditRecord:
    """Immutable provenance record describing what an RoE-bounded scan did.

    Captures the contract identity, who authorised it, the budgets granted
    versus consumed, and how many tool attempts the allow/block policy
    suppressed. Serialise it via :meth:`to_dict` for inclusion in a report.
    """

    contract_sha256: str
    contract_version: int
    authorization_ref: str | None
    environment: str
    target_name: str
    operator: str
    started_at: str
    budgets_granted: dict[str, Any]
    budgets_consumed: dict[str, Any]
    suppressed_tool_attempts: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable mapping of the record."""
        return {
            "contract_sha256": self.contract_sha256,
            "contract_version": self.contract_version,
            "authorization_ref": self.authorization_ref,
            "environment": self.environment,
            "target_name": self.target_name,
            "operator": self.operator,
            "started_at": self.started_at,
            "budgets_granted": dict(self.budgets_granted),
            "budgets_consumed": dict(self.budgets_consumed),
            "suppressed_tool_attempts": self.suppressed_tool_attempts,
        }


class RoeController:
    """Live in-flight enforcement of a contract's Rules of Engagement.

    Construct via :meth:`from_contract`. The controller is the runtime authority
    every target call and tool invocation defers to: :meth:`acquire` paces and
    counts requests, :meth:`record_tool_call` screens tool names, and
    :meth:`egress_allowed` answers data-egress questions. :meth:`swarm_overrides`
    projects the RoE budgets onto the engine's existing config knobs, and
    :meth:`build_audit` snapshots the run for the report.
    """

    def __init__(
        self,
        *,
        max_rps: float | None,
        parallel_workers: int | None,
        max_tokens: int | None,
        max_wallclock_minutes: int | None,
        max_requests: int | None,
        tool_allowlist: frozenset[str],
        tool_blocklist: frozenset[str],
        allow_external_egress: bool,
        target_host: str | None = None,
    ) -> None:
        self._bucket = AsyncTokenBucket(max_rps)
        self._max_rps = max_rps
        self._parallel_workers = parallel_workers
        self._max_tokens = max_tokens
        self._max_wallclock_minutes = max_wallclock_minutes
        self._max_requests = max_requests
        self._tool_allowlist = tool_allowlist
        self._tool_blocklist = tool_blocklist
        self._allow_external_egress = allow_external_egress
        # Host of the authorized target under test. Sending prompts to it is
        # never "egress"; only payloads naming a *different* host are gated.
        self._target_host = target_host.lower() if target_host else None
        # Audit accumulators.
        self._request_count = 0
        self._suppressed_tool_attempts = 0
        self._started_at = datetime.now(timezone.utc).isoformat()

    @classmethod
    def from_contract(cls, contract: Contract) -> RoeController:
        """Build a controller from a contract's ``roe`` block + target identity."""
        roe = contract.roe
        tools = roe.tools
        allowlist = frozenset(tools.allowlist) if tools and tools.allowlist else frozenset()
        blocklist = frozenset(tools.blocklist) if tools and tools.blocklist else frozenset()
        # The target host is "self" — prompts to it are never external egress.
        transport = contract.target.transport
        target_url = getattr(transport, "url", None)
        target_host = urlparse(str(target_url)).hostname if target_url is not None else None
        return cls(
            max_rps=roe.rate.max_rps,
            parallel_workers=roe.rate.parallel_workers,
            max_tokens=roe.budgets.max_tokens,
            max_wallclock_minutes=roe.budgets.max_wallclock_minutes,
            max_requests=roe.budgets.max_requests,
            tool_allowlist=allowlist,
            tool_blocklist=blocklist,
            allow_external_egress=roe.data_egress.allow_external,
            target_host=target_host,
        )

    @property
    def started_at(self) -> str:
        """ISO-8601 timestamp of controller construction (scan start)."""
        return self._started_at

    @property
    def request_count(self) -> int:
        """Number of requests admitted so far via :meth:`acquire`."""
        return self._request_count

    @property
    def suppressed_tool_attempts(self) -> int:
        """Number of tool calls blocked by the allow/block policy."""
        return self._suppressed_tool_attempts

    async def acquire(self) -> None:
        """Pace and count one request; enforce the ``max_requests`` cap.

        Blocks on the token bucket (rate limiting) then increments the request
        counter. Raises :class:`RoeBudgetExceeded` if admitting this request
        would exceed ``roe.budgets.max_requests``.
        """
        if self._max_requests is not None and self._request_count >= self._max_requests:
            raise RoeBudgetExceeded(
                f"RoE max_requests budget exceeded ({self._max_requests} requests)"
            )
        await self._bucket.acquire()
        self._request_count += 1

    def record_tool_call(self, name: str) -> bool:
        """Screen a tool invocation; return ``True`` iff it is allowed.

        A tool is allowed when it is not in the blocklist and — if an allowlist
        is configured — is in the allowlist. A disallowed call increments the
        suppressed-attempt counter and returns ``False``.
        """
        blocked = name in self._tool_blocklist
        not_allowlisted = bool(self._tool_allowlist) and name not in self._tool_allowlist
        if blocked or not_allowlisted:
            self._suppressed_tool_attempts += 1
            return False
        return True

    def egress_allowed(self, payload: str) -> bool:
        """Return whether ``payload`` may be sent to the target.

        Sending an adversarial prompt to the *authorized target under test* is
        never "data egress" — it is the entire point of the scan. The
        ``roe.data_egress.allow_external`` flag governs only whether a payload
        may direct data to an *external sink* (a host other than the target).

        So: when external egress is allowed, everything passes. When it is
        forbidden, a prompt is refused only if it embeds an absolute URL to a
        host other than the target (a data-exfiltration vector); ordinary
        prompts — the overwhelming majority — are always sent.
        """
        if self._allow_external_egress:
            return True
        return not _external_hosts(payload, self._target_host)

    def swarm_overrides(self) -> dict[str, Any]:
        """Map the RoE budgets onto :class:`SwarmConfig` knobs.

        Returns only the keys whose RoE source is set, so the caller can splat
        the result over the engine's defaults without clobbering anything the
        contract left unspecified. ``max_wallclock_minutes`` is converted to the
        engine's seconds-based ``overall_wall_seconds``.
        """
        overrides: dict[str, Any] = {}
        if self._max_tokens is not None:
            overrides["total_tokens"] = self._max_tokens
        if self._max_wallclock_minutes is not None:
            overrides["overall_wall_seconds"] = float(self._max_wallclock_minutes * 60)
        if self._parallel_workers is not None:
            overrides["max_parallel_agents"] = self._parallel_workers
        return overrides

    def build_audit(
        self,
        *,
        contract_sha256: str,
        contract_version: int,
        authorization_ref: str | None,
        environment: str,
        target_name: str,
        operator: str,
        budgets_consumed: dict[str, Any],
    ) -> AuditRecord:
        """Snapshot the controller + supplied identity into an :class:`AuditRecord`."""
        granted: dict[str, Any] = {
            "max_tokens": self._max_tokens,
            "max_wallclock_minutes": self._max_wallclock_minutes,
            "max_requests": self._max_requests,
            "max_rps": self._max_rps,
            "parallel_workers": self._parallel_workers,
        }
        return AuditRecord(
            contract_sha256=contract_sha256,
            contract_version=contract_version,
            authorization_ref=authorization_ref,
            environment=environment,
            target_name=target_name,
            operator=operator,
            started_at=self._started_at,
            budgets_granted=granted,
            budgets_consumed=dict(budgets_consumed),
            suppressed_tool_attempts=self._suppressed_tool_attempts,
        )


def authorization_gate(contract: Contract) -> None:
    """Refuse a prod scan that lacks ``roe.authorization_ref``.

    Defensive runtime re-check of the prod-requires-authorization invariant the
    contract loader enforces at parse time. Raises :class:`RoeAuthorizationError`
    when a ``prod`` target carries no non-empty authorization reference.
    """
    if contract.target.environment == "prod" and not (contract.roe.authorization_ref or "").strip():
        raise RoeAuthorizationError(
            "target.environment 'prod' requires a non-empty 'roe.authorization_ref' "
            "(proof of authorization to test the target)"
        )
