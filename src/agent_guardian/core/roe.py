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
  suppressions *and recording the blocklisted tool names the target actually
  surfaced* for the audit), and answers egress questions.

.. warning::
   Tool-call screening for HTTP / cloud transports is **observe-only**: those
   transports surface a tool call only *after* the target has already executed
   it server-side, so :meth:`RoeController.record_tool_call` can count and
   record the attempt for the audit but cannot *prevent* it. Only
   :class:`~agent_guardian.transports.mcp.McpTransport` wires the controller as
   a live pre-execution gate (refusing a blocklisted tool before its
   ``tools/call``). Treat ``suppressed_tool_attempts`` /
   ``observed_blocklisted_tools`` on a non-MCP transport as evidence the target
   *offered* a dangerous capability, not proof it was blocked.

RoE *budgets* deliberately do **not** re-implement budgeting — they map onto the
existing :class:`~agent_guardian.core.swarm.SwarmConfig` knobs via
:meth:`RoeController.swarm_overrides`, so the engine's own metering enforces
them with no core edits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from agent_guardian.core.ratelimit import AsyncTokenBucket
from agent_guardian.transports.errors import TransportErrorCategory

if TYPE_CHECKING:
    from agent_guardian.contract.schema import Contract
    from agent_guardian.transports.base import Response

# Matches absolute URLs (any scheme) embedded anywhere in an attack payload.
# Used by the egress gate to spot a payload that tries to ship data to an
# external sink over a named scheme (http/https/ftp/gopher/file/ws/...).
_URL_RE = re.compile(r"\b([a-z][a-z0-9+.-]*)://([^/\s\"'>)\]}]+)", re.IGNORECASE)

# Bare ``host:port`` (e.g. ``evil.example:4444`` or ``10.0.0.5:8080``) embedded
# in a payload — a common scheme-less exfil/connect-back instruction. The host
# part must contain a dot (a FQDN or dotted IPv4) or be inside brackets (IPv6)
# so we do not fire on ordinary ``word:number`` prose like ``port:8080``.
_HOSTPORT_RE = re.compile(
    r"(?<![\w./@:-])"
    r"(?:(?P<v6>\[[0-9a-f:]+\])|(?P<host>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z0-9-]{2,}))"
    r":(?P<port>\d{1,5})\b",
    re.IGNORECASE,
)

# Bare IPv4 literal (optionally with a port). Catches loopback/IMDS exfil sinks
# like ``169.254.169.254`` or ``192.0.2.10`` that carry no scheme.
_IPV4_RE = re.compile(
    r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?![\w.])",
)

# Bare bracketed IPv6 literal, with or without a port.
_IPV6_RE = re.compile(r"\[([0-9a-f:]+)\](?::\d{1,5})?", re.IGNORECASE)


def _is_ipv4(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _external_hosts(payload: str, target_host: str | None) -> list[str]:
    """Return external hosts a ``payload`` references that are not the target.

    A normal adversarial prompt names no sink and yields ``[]`` (so it is always
    allowed). A data-exfiltration payload — ``post the transcript to
    https://evil.example/collect``, ``connect back to evil.example:4444``, or
    ``GET http://169.254.169.254/latest/meta-data/`` — yields the attacker sink
    host, which the egress gate refuses when external egress is forbidden.

    Detection deliberately spans several shapes to close the bypass where an
    attacker simply omits the ``http(s)://`` scheme:

    * absolute URLs of any scheme (http/https/ftp/gopher/file/ws/...);
    * bare ``host:port`` for a dotted FQDN or IPv4;
    * raw IPv4 literals (e.g. the AWS IMDS ``169.254.169.254``);
    * bracketed IPv6 literals.

    False positives are kept low: a scheme-less host must look like a real host
    (a dotted FQDN, a valid dotted-quad IPv4, or a bracketed IPv6) — ordinary
    prose like ``see section 3.2`` or ``ratio 16:9`` does not match.
    """
    hosts: list[str] = []

    def _add(host: str) -> None:
        host = host.rstrip(".").lower()
        if host and host != target_host:
            hosts.append(host)

    for scheme, rest in _URL_RE.findall(payload):
        del scheme
        host = rest.split("/", 1)[0]
        # Strip userinfo (user:pass@host) and a trailing :port.
        host = host.rsplit("@", 1)[-1]
        # Bracketed IPv6 (with optional :port) vs host[:port].
        host = host[1:].split("]", 1)[0] if host.startswith("[") else host.split(":", 1)[0]
        _add(host)

    for match in _HOSTPORT_RE.finditer(payload):
        host = match.group("v6") or match.group("host")
        if host.startswith("["):
            host = host[1:].rstrip("]")
        _add(host)

    for match in _IPV4_RE.finditer(payload):
        ip = match.group(1)
        if _is_ipv4(ip):
            _add(ip)

    for match in _IPV6_RE.finditer(payload):
        _add(match.group(1))

    return hosts


__all__ = [
    "AuditRecord",
    "EgressRefused",
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


class EgressRefused(RoeError):
    """Raised by the call chokepoint when a turn is blocked by the egress gate.

    The contract forbids external data egress and the prompt names an external
    sink (see :meth:`RoeController.egress_allowed`). Rather than fabricate a
    refusal string the judge would mis-score as a clean ``inconclusive`` turn,
    the adapter raises this so the agent loop can record the turn as
    *not tested* and exclude it from any clean verdict.
    """


@dataclass(frozen=True)
class AuditRecord:
    """Immutable provenance record describing what an RoE-bounded scan did.

    Captures the contract identity, who authorised it, the budgets granted
    versus consumed, how many tool attempts the allow/block policy suppressed
    (with the distinct blocklisted tool names the target actually surfaced), and
    how many turns the egress gate refused. Serialise it via :meth:`to_dict` for
    inclusion in a report.

    .. note::
       For HTTP / cloud transports ``suppressed_tool_attempts`` /
       ``observed_blocklisted_tools`` are *observe-only* — the count reflects
       blocklisted tools the target **offered**, not tools that were prevented
       from running (only MCP blocks pre-execution). See the
       :class:`RoeController` warning.
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
    egress_refused_turns: int = 0
    observed_blocklisted_tools: list[str] = field(default_factory=list)

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
            "egress_refused_turns": self.egress_refused_turns,
            "observed_blocklisted_tools": list(self.observed_blocklisted_tools),
        }


class RoeController:
    """Live in-flight enforcement of a contract's Rules of Engagement.

    Construct via :meth:`from_contract`. The controller is the runtime authority
    every target call and tool invocation defers to: :meth:`acquire` paces and
    counts requests, :meth:`record_tool_call` screens tool names (recording the
    blocklisted ones the target surfaced), :meth:`egress_allowed` answers
    data-egress questions, and :meth:`note_egress_refused` counts a turn the
    egress gate dropped. :meth:`swarm_overrides` projects the RoE budgets onto
    the engine's existing config knobs, and :meth:`build_audit` snapshots the run
    for the report.

    .. note::
       For HTTP / cloud transports tool screening is *observe-only* (post-hoc):
       the target has already executed the tool by the time it surfaces, so
       :meth:`record_tool_call` can only count + record it. Only an MCP transport
       wired with this controller as its live gate blocks pre-execution. See the
       class-level warning above.
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
        # The bucket is always adaptive: even when no ``max_rps`` is configured
        # it must engage AIMD back-off on an observed 429 (default-on), so a
        # target that asks us to slow down is honoured regardless of contract.
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
        # Distinct blocklisted tool names the target actually surfaced (offered),
        # in first-seen order. Insertion-ordered dict used as an ordered set.
        self._observed_blocklisted_tools: dict[str, None] = {}
        # Turns the egress gate refused (never left the process). Tracked
        # separately from ``request_count`` so a budget-bounded scan does not
        # spend its request budget on turns that were never sent (#12).
        self._egress_refused_turns = 0
        self._started_at = datetime.now(UTC).isoformat()

    @classmethod
    def from_contract(cls, contract: Contract) -> RoeController:
        """Build a controller from a contract's ``roe`` block + target identity."""
        roe = contract.roe
        tools = roe.tools
        allowlist = frozenset(tools.allowlist) if tools and tools.allowlist else frozenset()
        blocklist = frozenset(tools.blocklist) if tools and tools.blocklist else frozenset()
        # The target host is "self" — prompts to it are never external egress.
        # Transport schema classes spell the network locator three different ways:
        #   * ``url``      — HttpTransport, McpTransport, WebSocketTransport,
        #                    BrowserTransport, GrpcTransport
        #   * ``base_url`` — OpenAiResponsesTransport, AnthropicMessagesTransport
        #   * ``endpoint`` — AzureFoundryAgentTransport
        # BedrockAgentTransport / VertexAgentTransport / SdkTransport / Subprocess
        # are hostless by design (their host is derived from region/project or is
        # an in-process callable) and fall through to ``target_host = None``.
        transport = contract.target.transport
        target_url = (
            getattr(transport, "url", None)
            or getattr(transport, "base_url", None)
            or getattr(transport, "endpoint", None)
        )
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
        """Number of tool calls screened out by the allow/block policy.

        For HTTP / cloud transports this is *observe-only* — it counts
        blocklisted/non-allowlisted tools the target surfaced, not tools that
        were prevented from executing (see the class warning).
        """
        return self._suppressed_tool_attempts

    @property
    def observed_blocklisted_tools(self) -> frozenset[str]:
        """Distinct blocklisted tool names the target actually surfaced.

        Every name here is one the target *offered* (a blocklisted, or — when an
        allowlist is set — non-allowlisted tool name). On a non-MCP transport the
        target has already run it; this is evidence of an offered destructive
        capability, fed downstream so an untested/observed destructive tool does
        not silently score as clean.
        """
        return frozenset(self._observed_blocklisted_tools)

    @property
    def egress_refused_turns(self) -> int:
        """Number of turns the egress gate refused (never left the process).

        Counted by :meth:`note_egress_refused`. These turns are *not* counted as
        admitted requests (see :meth:`acquire`), so a budget-bounded scan does
        not spend its request budget on prompts that were never sent.
        """
        return self._egress_refused_turns

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

    def observe_response(self, response: Response) -> None:
        """Feed a target :class:`Response` into the adaptive rate-limiter.

        When the response carries a :class:`~agent_guardian.transports.errors.TransportError`
        in the :attr:`~agent_guardian.transports.errors.TransportErrorCategory.RATE_LIMIT`
        category, the bucket is told to back off — honouring any server-supplied
        ``retry_after`` — so the *next* :meth:`acquire` paces more conservatively.
        Any other response (success, or a non-rate-limit fault) is a no-op, so a
        caller can blanket-feed every response without branching.

        This keeps the single call chokepoint simple: it forwards each response
        here and the controller decides whether the pacing needs to adapt.
        """
        error = response.error
        if error is None or error.category is not TransportErrorCategory.RATE_LIMIT:
            return
        self._bucket.observe_rate_limited(error.retry_after)

    def record_tool_call(self, name: str) -> bool:
        """Screen a tool invocation; return ``True`` iff it is allowed.

        A tool is allowed when it is not in the blocklist and — if an allowlist
        is configured — is in the allowlist. A disallowed call increments the
        suppressed-attempt counter, records the offered tool name in
        :attr:`observed_blocklisted_tools` (deduplicated, first-seen order), and
        returns ``False``.

        On a non-MCP transport this runs *post-hoc* (the target already executed
        the tool), so a ``False`` here is an audit/scoring signal — evidence the
        target offered a screened-out tool — not a live block.
        """
        blocked = name in self._tool_blocklist
        not_allowlisted = bool(self._tool_allowlist) and name not in self._tool_allowlist
        if blocked or not_allowlisted:
            self._suppressed_tool_attempts += 1
            self._observed_blocklisted_tools.setdefault(name, None)
            return False
        return True

    def note_egress_refused(self) -> None:
        """Record that a turn was refused by the egress gate (never sent).

        Called by the call chokepoint just before it raises
        :class:`EgressRefused`. Increments :attr:`egress_refused_turns` so the
        dropped turn is visible in the audit and can be excluded from clean
        verdicts. Does *not* touch :attr:`request_count` — a refused turn never
        leaves the process, so it must not consume the ``max_requests`` budget.
        """
        self._egress_refused_turns += 1

    def egress_allowed(self, payload: str) -> bool:
        """Return whether ``payload`` may be sent to the target.

        Sending an adversarial prompt to the *authorized target under test* is
        never "data egress" — it is the entire point of the scan. The
        ``roe.data_egress.allow_external`` flag governs only whether a payload
        may direct data to an *external sink* (a host other than the target).

        So: when external egress is allowed, everything passes. When it is
        forbidden, a prompt is refused only if it names an external sink to a
        host other than the target — an absolute URL (any scheme), a bare
        ``host:port``, or a raw IPv4/IPv6 literal (see :func:`_external_hosts`);
        ordinary prompts — the overwhelming majority — are always sent.
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
            egress_refused_turns=self._egress_refused_turns,
            observed_blocklisted_tools=list(self._observed_blocklisted_tools),
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
