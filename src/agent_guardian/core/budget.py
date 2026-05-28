"""Budget controller (PRD §14.2) + USD budget ledger (M2 Pattern 7).

Two complementary mechanisms live here:

* :class:`BudgetController` — the original token-slice accountant. A per-scan
  token ceiling split into per-agent slices, donatable under an
  :class:`asyncio.Lock`. Governs in-loop token spend.
* :class:`BudgetLedger` — the M2 financial envelope. A USD/token/wall-clock
  :class:`BudgetEnvelope` declared up front; agents ``reserve`` before a paid
  call and ``commit`` the actual cost, and the ledger refuses any reservation
  that would exceed the workflow cap or an agent's declared share. Makes scans
  financially predictable (ATLANTIS CP-MANAGER proportional allocation).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agent_guardian.cost import lookup_price

__all__ = [
    "DEFAULT_SLICE_ALLOCATIONS",
    "BudgetController",
    "BudgetEnvelope",
    "BudgetExhausted",
    "BudgetLedger",
    "BudgetReceipt",
    "BudgetSlice",
    "LedgerEntry",
    "tokens_to_usd",
]

_LOG = logging.getLogger(__name__)


def tokens_to_usd(model_spec: str, input_tokens: int, output_tokens: int) -> float:
    """Convert token counts to USD via the shared price table."""
    row = lookup_price(model_spec)
    return (input_tokens / 1_000_000) * row.input_per_1m + (
        output_tokens / 1_000_000
    ) * row.output_per_1m


# Default per-agent allocations (PRD §14.2). Sum = 2,000,000.
DEFAULT_SLICE_ALLOCATIONS: dict[str, int] = {
    "recon": 50_000,
    "asi01": 150_000,
    "asi02": 150_000,
    "asi03": 150_000,
    "asi04": 150_000,
    "asi05": 150_000,
    "asi06": 150_000,
    "asi07": 150_000,
    "asi08": 150_000,
    "asi09": 150_000,
    "asi10": 150_000,
    "commander": 100_000,
    "evaluator": 350_000,
}


class BudgetSlice(BaseModel):
    """Per-agent budget envelope mutated as the scan progresses."""

    agent: str = Field(min_length=1)
    tokens_remaining: int = Field(ge=0)
    wall_seconds_remaining: float = Field(ge=0.0)

    # Slices mutate during a scan — frozen=False (default), but extras forbidden.
    model_config = ConfigDict(extra="forbid")


class BudgetController:
    """Thread-safe budget controller across asyncio tasks."""

    def __init__(
        self,
        total_tokens: int = 2_000_000,
        wall_seconds: float = 900.0,
        allocations: dict[str, int] | None = None,
    ) -> None:
        if total_tokens < 0:
            raise ValueError("total_tokens must be non-negative")
        if wall_seconds < 0:
            raise ValueError("wall_seconds must be non-negative")

        effective_allocations = (
            dict(allocations) if allocations is not None else dict(DEFAULT_SLICE_ALLOCATIONS)
        )
        allocated = sum(effective_allocations.values())
        if any(value < 0 for value in effective_allocations.values()):
            raise ValueError("Allocation values must be non-negative")
        if allocated > total_tokens:
            raise ValueError(
                f"Sum of allocations ({allocated}) exceeds total_tokens ({total_tokens})"
            )

        self._total_tokens = total_tokens
        self._wall_seconds = wall_seconds
        self._original_total = allocated
        self._lock = asyncio.Lock()
        self._slices: dict[str, BudgetSlice] = {}

        for agent, tokens in effective_allocations.items():
            share = tokens / allocated if allocated > 0 else 0.0
            self._slices[agent] = BudgetSlice(
                agent=agent,
                tokens_remaining=tokens,
                wall_seconds_remaining=wall_seconds * share,
            )

    def slice_for(self, agent: str) -> BudgetSlice:
        """Return the current slice for ``agent``.

        Raises:
            KeyError: if ``agent`` was not configured.
        """
        if agent not in self._slices:
            raise KeyError(f"No budget slice configured for agent {agent!r}")
        return self._slices[agent]

    def request(self, agent: str, tokens: int) -> bool:
        """Attempt to consume ``tokens`` from ``agent``'s slice.

        Returns ``True`` if the request succeeds; ``False`` if the slice is
        exhausted. Negative requests are rejected.
        """
        if tokens < 0:
            raise ValueError("tokens must be non-negative")
        slice_ = self.slice_for(agent)
        if slice_.tokens_remaining < tokens:
            return False
        slice_.tokens_remaining -= tokens
        return True

    def donate(self, from_agent: str, to_agent: str, tokens: int) -> None:
        """Move ``tokens`` from one agent's slice to another's.

        Raises:
            ValueError: if ``tokens`` is negative or ``from_agent`` lacks
                the requested amount.
            KeyError: if either agent was not configured.
        """
        if tokens < 0:
            raise ValueError("tokens must be non-negative")
        src = self.slice_for(from_agent)
        dst = self.slice_for(to_agent)
        if src.tokens_remaining < tokens:
            raise ValueError(
                f"Cannot donate {tokens} tokens from {from_agent!r}: only "
                f"{src.tokens_remaining} remaining"
            )
        src.tokens_remaining -= tokens
        dst.tokens_remaining += tokens

    def total_spent(self) -> int:
        """Total tokens consumed across all configured slices."""
        return self._original_total - self.total_remaining()

    def total_remaining(self) -> int:
        """Total tokens still available across all slices."""
        return sum(s.tokens_remaining for s in self._slices.values())


# ---------------------------------------------------------------------------
# M2 Pattern 7 — USD budget envelope + ledger
# ---------------------------------------------------------------------------


class BudgetExhausted(Exception):
    """Raised when a reservation would exceed the envelope or an agent share."""


@dataclass(frozen=True)
class BudgetEnvelope:
    """Declared up front on every ScanPlan.

    ``per_agent_share`` maps agent_id -> fraction in [0, 1] of ``usd_cap`` that
    agent may spend. Agents absent from the map fall back to
    :attr:`default_share`. Shares need not sum to 1 — the workflow ``usd_cap``
    is the hard ceiling regardless.
    """

    usd_cap: float
    token_cap: int
    wallclock_cap_s: float
    per_agent_share: dict[str, float] = field(default_factory=dict)
    default_share: float = 1.0

    def share_for(self, agent_id: str) -> float:
        return self.per_agent_share.get(agent_id, self.default_share)


@dataclass(frozen=True)
class BudgetReceipt:
    """Handle for an outstanding reservation, redeemed by :meth:`BudgetLedger.commit`."""

    receipt_id: str
    agent_id: str
    tokens: int
    est_usd: float


@dataclass(frozen=True)
class LedgerEntry:
    """One append-only ledger record."""

    timestamp: float
    agent_id: str
    kind: str  # "reserve" | "commit"
    tokens: int
    usd: float
    receipt_id: str


class BudgetLedger:
    """Single source of truth for USD spend across a workflow.

    All methods are synchronous and atomic within the swarm's single
    event-loop thread; entries mirror to an append-only JSONL when a path is
    supplied so a crashed scan's spend stays auditable.
    """

    def __init__(self, envelope: BudgetEnvelope, *, jsonl_path: Path | None = None) -> None:
        self._env = envelope
        self._spent_usd = 0.0
        self._spent_tokens = 0
        self._reserved_usd = 0.0
        self._reserved_tokens = 0
        self._per_agent_usd: dict[str, float] = {}
        self._per_agent_reserved: dict[str, float] = {}
        self._open: dict[str, BudgetReceipt] = {}
        self._entries: list[LedgerEntry] = []
        self._jsonl_path = jsonl_path
        self._start = time.monotonic()

    # -- queries --------------------------------------------------------

    @property
    def spent_usd(self) -> float:
        return self._spent_usd

    @property
    def committed_plus_reserved_usd(self) -> float:
        return self._spent_usd + self._reserved_usd

    def remaining(self, agent_id: str) -> tuple[float, int]:
        """(usd, tokens) the agent may still reserve — min of envelope + share."""
        agent_cap = self._env.usd_cap * self._env.share_for(agent_id)
        agent_used = self._per_agent_usd.get(agent_id, 0.0) + self._per_agent_reserved.get(
            agent_id, 0.0
        )
        agent_left = max(0.0, agent_cap - agent_used)
        env_left = max(0.0, self._env.usd_cap - self.committed_plus_reserved_usd)
        usd_left = min(agent_left, env_left)
        tok_left = max(0, self._env.token_cap - self._spent_tokens - self._reserved_tokens)
        return usd_left, tok_left

    def usage_fraction(self) -> float:
        """Fraction of the USD cap committed-or-reserved (drives the 90% early-stop)."""
        if self._env.usd_cap <= 0:
            return 1.0
        return self.committed_plus_reserved_usd / self._env.usd_cap

    def is_exhausted(self) -> bool:
        if self.committed_plus_reserved_usd >= self._env.usd_cap:
            return True
        if self._spent_tokens + self._reserved_tokens >= self._env.token_cap:
            return True
        return (time.monotonic() - self._start) >= self._env.wallclock_cap_s

    def wallclock_remaining_s(self) -> float:
        return max(0.0, self._env.wallclock_cap_s - (time.monotonic() - self._start))

    # -- mutations ------------------------------------------------------

    def reserve(self, agent_id: str, tokens: int, est_usd: float) -> BudgetReceipt:
        """Hold budget for an upcoming paid call. Raises :class:`BudgetExhausted`."""
        if tokens < 0 or est_usd < 0:
            raise ValueError("reservation amounts must be non-negative")
        usd_left, tok_left = self.remaining(agent_id)
        if est_usd > usd_left + 1e-12:
            raise BudgetExhausted(
                f"agent {agent_id!r} reservation ${est_usd:.4f} exceeds remaining ${usd_left:.4f}"
            )
        if tokens > tok_left:
            raise BudgetExhausted(
                f"agent {agent_id!r} reservation {tokens} tokens exceeds remaining {tok_left}"
            )
        receipt = BudgetReceipt(
            receipt_id=uuid.uuid4().hex[:12],
            agent_id=agent_id,
            tokens=tokens,
            est_usd=est_usd,
        )
        self._reserved_usd += est_usd
        self._reserved_tokens += tokens
        self._per_agent_reserved[agent_id] = self._per_agent_reserved.get(agent_id, 0.0) + est_usd
        self._open[receipt.receipt_id] = receipt
        self._record(
            LedgerEntry(time.monotonic(), agent_id, "reserve", tokens, est_usd, receipt.receipt_id)
        )
        return receipt

    def commit(
        self,
        receipt: BudgetReceipt,
        actual_usd: float,
        actual_tokens: int | None = None,
    ) -> None:
        """Redeem a reservation with the observed cost."""
        if actual_usd < 0:
            raise ValueError("actual_usd must be non-negative")
        open_receipt = self._open.pop(receipt.receipt_id, None)
        if open_receipt is None:
            raise ValueError(f"unknown or already-committed receipt {receipt.receipt_id!r}")
        toks = receipt.tokens if actual_tokens is None else actual_tokens
        self._reserved_usd = max(0.0, self._reserved_usd - receipt.est_usd)
        self._reserved_tokens = max(0, self._reserved_tokens - receipt.tokens)
        self._per_agent_reserved[receipt.agent_id] = max(
            0.0, self._per_agent_reserved.get(receipt.agent_id, 0.0) - receipt.est_usd
        )
        self._spent_usd += actual_usd
        self._spent_tokens += toks
        self._per_agent_usd[receipt.agent_id] = (
            self._per_agent_usd.get(receipt.agent_id, 0.0) + actual_usd
        )
        self._record(
            LedgerEntry(
                time.monotonic(), receipt.agent_id, "commit", toks, actual_usd, receipt.receipt_id
            )
        )

    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    # -- internals ------------------------------------------------------

    def _record(self, entry: LedgerEntry) -> None:
        self._entries.append(entry)
        if self._jsonl_path is None:
            return
        try:
            self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            with self._jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "ts": entry.timestamp,
                            "agent": entry.agent_id,
                            "kind": entry.kind,
                            "tokens": entry.tokens,
                            "usd": entry.usd,
                            "receipt": entry.receipt_id,
                        }
                    )
                    + "\n"
                )
        except OSError as exc:  # pragma: no cover — defensive; ledger must not crash a scan
            _LOG.warning("budget: failed to append ledger entry to %s (%s)", self._jsonl_path, exc)
