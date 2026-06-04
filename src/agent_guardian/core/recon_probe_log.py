"""Per-probe JSONL log written from inside the capability audit (OPT-IN).

The capability audit reads a black-box agent by making it take observable
actions; this module persists each of those probes — the prompt sent, the
normalized response envelope, and the structured signals observed — as one
JSONL line so a later session (the dashboard, a replay, an investigator) can
reconstruct exactly how recon arrived at a fingerprint without re-running the
target.

It is **opt-in**: nothing writes a probe log unless a caller hands a
:class:`ProbeLog` to :func:`agent_guardian.core.capability_audit.run_capability_audit`.
The default scan path never constructs one, so the audit's behaviour and cost
are byte-for-byte unchanged when the log is absent.

Persistence mirrors :class:`agent_guardian.server.scan_store.ScanStore`: a
per-log persistent append-mode handle, opened lazily and ``flush()``-ed after
every line so a concurrent reader always sees committed bytes. The log writes
a SIBLING file, ``recon_probes.jsonl`` — deliberately NOT ``events.jsonl``.
Co-mingling probe records with :class:`~agent_guardian.core.swarm.SwarmEvent`
lines would force the event schema to grow probe-shaped fields and risk the
SSE wire contract the dashboard depends on; a separate file keeps the two
concerns independent.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

__all__ = ["ProbeLog", "ProbeLogRecord"]

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ProbeLogRecord:
    """One probe + its observed outcome, as written to ``recon_probes.jsonl``.

    The required keys (``probe_id``, ``seq``, ``band``, ``intent``, ``prompt``,
    ``session``, ``signals_observed``) are always serialised; the optional keys
    (``response_envelope``, ``response_ref``, ``latency_ms``,
    ``novelty_decision``, ``error``) are dropped from :meth:`to_dict` when
    ``None`` so a line carries only what the turn produced. The coverage /
    novelty / tool-call / reply facets the recon engine needs are represented
    *within* ``signals_observed`` + ``response_envelope`` rather than as
    top-level columns — one record schema serves the audit and the engine.
    """

    probe_id: str
    seq: int
    band: str
    intent: str
    prompt: str
    session: str | None
    response_envelope: dict[str, Any] | None = None
    response_ref: str | None = None
    signals_observed: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None
    novelty_decision: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "probe_id": self.probe_id,
            "seq": self.seq,
            "band": self.band,
            "intent": self.intent,
            "prompt": self.prompt,
            "session": self.session,
            "signals_observed": self.signals_observed,
        }
        for key, value in (
            ("response_envelope", self.response_envelope),
            ("response_ref", self.response_ref),
            ("latency_ms", self.latency_ms),
            ("novelty_decision", self.novelty_decision),
            ("error", self.error),
        ):
            if value is not None:
                out[key] = value
        return out


class ProbeLog:
    """Append-only JSONL writer for capability-audit probe records.

    Holds one lazily-opened append-mode handle and flushes after every line
    (the :class:`ScanStore` idiom). :meth:`record` never re-raises — a probe
    log is a forensic convenience, never a reason to abort an audit — so an
    ``OSError`` on write is logged and swallowed, and the record is still
    returned to the caller.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._fh: IO[str] | None = None
        self._seq = 0

    def next_seq(self) -> int:
        """Return the next monotonic sequence number (0-based, per log)."""
        s = self._seq
        self._seq += 1
        return s

    def record(
        self,
        *,
        band: str,
        intent: str,
        prompt: str,
        session: str | None,
        response_envelope: dict[str, Any] | None = None,
        response_ref: str | None = None,
        signals_observed: dict[str, Any] | None = None,
        latency_ms: float | None = None,
        novelty_decision: str | None = None,
        error: str | None = None,
    ) -> ProbeLogRecord:
        """Build a :class:`ProbeLogRecord`, append it as one JSONL line, return it.

        Writing is best-effort: an ``OSError`` is logged and swallowed so a
        disk hiccup can never break the audit. The handle is opened lazily on
        the first record and flushed after every line.
        """
        record = ProbeLogRecord(
            probe_id=f"probe-{uuid.uuid4().hex[:8]}",
            seq=self.next_seq(),
            band=band,
            intent=intent,
            prompt=prompt,
            session=session,
            response_envelope=response_envelope,
            response_ref=response_ref,
            signals_observed=signals_observed or {},
            latency_ms=latency_ms,
            novelty_decision=novelty_decision,
            error=error,
        )
        try:
            if self._fh is None:
                self._fh = self._path.open("a", encoding="utf-8")
            self._fh.write(json.dumps(record.to_dict()) + "\n")
            self._fh.flush()
        except OSError as exc:
            _LOG.warning("recon_probe_log: append to %s failed (%s)", self._path, exc)
        return record

    def close(self) -> None:
        """Flush + close the handle if open (idempotent)."""
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            finally:
                self._fh = None

    @classmethod
    def for_scan_dir(cls, scan_dir: Path) -> ProbeLog:
        """Construct a log writing ``recon_probes.jsonl`` inside ``scan_dir``."""
        return cls(scan_dir / "recon_probes.jsonl")
