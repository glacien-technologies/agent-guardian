"""Shared swarm memory (PRD §4, M5).

The :class:`SharedMemory` is the central nervous system of an active scan.
Eleven concurrent ASI agents plus recon, commander, and evaluator read and
write four kinds of records into it:

* **findings** — confirmed attack-attempt records (one per successful or
  failed probe attempt).
* **reflections** — agent-private reasoning notes that feed semantic recall.
* **attempted_seeds** — dedup index of probe-seed IDs already tried per ASI
  category (prevents wasted budget on retries).
* **fingerprint** — the recon-agent's static description of the target
  surface, populated once at the start of the scan.

Persistence is an append-only JSONL file per scan; every write is fsynced
so a crash mid-scan leaves a recoverable transcript. In-memory typed
indexes are rebuilt from the JSONL on instantiation. The vector index is
*lazy* — populated only when :meth:`vector_search` or
:meth:`write_reflection` with ``embed=True`` is first called.

Optional dependency strategy (mirrors :mod:`agent_guardian.core.redact`):

* ``faiss-cpu`` is in the ``[full]`` extra. When absent we use a NumPy
  brute-force L2 search (also in ``[full]`` via the
  ``sentence-transformers``/``faiss-cpu`` transitive numpy dep).
* ``sentence-transformers`` is in the ``[full]`` extra. When absent we
  degrade to a deterministic hash-based fallback embedding. The hash
  embedder is NOT a real semantic embedder — it exists for testability,
  not real-world relevance. Production users install ``[full]``.
* When neither numpy nor sentence-transformers is available,
  :meth:`vector_search` raises :class:`MemoryFeatureUnavailable`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.core.redact import PiiRedactor
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.finding import Finding

if TYPE_CHECKING:
    pass

__all__ = [
    "MemoryFeatureUnavailable",
    "MemoryRecord",
    "MemoryStats",
    "SharedMemory",
    "VectorHit",
]

_LOG = logging.getLogger(__name__)

EmbedderKind = Literal["sentence-transformers", "hash-fallback", "none"]
RecordType = Literal[
    "finding",
    "reflection",
    "attempted_seed",
    "fingerprint",
    "agent_skipped",
]

_HASH_EMBED_DIM = 128

# Forensic mode — set AGENT_GUARDIAN_FORENSIC_MODE=1 to disable durable
# redaction of memory.jsonl writes. The forensic mode is intended for
# off-line replays where a trusted operator needs the raw target output
# (transcripts, captured tokens, exfil payloads). In the default secure
# mode every reflection / finding / fingerprint payload is run through a
# shared :class:`PiiRedactor` instance before being persisted to JSONL so a
# memory dump never re-emits captured secrets.
_FORENSIC_ENV = "AGENT_GUARDIAN_FORENSIC_MODE"
# Opt-IN PII redaction of memory.jsonl writes. Redaction is now OFF by default
# so the dashboard shows the verbatim target output (account ids, transaction
# ids, dollar amounts were being mangled into "[REDACTED:PHONE_NUMBER]"). Set
# AGENT_GUARDIAN_REDACT_PII=1 to re-enable scrubbing for shareable artifacts.
_REDACT_ENV = "AGENT_GUARDIAN_REDACT_PII"

_TRUTHY = {"1", "true", "yes", "on"}


def _forensic_mode_enabled() -> bool:
    """Read ``AGENT_GUARDIAN_FORENSIC_MODE`` and return a bool.

    Truthy values: ``1``, ``true``, ``yes``, ``on`` (case-insensitive). Kept
    for back-compat; it force-disables redaction even if redaction is opted in.
    """
    return os.environ.get(_FORENSIC_ENV, "").strip().lower() in _TRUTHY


def _redaction_enabled() -> bool:
    """Whether to scrub PII before persisting a memory record.

    OFF by default (operators asked to see the verbatim target output, which
    the PII regexes were corrupting). Opt in with ``AGENT_GUARDIAN_REDACT_PII=1``.
    Forensic mode always wins (no redaction). Evaluated on every write so unit
    tests can flip the env var mid-process.
    """
    if _forensic_mode_enabled():
        return False
    return os.environ.get(_REDACT_ENV, "").strip().lower() in _TRUTHY


# Module-level :class:`PiiRedactor` reused for every memory write so the
# credential/PII regex bank is compiled once. Lazy because in early import
# (e.g. during ``agent_guardian.__init__``) Presidio's analyser-engine init
# adds 1-2 s of boot latency we don't want to pay unless memory is actually
# written.
_MEMORY_REDACTOR: PiiRedactor | None = None


def _get_memory_redactor() -> PiiRedactor:
    global _MEMORY_REDACTOR
    if _MEMORY_REDACTOR is None:
        _MEMORY_REDACTOR = PiiRedactor()
    return _MEMORY_REDACTOR


# Per-record-type list of payload fields that must be scrubbed before the
# record hits durable storage. Keeping this declarative means a new record
# type adds a single entry instead of editing the write path.
_REDACTABLE_PAYLOAD_FIELDS: dict[RecordType, tuple[str, ...]] = {
    "finding": ("summary", "transcript_ref", "trigger_prompt"),
    "reflection": ("content",),
    "fingerprint": ("notes", "inferred_goal"),
    # attempted_seed / agent_skipped carry only enum/id values + an internal
    # ``reason`` string; no attacker-reflected fields. Left out so the
    # secure path is a strict superset of the forensic path semantically.
    "attempted_seed": (),
    "agent_skipped": ("reason",),
}


def _redact_payload(record_type: RecordType, payload: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of ``payload`` with sensitive fields scrubbed.

    Walks the per-record-type field list. ``reflection`` payloads embed the
    full turn record as a JSON-encoded ``content`` string — we re-parse it
    and redact the well-known leaky string fields BEFORE re-encoding so the
    PII regexes never see ascii-escaped multibyte sequences (e.g. ``\\u2014``
    em-dash, which the PHONE_NUMBER pattern would otherwise mangle into
    ``\\u[REDACTED:PHONE_NUMBER]`` and break downstream ``json.loads``).
    """
    fields = _REDACTABLE_PAYLOAD_FIELDS.get(record_type, ())
    if not fields:
        return payload
    redactor = _get_memory_redactor()
    out: dict[str, Any] = dict(payload)
    # WHY: reflection.content is a JSON-encoded turn record — redact at the
    # typed-string level (inner fields) instead of treating the JSON blob as
    # opaque text. The outer pass over the encoded string would mangle any
    # non-ASCII rune via its \uXXXX escape (em-dash → digit run → PHONE_NUMBER).
    deferred_outer: set[str] = set()
    if record_type == "reflection":
        content = out.get("content")
        if isinstance(content, str) and content.startswith("{"):
            try:
                turn = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                turn = None
            if isinstance(turn, dict):
                for inner_field in (
                    "prompt",
                    "target_response",
                    "reasoning",
                    "rationale",
                    "attacker_refusal_text",
                ):
                    inner_value = turn.get(inner_field)
                    if isinstance(inner_value, str) and inner_value:
                        turn[inner_field] = redactor.redact(inner_value)
                out["content"] = json.dumps(turn)
                deferred_outer.add("content")
    for field_name in fields:
        if field_name in deferred_outer:
            continue
        value = out.get(field_name)
        if isinstance(value, str) and value:
            out[field_name] = redactor.redact(value)
    # rc29 finding-aggregation redesign — a Finding now carries a nested
    # ``attempts`` list whose Attempt records duplicate the leak-prone fields
    # (``summary``, ``trigger_prompt``, ``trigger_response``, ``evidence_quote``)
    # at the per-turn level. The legacy compat reader for a v1 record also
    # synthesises this list from the outer fields. Walk the list and redact
    # the per-Attempt copies so the durable JSONL never persists the raw
    # secret values that the outer-level redaction caught.
    if record_type == "finding":
        attempts_payload = out.get("attempts")
        if isinstance(attempts_payload, list) and attempts_payload:
            redacted_attempts: list[Any] = []
            for raw_attempt in attempts_payload:
                if not isinstance(raw_attempt, dict):
                    redacted_attempts.append(raw_attempt)
                    continue
                inner = dict(raw_attempt)
                for inner_field in (
                    "summary",
                    "trigger_prompt",
                    "trigger_response",
                    "evidence_quote",
                ):
                    inner_value = inner.get(inner_field)
                    if isinstance(inner_value, str) and inner_value:
                        inner[inner_field] = redactor.redact(inner_value)
                redacted_attempts.append(inner)
            out["attempts"] = redacted_attempts
    return out


class MemoryFeatureUnavailable(RuntimeError):
    """Raised when a vector feature is invoked without the ``[full]`` extra.

    The hash-fallback embedder works for *storing* embeddings, but real
    similarity search requires numpy. Install ``agent-guardian[full]`` to
    enable vector search.
    """


class MemoryRecord(BaseModel):
    """A single durable entry in the JSONL log.

    ``payload`` is a record-type-specific dict — see :class:`SharedMemory`
    for the schemas. ``timestamp`` is always tz-aware UTC.
    """

    record_type: RecordType
    scan_id: str
    timestamp: datetime
    payload: dict[str, Any]

    model_config = ConfigDict(frozen=True, extra="forbid")


@dataclass(frozen=True)
class MemoryStats:
    """Snapshot of memory contents for introspection / restore inspection."""

    findings: int
    reflections: int
    attempted_seeds: int
    has_fingerprint: bool
    vector_index_size: int
    embedder_kind: EmbedderKind


@dataclass(frozen=True)
class VectorHit:
    """One row of a :meth:`SharedMemory.vector_search` result.

    ``score`` is cosine similarity, normalised to ``[0, 1]`` where higher
    is more similar. For FAISS L2 indices we use ``1 / (1 + distance)``.
    """

    text: str
    agent: str
    score: float
    record_type: Literal["finding", "reflection"]


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _default_root_dir() -> Path:
    return Path.home() / ".agentguardian" / "scans"


def _hash_embed(text: str) -> list[float]:
    """Deterministic hash-based fallback embedder.

    Returns a 128-dim float vector derived from the SHA-256 of the input.
    The vector is L2-normalised so dot products are cosine similarities.

    .. warning::
       This is NOT a semantic embedder. Two strings with overlapping
       words will not be closer than two unrelated strings. It exists so
       :class:`SharedMemory` has *something* deterministic to store when
       ``sentence-transformers`` isn't installed. Production deployments
       must install ``agent-guardian[full]``.
    """
    # SHA-256 → 32 bytes; tile to 128 bytes; unpack as uint8 → float.
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    tiled = (digest * 4)[:_HASH_EMBED_DIM]
    # Centre on 0 (subtract 127.5) and divide by 128 so values live roughly
    # in [-1, 1] before normalisation.
    centred = [(byte - 127.5) / 128.0 for byte in tiled]
    # L2 normalise.
    norm = sum(v * v for v in centred) ** 0.5
    if norm == 0.0:
        return centred
    return [v / norm for v in centred]


class SharedMemory:
    """Append-only shared memory for an active scan (PRD §4).

    Thread-safe across asyncio tasks via :class:`asyncio.Lock` — every
    write serialises at the lock. Reads operate on pure in-memory indexes
    and never block writes.

    Persistence: every write fsyncs the JSONL line so a crash leaves a
    recoverable transcript. :meth:`restore` replays the JSONL on
    instantiation if the file exists.

    The vector index is lazily initialised — the first call to
    :meth:`vector_search` or :meth:`write_reflection` with ``embed=True``
    pays the model-load cost.
    """

    def __init__(
        self,
        scan_id: str,
        *,
        root_dir: Path | None = None,
        embedder_model: str = "all-MiniLM-L6-v2",
        use_faiss: bool = True,
        use_sentence_transformers: bool = True,
    ) -> None:
        if not scan_id:
            raise ValueError("SharedMemory requires a non-empty scan_id")

        self.scan_id = scan_id
        self.root_dir = root_dir if root_dir is not None else _default_root_dir()
        self.embedder_model = embedder_model
        self._use_faiss = use_faiss
        self._use_st = use_sentence_transformers

        self.scan_dir = self.root_dir / scan_id
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.scan_dir / "memory.jsonl"
        self.stats_path = self.scan_dir / "stats.json"

        self._lock = asyncio.Lock()
        # Local file lock guards JSONL writes inside the to_thread call
        # so two SharedMemory instances in the same process don't interleave
        # partial appends. Cross-process safety is via POSIX atomic-append on
        # lines <PIPE_BUF; the asyncio lock alone is enough for the common
        # single-process swarm case.
        self._file_lock = threading.Lock()

        # In-memory indexes — rebuilt from JSONL.
        self._findings_by_asi: dict[AsiCategory, list[Finding]] = {a: [] for a in AsiCategory}
        self._all_findings: list[Finding] = []
        self._attempted_seeds: dict[AsiCategory, set[str]] = {a: set() for a in AsiCategory}
        self._reflections_by_agent: dict[str, list[str]] = {}
        self._fingerprint: TargetFingerprint | None = None
        # Agents skipped by the swarm commander's applicability gate. Each
        # entry is the persisted payload (``agent``, ``asi``, ``reason``)
        # so coverage tooling can answer "which agents did the swarm
        # bypass and why?" without replaying the JSONL again.
        self._agent_skipped: list[dict[str, Any]] = []

        # Vector index — lazy.
        self._vectors: list[list[float]] = []
        self._vector_meta: list[tuple[str, str, Literal["finding", "reflection"]]] = []
        self._embedder_kind: EmbedderKind = "none"
        self._st_model: Any | None = None
        self._faiss_index: Any | None = None
        self._embedder_initialised = False

        # Replay JSONL into in-memory indexes.
        if self.jsonl_path.exists():
            self._replay()
            _LOG.info(
                "memory: replayed scan %s (findings=%d, reflections=%d, attempted_seeds=%d)",
                scan_id,
                len(self._all_findings),
                sum(len(v) for v in self._reflections_by_agent.values()),
                sum(len(s) for s in self._attempted_seeds.values()),
            )
        else:
            _LOG.debug("memory: fresh scan %s (no jsonl yet at %s)", scan_id, self.jsonl_path)

    # ------------------------------------------------------------------
    # Replay / restore
    # ------------------------------------------------------------------

    def _replay(self) -> None:
        """Rebuild in-memory indexes from the JSONL file.

        Malformed lines are logged at WARNING and skipped. Partial recovery
        is preferable to no recovery.
        """
        with self.jsonl_path.open("r", encoding="utf-8") as fh:
            for line_no, raw in enumerate(fh, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    record = MemoryRecord.model_validate_json(stripped)
                except Exception as exc:
                    _LOG.warning(
                        "Skipping malformed JSONL line %d in %s: %s",
                        line_no,
                        self.jsonl_path,
                        exc,
                    )
                    continue
                self._apply_record(record)

    def _apply_record(self, record: MemoryRecord) -> None:
        """Apply one validated record to the in-memory indexes."""
        if record.record_type == "finding":
            try:
                finding = Finding.model_validate(record.payload)
            except Exception as exc:
                _LOG.warning("Skipping invalid finding payload: %s", exc)
                return
            self._all_findings.append(finding)
            self._findings_by_asi[finding.asi].append(finding)
        elif record.record_type == "reflection":
            agent = str(record.payload.get("agent", ""))
            content = str(record.payload.get("content", ""))
            if not agent or not content:
                _LOG.debug(
                    "memory replay: dropping reflection with empty agent/content (agent=%r)",
                    agent,
                )
                return
            self._reflections_by_agent.setdefault(agent, []).append(content)
        elif record.record_type == "attempted_seed":
            try:
                asi = AsiCategory(record.payload.get("asi"))
            except (ValueError, KeyError) as exc:
                _LOG.debug(
                    "memory replay: dropping attempted_seed with bad asi %r (%s)",
                    record.payload.get("asi"),
                    exc,
                )
                return
            seed_id = str(record.payload.get("seed_id", ""))
            if seed_id:
                self._attempted_seeds[asi].add(seed_id)
        elif record.record_type == "fingerprint":
            try:
                self._fingerprint = TargetFingerprint.model_validate(record.payload)
            except Exception as exc:
                _LOG.warning("Skipping invalid fingerprint payload: %s", exc)
        elif record.record_type == "agent_skipped":
            # Defensive validation — at minimum the payload must include an
            # ``agent`` key. Other fields are surfaced as-is to keep the
            # schema additive (operators can extend the payload with extra
            # diagnostic context without an in-process schema migration).
            skipped_agent = record.payload.get("agent")
            if isinstance(skipped_agent, str) and skipped_agent:
                self._agent_skipped.append(dict(record.payload))

    @classmethod
    def restore(
        cls,
        scan_id: str,
        *,
        root_dir: Path | None = None,
    ) -> SharedMemory:
        """Re-instantiate a :class:`SharedMemory` from disk.

        Equivalent to ``SharedMemory(scan_id, root_dir=root_dir)`` — the
        constructor replays the JSONL automatically. This classmethod is
        the documented entrypoint for "load an existing scan".
        """
        return cls(scan_id, root_dir=root_dir)

    # ------------------------------------------------------------------
    # JSONL persistence
    # ------------------------------------------------------------------

    def _append_line_sync(self, line: str) -> None:
        """Append one JSONL line and fsync. Runs inside :meth:`asyncio.to_thread`."""
        with self._file_lock, open(self.jsonl_path, "a", encoding="utf-8") as fh:
            fh.write(line)
            if not line.endswith("\n"):
                fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())

    async def _write_record(self, record: MemoryRecord) -> None:
        # BLOCKER #1 — durable-storage redaction. Every JSONL line is run
        # through :class:`PiiRedactor` so a memory dump never re-emits
        # captured secrets / PII back to disk. The in-memory indexes still
        # carry the raw payload (this method is called *after* the in-
        # memory index update in every write path) so live observers see
        # the full record while the persisted artifact is scrubbed.
        # Forensic mode (AGENT_GUARDIAN_FORENSIC_MODE=1) skips the redaction
        # pass for off-line replays where the operator needs the raw turn
        # text. The forensic switch is read on every write so a unit test
        # can flip it mid-process.
        if _redaction_enabled():
            redacted_payload = _redact_payload(record.record_type, record.payload)
            redacted = record.model_copy(update={"payload": redacted_payload})
            line = redacted.model_dump_json()
        else:
            line = record.model_dump_json()
        await asyncio.to_thread(self._append_line_sync, line)

    def _write_stats_snapshot_sync(self) -> None:
        """Persist a small JSON snapshot for fast restore-inspection."""
        snapshot = {
            "scan_id": self.scan_id,
            "findings": len(self._all_findings),
            "reflections": sum(len(v) for v in self._reflections_by_agent.values()),
            "attempted_seeds": sum(len(s) for s in self._attempted_seeds.values()),
            "has_fingerprint": self._fingerprint is not None,
            "vector_index_size": len(self._vectors),
            "embedder_kind": self._embedder_kind,
            "updated_at": _utcnow().isoformat(),
        }
        tmp = self.stats_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        tmp.replace(self.stats_path)

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    async def write_finding(self, finding: Finding) -> None:
        """Persist one :class:`Finding` to the JSONL and the in-memory index."""
        record = MemoryRecord(
            record_type="finding",
            scan_id=self.scan_id,
            timestamp=_utcnow(),
            payload=finding.model_dump(mode="json"),
        )
        async with self._lock:
            await self._write_record(record)
            self._all_findings.append(finding)
            self._findings_by_asi[finding.asi].append(finding)
            await asyncio.to_thread(self._write_stats_snapshot_sync)
        _LOG.debug(
            "memory write: finding asi=%s severity=%s probe=%s (total_findings=%d)",
            finding.asi.value,
            finding.severity.value,
            finding.probe_id,
            len(self._all_findings),
        )

    async def write_reflection(
        self,
        agent: str,
        content: str,
        *,
        embed: bool = True,
    ) -> None:
        """Persist an agent reflection. Optionally generate and store an embedding."""
        if not agent:
            raise ValueError("agent must be non-empty")
        if not content:
            raise ValueError("content must be non-empty")
        record = MemoryRecord(
            record_type="reflection",
            scan_id=self.scan_id,
            timestamp=_utcnow(),
            payload={"agent": agent, "content": content},
        )
        async with self._lock:
            await self._write_record(record)
            self._reflections_by_agent.setdefault(agent, []).append(content)
            if embed:
                vec = self._embed(content)
                self._vectors.append(vec)
                self._vector_meta.append((content, agent, "reflection"))
                self._add_to_faiss(vec)
            await asyncio.to_thread(self._write_stats_snapshot_sync)
        # Per-write reflection bookkeeping is intentionally not logged: it
        # fires on every turn and floods the operator log with no actionable
        # signal. Reflection volume is already visible in the stats snapshot.

    async def write_attempted_seed(self, asi: AsiCategory, seed_id: str) -> None:
        """Record that an ASI agent tried a particular probe seed.

        Idempotent — re-writing the same ``(asi, seed_id)`` pair still
        appends a JSONL line (audit trail) but the in-memory set
        deduplicates.
        """
        if not seed_id:
            raise ValueError("seed_id must be non-empty")
        record = MemoryRecord(
            record_type="attempted_seed",
            scan_id=self.scan_id,
            timestamp=_utcnow(),
            payload={"asi": asi.value, "seed_id": seed_id},
        )
        async with self._lock:
            await self._write_record(record)
            self._attempted_seeds[asi].add(seed_id)
            await asyncio.to_thread(self._write_stats_snapshot_sync)

    async def write_agent_skipped(
        self,
        *,
        agent: str,
        asi: AsiCategory | None,
        reason: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Persist that the swarm bypassed an ASI agent for this fingerprint.

        The live :class:`SwarmEvent` ``kind="agent_skipped"`` is ephemeral
        (it goes only to the optional observer). This durable record means
        post-scan tooling can answer "which agents were skipped and why?"
        without replaying observer events that were never captured.
        Implements IMPORTANT #5 in the 14-flaw inventory.
        """
        if not agent:
            raise ValueError("agent must be non-empty")
        payload: dict[str, Any] = {
            "agent": agent,
            "asi": asi.value if asi is not None else None,
            "reason": reason,
        }
        if extra:
            payload.update(extra)
        record = MemoryRecord(
            record_type="agent_skipped",
            scan_id=self.scan_id,
            timestamp=_utcnow(),
            payload=payload,
        )
        async with self._lock:
            await self._write_record(record)
            self._agent_skipped.append(dict(payload))
            await asyncio.to_thread(self._write_stats_snapshot_sync)

    async def set_target_fingerprint(self, fingerprint: TargetFingerprint) -> None:
        """Set (or replace) the target fingerprint.

        Idempotent — latest wins. Every call appends a JSONL line so the
        audit trail records all updates; the in-memory pointer always
        reflects the most recent value.
        """
        record = MemoryRecord(
            record_type="fingerprint",
            scan_id=self.scan_id,
            timestamp=_utcnow(),
            payload=fingerprint.model_dump(mode="json"),
        )
        async with self._lock:
            await self._write_record(record)
            self._fingerprint = fingerprint
            await asyncio.to_thread(self._write_stats_snapshot_sync)

    # ------------------------------------------------------------------
    # Read API (pure, no I/O, no lock)
    # ------------------------------------------------------------------

    def findings_by_asi(self, asi: AsiCategory) -> tuple[Finding, ...]:
        return tuple(self._findings_by_asi[asi])

    def attempted_seeds(self, asi: AsiCategory) -> frozenset[str]:
        return frozenset(self._attempted_seeds[asi])

    def target_fingerprint(self) -> TargetFingerprint | None:
        return self._fingerprint

    def reflections_for(self, agent: str) -> tuple[str, ...]:
        return tuple(self._reflections_by_agent.get(agent, ()))

    def all_findings(self) -> tuple[Finding, ...]:
        return tuple(self._all_findings)

    def skipped_agents(self) -> tuple[dict[str, Any], ...]:
        """Return the durable record of agents the swarm bypassed."""
        return tuple(self._agent_skipped)

    def stats(self) -> MemoryStats:
        return MemoryStats(
            findings=len(self._all_findings),
            reflections=sum(len(v) for v in self._reflections_by_agent.values()),
            attempted_seeds=sum(len(s) for s in self._attempted_seeds.values()),
            has_fingerprint=self._fingerprint is not None,
            vector_index_size=len(self._vectors),
            embedder_kind=self._embedder_kind,
        )

    # ------------------------------------------------------------------
    # Embedding / vector search
    # ------------------------------------------------------------------

    def _init_embedder(self) -> None:
        """Lazy embedder init. Picks sentence-transformers if available, else hash fallback."""
        if self._embedder_initialised:
            return
        self._embedder_initialised = True
        if self._use_st:
            try:
                from sentence_transformers import (  # type: ignore[import-not-found,unused-ignore]  # pragma: no cover
                    SentenceTransformer,
                )
            except ImportError:
                self._st_model = None
            else:  # pragma: no cover  # covered by [full]-extra integration test slot
                try:
                    self._st_model = SentenceTransformer(self.embedder_model)
                    self._embedder_kind = "sentence-transformers"
                    return
                except Exception as exc:
                    _LOG.warning(
                        "sentence-transformers load failed (%s); falling back to hash embedder",
                        exc,
                    )
                    self._st_model = None
        self._embedder_kind = "hash-fallback"

    def _init_faiss(self, dim: int) -> None:
        """Lazy FAISS index creation."""
        if not self._use_faiss or self._faiss_index is not None:
            return
        try:
            import faiss  # type: ignore[import-not-found,unused-ignore]  # pragma: no cover
        except ImportError:
            return
        # pragma: no cover  # covered by [full]-extra integration test slot
        self._faiss_index = faiss.IndexFlatL2(dim)  # pragma: no cover

    def _embed(self, text: str) -> list[float]:
        """Return a unit-norm embedding for ``text``."""
        self._init_embedder()
        if self._st_model is not None:  # pragma: no cover
            # covered by [full]-extra integration test slot
            import numpy as np  # type: ignore[import-not-found,unused-ignore]

            arr = self._st_model.encode([text], normalize_embeddings=True)
            vec = np.asarray(arr[0], dtype=float).tolist()
            return list(vec)
        return _hash_embed(text)

    def _add_to_faiss(self, vec: list[float]) -> None:
        if self._faiss_index is None:
            self._init_faiss(len(vec))
        if self._faiss_index is None:
            return
        # pragma: no cover  # covered by [full]-extra integration test slot
        import numpy as np  # pragma: no cover

        self._faiss_index.add(np.asarray([vec], dtype="float32"))  # pragma: no cover

    async def vector_search(self, query: str, *, k: int = 5) -> list[VectorHit]:
        """Return the top-``k`` most semantically similar reflections / findings.

        Requires the ``[full]`` extra for *real* semantic search. Without
        numpy, vector search raises :class:`MemoryFeatureUnavailable`. The
        hash-fallback embedder works for *storing* embeddings (so the
        stored vectors are consistent), but search needs vectorised math.
        """
        if k <= 0:
            return []
        # Need numpy for search. Refuse early if absent.
        try:
            import numpy as np  # type: ignore[import-not-found,unused-ignore]
        except ImportError as exc:
            raise MemoryFeatureUnavailable(
                "vector_search requires numpy; install agent-guardian[full] "
                "to enable semantic similarity over swarm memory."
            ) from exc

        self._init_embedder()
        if not self._vectors:
            return []

        async with self._lock:
            stored = list(self._vectors)
            metas = list(self._vector_meta)

        query_vec = self._embed(query)

        # FAISS path (only when index was built).
        if self._faiss_index is not None and self._use_faiss:  # pragma: no cover
            # pragma: no cover  # covered by [full]-extra integration test slot
            q = np.asarray([query_vec], dtype="float32")
            distances, indices = self._faiss_index.search(q, min(k, len(stored)))
            hits: list[VectorHit] = []
            for dist, idx in zip(distances[0], indices[0], strict=True):
                if idx < 0 or idx >= len(metas):
                    continue
                text, agent, kind = metas[int(idx)]
                hits.append(
                    VectorHit(
                        text=text,
                        agent=agent,
                        score=1.0 / (1.0 + float(dist)),
                        record_type=kind,
                    )
                )
            return hits

        # NumPy brute-force fallback (cosine over unit-norm vectors == dot product).
        matrix = np.asarray(stored, dtype=float)
        q = np.asarray(query_vec, dtype=float)
        # All stored vectors are already L2-normalised, so dot == cosine.
        scores = matrix @ q
        order = np.argsort(-scores)[:k]
        hits = []
        for idx in order:
            text, agent, kind = metas[int(idx)]
            # Clamp to [0, 1] (numerical fuzz can push cosine slightly >1).
            score = float(max(0.0, min(1.0, (scores[int(idx)] + 1.0) / 2.0)))
            hits.append(VectorHit(text=text, agent=agent, score=score, record_type=kind))
        return hits

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def aclose(self) -> None:
        """Release any resources. Currently a no-op; defined for symmetry."""
        # No long-lived file handles — every write opens/closes the JSONL.
        # The FAISS index lives in-memory and is freed on GC.
        self._st_model = None
        self._faiss_index = None

    async def __aenter__(self) -> SharedMemory:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
