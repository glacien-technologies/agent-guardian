"""Cross-process partial-scan snapshot.

The CLI's swarm run lives in a different OS process from the dashboard
``uvicorn`` server (the CLI spawns the server as a child via
``AutoServeManager``). The dashboard's :class:`ScanStore.is_running`
registry is in-process only, so without a disk-backed bridge the
dashboard subprocess sees every scan as "unknown" until the terminal
``scan.raw.json`` lands at the very end of the run -- which is exactly
the broken-wire the user reported (AIVSS=0, ASI rows always "running",
at-a-glance always 0).

This module is the bridge:

* The CLI process attaches :func:`make_partial_writer` as a swarm
  observer; after every ``agent_done`` event it snapshots a partial
  :class:`Scan` from the swarm's mid-flight state and writes it to
  ``<scan_dir>/scan.partial.json``.
* The dashboard process detects the partial file in
  :class:`ScanStore.is_running` and :class:`ScanStore.load_completed`
  (added in ``scan_store.py``) and renders the real mid-flight numbers
  instead of the always-zero placeholders.

The partial Scan is a fully-valid :class:`Scan` model (it has to be,
since :meth:`ScanStore.load_completed` returns ``Scan`` instances) --
fields that aren't yet known mid-flight default to empty / zero, which
the dashboard's view-model already handles gracefully.
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
import traceback
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from agent_guardian._version import __version__
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier

if TYPE_CHECKING:
    from agent_guardian.core.swarm import SwarmCommander, SwarmEvent

__all__ = [
    "INTERRUPT_MARKER_FILENAME",
    "PARTIAL_SCAN_FILENAME",
    "JsonlLogHandler",
    "build_partial_scan",
    "clear_interrupt_marker",
    "install_jsonl_log_handler",
    "interrupt_marker_path",
    "is_interrupted_on_disk",
    "is_terminal_scan_on_disk",
    "make_events_writer",
    "make_partial_writer",
    "partial_scan_path",
    "read_partial_scan",
    "write_interrupt_marker",
    "write_partial_scan",
]

_LOG = logging.getLogger(__name__)


# Phase 2 Step 2.1 — per-scan monotonic ``seq`` counter shared across
# the SwarmEvent writer (:func:`make_events_writer`) and the Python
# logging bridge (:class:`JsonlLogHandler`) so every JSONL line in a
# given scan directory has a strictly-monotonic top-level ``seq``,
# regardless of which sink wrote it. Keyed by the resolved scan_dir
# string. Thread-safe via the lock — log records emit on worker
# threads (httpx, asyncio executors) while SwarmEvents emit on the
# scan-driver thread.
_SEQ_COUNTERS: dict[str, int] = {}
_SEQ_LOCK = threading.Lock()


def _next_seq(scan_dir: Path) -> int:
    """Return the next monotonic seq for the given scan directory.

    First call for a fresh scan_dir returns 0. Thread-safe.
    """
    key = str(scan_dir.resolve())
    with _SEQ_LOCK:
        seq = _SEQ_COUNTERS.get(key, 0)
        _SEQ_COUNTERS[key] = seq + 1
        return seq


# On-disk filename for the in-flight partial scan snapshot. Distinct from the
# terminal ``scan.raw.json`` / ``scan.json`` filenames so a partial snapshot
# can't be mistaken for a completed scan by any caller that hasn't been
# updated to check for it.
PARTIAL_SCAN_FILENAME: str = "scan.partial.json"


def partial_scan_path(scan_dir: Path) -> Path:
    """Return the canonical path of the partial-scan snapshot for a scan dir."""
    return scan_dir / PARTIAL_SCAN_FILENAME


def is_terminal_scan_on_disk(scan_dir: Path) -> bool:
    """Return ``True`` when a terminal scan file (raw or signed) is on disk."""
    return (scan_dir / "scan.raw.json").is_file() or (scan_dir / "scan.json").is_file()


# On-disk marker the CLI drops when a scan ends abnormally (user Ctrl-C, a
# sandbox violation, an LLM-provider error) before it could finalise a
# terminal ``scan.json``. The dashboard treats its presence as a definitive
# "failed" so a cancelled scan reads ``failed`` immediately, rather than
# lingering as ``live`` until the activity-staleness window expires. A hard
# kill (SIGKILL / OOM) can't write it -- those still fall back to staleness.
INTERRUPT_MARKER_FILENAME: str = "scan.interrupted"


def interrupt_marker_path(scan_dir: Path) -> Path:
    """Return the canonical path of the abnormal-termination marker."""
    return scan_dir / INTERRUPT_MARKER_FILENAME


def is_interrupted_on_disk(scan_dir: Path) -> bool:
    """Return ``True`` when a scan was recorded as abnormally terminated."""
    return interrupt_marker_path(scan_dir).is_file()


def write_interrupt_marker(scan_dir: Path, reason: str) -> None:
    """Record that a scan ended before finalising (best-effort).

    Stores a short ``reason`` + ISO timestamp so an operator inspecting the
    scan dir can see why the run never produced a terminal ``scan.json``.
    Never raises -- a failure to mark is strictly less bad than masking the
    original interrupt.
    """
    target = interrupt_marker_path(scan_dir)
    try:
        scan_dir.mkdir(parents=True, exist_ok=True)
        payload = {"reason": reason, "at": datetime.now(tz=UTC).isoformat()}
        target.write_text(json.dumps(payload), encoding="utf-8")
    except OSError as exc:  # pragma: no cover -- best-effort disk write
        _LOG.warning("partial_scan: interrupt marker write failed for %s (%s)", target, exc)


def clear_interrupt_marker(scan_dir: Path) -> None:
    """Remove a stale abnormal-termination marker (best-effort).

    Called from the success path so a ``scan_id`` reused after a prior failed
    run doesn't inherit the old marker once a terminal ``scan.json`` lands.
    """
    target = interrupt_marker_path(scan_dir)
    if not target.is_file():
        return
    with contextlib.suppress(OSError):
        target.unlink()


def write_partial_scan(scan_dir: Path, scan: Scan) -> None:
    """Persist a partial :class:`Scan` snapshot to ``<scan_dir>/scan.partial.json``.

    Writes atomically via ``<file>.tmp`` + ``replace`` so a reader can never
    observe a half-written / truncated JSON document (the dashboard polls
    this file every ~500 ms via SSE).
    """
    scan_dir.mkdir(parents=True, exist_ok=True)
    target = partial_scan_path(scan_dir)
    tmp = target.with_suffix(target.suffix + ".tmp")
    try:
        tmp.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
        tmp.replace(target)
    except OSError as exc:  # pragma: no cover -- best-effort disk write
        _LOG.warning("partial_scan: write failed for %s (%s)", target, exc)


def read_partial_scan(scan_dir: Path) -> Scan | None:
    """Return the partial Scan snapshot if present, else ``None``.

    Tolerates a malformed / half-written file by returning ``None`` rather
    than raising -- the caller (``ScanStore.load_completed``) then treats
    the scan as fully unknown, which is the same fallback path the existing
    cold-start scans use.
    """
    path = partial_scan_path(scan_dir)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning("partial_scan: read failed for %s (%s)", path, exc)
        return None
    if not isinstance(payload, dict):
        return None
    try:
        return Scan.model_validate(payload)
    except (ValueError, TypeError) as exc:
        _LOG.warning(
            "partial_scan: model_validate failed for %s (%s: %s)",
            path,
            type(exc).__name__,
            exc,
        )
        return None


def build_partial_scan(swarm: SwarmCommander) -> Scan:
    """Build a partial :class:`Scan` from a swarm's mid-flight state.

    The snapshot reflects what's already known after the last ``agent_done``
    event: the findings accumulated in ``swarm.memory``, the per-ASI score
    contributions from completed agent reports, the live token / cost
    counters, and the elapsed wall-clock.

    Fields the swarm hasn't computed yet (e.g. ``aivss``, ``sub_scores``,
    final band) are filled with provisional values so the dashboard's
    view-model branches into the ``scan is not None`` paths and renders real
    numbers instead of placeholders. The provisional band is
    :class:`SeverityBand.NOT_EVALUATED` so a partial snapshot can never be
    mistaken for an authoritative completed scan.
    """
    # Pull what's already known. None of these reads block the swarm (we
    # touch synchronous attribute snapshots; the memory write path is the
    # one that runs concurrently and is itself lock-protected).
    findings = list(swarm.memory.all_findings())
    fingerprint = swarm._fingerprint
    target_mode: str = fingerprint.mode if fingerprint is not None else "prompt"
    target_ref: str = fingerprint.ref if fingerprint is not None else swarm.config.scan_id

    # Per-ASI provisional score via the same ``asi_score()`` formula the
    # finalise phase uses (PRD §6 Step 2) so the dashboard's radar +
    # breakdown table tick over with real numbers as findings arrive
    # instead of staying flagged "pending" until end-of-scan. Categories
    # that have at least one finding OR a completed agent report get a
    # provisional value (real findings -> score < 100, completed-agent /
    # no-findings -> 100); categories with neither stay absent from the
    # dict so the dashboard renders them as "queued" rather than
    # fabricating coverage that hasn't happened yet.
    from agent_guardian.core.scoring import asi_score as _asi_score

    per_asi_findings: dict[AsiCategory, list[Finding]] = {cat: [] for cat in AsiCategory}
    for finding in findings:
        per_asi_findings.setdefault(finding.asi, []).append(finding)
    completed_categories: set[AsiCategory] = {
        r.asi_category for r in swarm._agent_reports if r.asi_category is not None
    }
    # Tester report #4 — provisional asi_score divides by the FULL probe
    # pool (loaded seeds) rather than landed-probes only, so a single
    # medium finding from a 17-probe run reads as ~98 (not 60). Reads
    # from completed agent reports first (authoritative count); falls
    # back to the running agents' active seed index when an agent is
    # still in flight.
    probes_per_category: dict[AsiCategory, int] = {}
    for report in swarm._agent_reports:
        if report.asi_category is None:
            continue
        n = getattr(report, "probes_attempted_count", 0) or 0
        if n > 0:
            probes_per_category[report.asi_category] = (
                probes_per_category.get(report.asi_category, 0) + n
            )
    for active_agent in getattr(swarm, "_active_agents", []) or []:
        cat = getattr(active_agent, "asi_category", None)
        if cat is None or cat in probes_per_category:
            continue
        seed_index = getattr(active_agent, "_seed_index", None) or {}
        if seed_index:
            probes_per_category[cat] = len(seed_index)
    asi_scores: dict[AsiCategory, float] = {}
    for cat, cat_findings in per_asi_findings.items():
        has_real_evidence = bool(cat_findings) or cat in completed_categories
        if not has_real_evidence:
            continue
        asi_scores[cat] = _asi_score(
            cat_findings,
            total_probes=probes_per_category.get(cat, 0),
        )

    # Live cost / tokens read off the same counter objects the budget
    # watchdog samples (so the at-a-glance widget never lags those counters
    # by more than one polling interval).
    live_cost = swarm._live_cost_usd()
    live_tokens = (
        swarm._commander_usage.prompt_tokens
        + swarm._commander_usage.completion_tokens
        + swarm._finalise_usage.prompt_tokens
        + swarm._finalise_usage.completion_tokens
    )
    for agent in swarm._active_agents:
        live_tokens += (
            agent._attacker_usage.prompt_tokens
            + agent._attacker_usage.completion_tokens
            + agent._evaluator_usage.prompt_tokens
            + agent._evaluator_usage.completion_tokens
        )

    # Elapsed wall-clock from the swarm's recorded start, clamped to >=0.
    import time as _time

    duration = max(0.0, _time.monotonic() - swarm._start_time)

    tier: Tier = (
        swarm.config.tier_override if swarm.config.tier_override is not None else Tier.T3_STANDARD
    )

    # Mode flows through verbatim from the swarm config so the partial snapshot
    # advertises the same scan-mode the terminal scan.raw.json will. The swarm
    # config's ``mode`` is technically ``ScanMode | None`` (defaults to FULL
    # in ``__post_init__``); narrow defensively so mypy --strict is clean.
    from agent_guardian.core.swarm import ScanMode as _ScanMode

    mode_enum = swarm.config.mode if swarm.config.mode is not None else _ScanMode.FULL
    return Scan(
        id=swarm.config.scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="partial",
        target_mode=target_mode,  # type: ignore[arg-type]
        target_ref=target_ref,
        tier=tier,
        # Provisional AIVSS: latest checkpoint sample, falling back to 0 when
        # the checkpoint loop hasn't sampled yet. The dashboard's score card
        # already handles a 0 AIVSS gracefully (renders the number; the band
        # below keeps it from being mis-claimed as EXCELLENT/GOOD).
        aivss=(swarm._aivss_window[-1] if swarm._aivss_window else 0),
        # Never claim a final band on a partial snapshot -- NOT_EVALUATED is
        # the canonical "not yet authoritative" band the post-72d4deb scan
        # model already uses for stub runs / incomplete scans.
        band=SeverityBand.NOT_EVALUATED,
        sub_scores={},
        findings=findings,
        asi_scores=asi_scores,
        probes_per_category=probes_per_category,
        duration_seconds=duration,
        cost_usd=max(0.0, live_cost),
        tokens_total=live_tokens,
        mode=mode_enum.value,
        mode_authoritative=False,
        scoring_valid=False,
        engine={
            "commander": swarm.config.commander_model,
            "attacker": swarm.config.attacker_model,
            "evaluator": swarm.config.evaluator_model,
        },
        created_at=datetime.now(tz=UTC),
    )


def make_partial_writer(
    swarm: SwarmCommander,
    scan_dir: Path,
) -> Callable[[SwarmEvent], None]:
    """Return a swarm observer that snapshots a partial Scan on each event.

    Snapshots are written on ``agent_done`` (the canonical "an agent has
    produced its verdict" event) and on ``checkpoint`` (so the at-a-glance
    widget's elapsed / cost counters stay fresh even when no agent has
    finished in the last poll window). All other events are ignored.

    The returned closure chains onto the swarm's pre-existing observer
    (CLI feed renderer, otel exporter, etc.) -- it sets ``swarm.observer``
    to a wrapper that forwards to the prior observer first, then writes
    the snapshot. Mirrors the wrap pattern in
    :meth:`AttackFeedRenderer.attach_to` / :meth:`ScanTUI.attach_to`.
    """
    prior_observer = swarm.observer

    def _observer(event: SwarmEvent) -> None:
        if prior_observer is not None:
            try:
                prior_observer(event)
            except Exception as exc:  # pragma: no cover -- defensive
                _LOG.warning(
                    "partial_scan: prior observer raised %s: %s",
                    type(exc).__name__,
                    exc,
                )
        # Snapshot only on events that actually change the partial state --
        # avoids one disk write per reflection event in a chatty scan.
        if event.kind not in ("agent_done", "checkpoint", "scan_done"):
            return
        # On scan_done the terminal scan.raw.json is about to be written by
        # the CLI's finalise path; we deliberately do NOT snapshot here so
        # the partial file is removed and the dashboard reads the terminal
        # file straight away (no flicker from a stale partial).
        if event.kind == "scan_done":
            path = partial_scan_path(scan_dir)
            try:
                if path.is_file():
                    path.unlink()
            except OSError as exc:  # pragma: no cover -- best-effort
                _LOG.warning("partial_scan: unlink %s failed (%s)", path, exc)
            return
        try:
            partial = build_partial_scan(swarm)
        except Exception as exc:  # pragma: no cover -- defensive
            _LOG.warning(
                "partial_scan: build failed (%s: %s) -- skipping snapshot",
                type(exc).__name__,
                exc,
            )
            return
        write_partial_scan(scan_dir, partial)

    swarm.observer = _observer
    return _observer


def _event_to_jsonable(event: SwarmEvent) -> dict[str, object]:
    """Convert a :class:`SwarmEvent` into the JSON shape that
    ``dashboard_view._parse_event_line`` reads.

    Locked wire format (matches the fixture used by the Logs tab tests):

      {
        "kind":               "<EventKind.value>",
        "timestamp":          "<ISO 8601 UTC>",
        "agent":              "<str or null>",
        "asi":                "<AsiCategory.value or null>",
        "provisional_aivss":  <int or null>,
        "decision":           "<CheckpointDecision.value or null>",
        "payload":            { ... arbitrary JSON-safe payload ... }
      }

    Enum members are flattened to their ``.value`` so the on-disk file is
    self-describing and stable across Python versions. ``datetime`` is
    rendered as ISO 8601 with UTC offset preserved.
    """
    asi_val = event.asi.value if event.asi is not None else None
    decision_val = event.decision.value if event.decision is not None else None
    # ``payload`` is a dict[str, object]; most callers stuff primitives in.
    # Defensive: if a caller stuffed in a non-JSON-safe value, fall back to
    # ``str()`` so we never silently drop the line.
    safe_payload: dict[str, object] = {}
    for k, v in (event.payload or {}).items():
        key = str(k)
        try:
            json.dumps(v)
        except (TypeError, ValueError):
            safe_payload[key] = str(v)
        else:
            safe_payload[key] = v
    # ``EventKind`` is a ``Literal[...]`` string union, not an Enum — the
    # value is already a plain ``str`` at this point.
    out: dict[str, object] = {
        "kind": str(event.kind),
        "timestamp": event.timestamp.isoformat(),
        "agent": event.agent,
        "asi": asi_val,
        "provisional_aivss": event.provisional_aivss,
        "decision": decision_val,
        "payload": safe_payload,
    }
    # Phase 2 Step 2.1 — emit ``seq`` as a top-level field (NOT nested
    # inside payload) so a cross-process replay can filter by it via
    # simple line-prefix matching. Mirrors the contract in
    # ``scan_store.event_to_payload``. Legacy events without ``seq``
    # omit the field entirely so the on-disk shape is back-compatible.
    if event.seq is not None:
        out["seq"] = event.seq
    return out


def make_events_writer(
    swarm: SwarmCommander,
    scan_dir: Path,
) -> Callable[[SwarmEvent], None]:
    """Return a swarm observer that appends every event as a JSON line to
    ``<scan_dir>/events.jsonl``.

    The Executive theme's Logs tab (``_tab_logs.html``) reads from this
    file via ``dashboard_view._assemble_logs_tail``. Before this writer
    landed (2026-05-31), the file was never created — only the dashboard
    server's in-process ``ScanStore.append_event`` knew how to write it,
    and the CLI scanner had no path to that code, so every operator's
    Logs tab read empty.

    Wire format: see :func:`_event_to_jsonable`. One event per line,
    fsync-free (the dashboard reader handles partial/torn lines via
    ``_parse_event_line``'s ``JSONDecodeError`` swallow).

    The returned closure chains onto the swarm's pre-existing observer
    (CLI feed renderer, otel exporter, partial writer, etc.) — mirrors
    the wrap pattern in :func:`make_partial_writer`. Failure to append
    is logged but never re-raised, so a full disk or a permissions blip
    can't break the swarm.
    """
    import dataclasses as _dataclasses

    prior_observer = swarm.observer
    events_path = scan_dir / "events.jsonl"
    # Touch the file so the dashboard sees an empty (but present) log even
    # on the very first event-less moment of a scan. Open mode is "a" so
    # parallel writes from a paused-and-resumed scan append rather than
    # truncate.
    is_fresh = not events_path.exists() or events_path.stat().st_size == 0
    try:
        events_path.touch(exist_ok=True)
    except OSError as exc:  # pragma: no cover -- defensive
        _LOG.warning(
            "events_writer: failed to touch %s (%s: %s)",
            events_path,
            type(exc).__name__,
            exc,
        )
    # Issue #221 — stamp a {"kind": "_meta", "schema_version": "events-v1"}
    # sentinel as the first line of a fresh events.jsonl so downstream
    # parsers can branch on the schema explicitly rather than peek at the
    # 14-kind taxonomy. Only when creating the file (size 0); reconnecting
    # to an existing stream skips this so we never double-stamp.
    if is_fresh:
        try:
            from agent_guardian.server.scan_store import EVENTS_JSONL_SCHEMA_VERSION

            header = {
                "kind": "_meta",
                "schema_version": EVENTS_JSONL_SCHEMA_VERSION,
                "scan_id": getattr(getattr(swarm, "config", None), "scan_id", None),
            }
            with events_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(header) + "\n")
        except (OSError, ImportError) as exc:  # pragma: no cover -- defensive
            _LOG.warning(
                "events_writer: failed to write schema header for %s (%s: %s)",
                events_path,
                type(exc).__name__,
                exc,
            )

    def _observer(event: SwarmEvent) -> None:
        if prior_observer is not None:
            try:
                prior_observer(event)
            except Exception as exc:  # pragma: no cover -- defensive
                _LOG.warning(
                    "events_writer: prior observer raised %s: %s",
                    type(exc).__name__,
                    exc,
                )
        # Phase 2 Step 2.1 — stamp ``seq`` BEFORE serialisation so the
        # on-disk shape matches the server-write path. If the event
        # already has a seq (defensive: e.g. observer chain double-stamp
        # via a future code path), preserve it. Counter is module-level
        # and shared with :class:`JsonlLogHandler` so SwarmEvents and
        # log records interleave with a strictly monotonic seq.
        if event.seq is None:
            event = _dataclasses.replace(event, seq=_next_seq(scan_dir))
        try:
            line = json.dumps(_event_to_jsonable(event), ensure_ascii=False)
        except (TypeError, ValueError) as exc:  # pragma: no cover
            _LOG.warning(
                "events_writer: failed to serialise event kind=%r (%s: %s)",
                str(event.kind),
                type(exc).__name__,
                exc,
            )
            return
        try:
            with events_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:  # pragma: no cover -- defensive
            _LOG.warning(
                "events_writer: append to %s failed (%s: %s)",
                events_path,
                type(exc).__name__,
                exc,
            )

    swarm.observer = _observer
    return _observer


# ---------------------------------------------------------------------------
# Python logging -> events.jsonl bridge (CLI-style running log in the
# Executive Logs tab).
# ---------------------------------------------------------------------------


# Default logger allowlist. Records whose logger name starts with one of
# these prefixes are forwarded to events.jsonl as ``kind="log"`` entries;
# all others are dropped. Keeps the file tractable (~hundreds of lines per
# scan, well under ``_LOGS_TAIL_CAP=1000``) and avoids spam from noisy deps
# like urllib3 / asyncio. ``agent_guardian`` covers all 90 in-package
# loggers (core.swarm, agents.*, llm.*, transports.*, server.*, cli, ...);
# ``httpx`` adds one INFO line per HTTP request.
_DEFAULT_LOG_ALLOWLIST: tuple[str, ...] = ("agent_guardian", "httpx")


class JsonlLogHandler(logging.Handler):
    """``logging.Handler`` that appends records to ``<scan_dir>/events.jsonl``.

    Wire format (matches the locked shape read by
    :func:`agent_guardian.server.dashboard_view._parse_event_line`)::

        {
          "kind":      "log",
          "timestamp": "<ISO-8601 UTC>",
          "agent":     null,
          "asi":       null,
          "provisional_aivss": null,
          "decision":  null,
          "payload": {
            "level":    "INFO|WARNING|ERROR|DEBUG|CRITICAL",
            "logger":   "<record.name>",
            "message":  "<record.getMessage()>",
            "exc_info": "<formatted traceback>"   # optional, omitted if None
          }
        }

    Thread safety: ``emit`` opens the file, appends one JSON line, and
    closes the file under a ``threading.Lock``. Python log calls can land
    on worker threads (httpx, aiohttp, asyncio executors), so a lock-per-
    emit is required. POSIX guarantees that a single ``write()`` of a
    short line is atomic, so the lock is belt-and-braces for short writes
    and strictly necessary for longer multiline tracebacks.

    Circular-logging guard: this handler MUST NOT call any logger itself
    (no ``_LOG.warning(...)``) — that would re-enter ``emit`` and recurse.
    All errors are swallowed silently. Failure to append a single line is
    strictly less bad than crashing the swarm.

    Volume control: pass ``allowlist`` (tuple of logger-name prefixes) to
    filter inbound records. Default is ``("agent_guardian", "httpx")``.
    Records whose ``record.name`` does not start with any prefix are
    dropped before serialization.
    """

    def __init__(
        self,
        scan_dir: Path,
        allowlist: tuple[str, ...] = _DEFAULT_LOG_ALLOWLIST,
    ) -> None:
        super().__init__()
        self._events_path = scan_dir / "events.jsonl"
        self._allowlist = tuple(allowlist)
        self._write_lock = threading.Lock()
        # Best-effort touch so the file exists even if no event fires
        # before the first log record.
        try:
            scan_dir.mkdir(parents=True, exist_ok=True)
            self._events_path.touch(exist_ok=True)
        except OSError as exc:
            # Disk-level failure; the handler itself logs each per-record
            # failure separately, so a noisy WARN here would just duplicate.
            # A debug-level breadcrumb names the cause for forensic replay.
            _LOG.debug(
                "JsonlLogHandler: best-effort touch of %s failed (%s: %s)",
                self._events_path,
                type(exc).__name__,
                exc,
            )

    @property
    def scan_dir(self) -> Path:
        """Return the directory whose ``events.jsonl`` this handler appends to."""
        return self._events_path.parent

    def _allowed(self, name: str) -> bool:
        return any(name == prefix or name.startswith(prefix + ".") for prefix in self._allowlist)

    def emit(self, record: logging.LogRecord) -> None:
        # Allowlist filter first so we never serialise records we'd drop.
        if not self._allowed(record.name):
            return
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover -- defensive
            message = str(record.msg)
        payload: dict[str, object] = {
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        if record.exc_info is not None:
            with contextlib.suppress(Exception):
                payload["exc_info"] = "".join(traceback.format_exception(*record.exc_info))
        # Timestamp from the record (when the log call happened), not from
        # emit() (when we serialise it) — matches SwarmEvent semantics.
        ts = datetime.fromtimestamp(record.created, tz=UTC).isoformat()
        wire: dict[str, object] = {
            "kind": "log",
            "timestamp": ts,
            "agent": None,
            "asi": None,
            "provisional_aivss": None,
            "decision": None,
            "payload": payload,
        }
        # Phase 2 Step 2.1 — stamp ``seq`` so log records share the same
        # per-scan monotonic numbering as SwarmEvents (the counter is
        # module-level + lock-guarded; see ``_next_seq``). Without this
        # the on-disk file would have a mix of ``seq: <int>`` (events)
        # and ``seq: null`` (logs), breaking the resume-by-id contract.
        # Never let seq stamping break a log emit — defensive suppress.
        with contextlib.suppress(Exception):
            wire["seq"] = _next_seq(self._events_path.parent)
        try:
            line = json.dumps(wire, ensure_ascii=False)
        except (TypeError, ValueError):
            return
        with self._write_lock:
            try:
                with self._events_path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                # Silent — we are not allowed to log from a logging
                # handler (recursive emit).
                return


def install_jsonl_log_handler(
    scan_dir: Path,
    allowlist: tuple[str, ...] = _DEFAULT_LOG_ALLOWLIST,
) -> JsonlLogHandler:
    """Attach a :class:`JsonlLogHandler` to the root logger.

    Idempotent: if a :class:`JsonlLogHandler` for the same ``scan_dir`` is
    already attached, the existing instance is returned and no second
    handler is added. Prevents double-writes if the CLI accidentally calls
    this twice (e.g. retry path).

    The handler is attached at level ``DEBUG`` so the per-record allowlist
    + the operator-configured root level decide what actually gets written.

    Returns the handler so the caller can detach it on scan-end via
    ``logging.getLogger().removeHandler(handler)`` if desired (not required
    — leaving it attached until process exit is harmless).
    """
    root = logging.getLogger()
    resolved = scan_dir.resolve()
    for existing in root.handlers:
        if isinstance(existing, JsonlLogHandler) and existing.scan_dir.resolve() == resolved:
            return existing
    handler = JsonlLogHandler(scan_dir, allowlist=allowlist)
    handler.setLevel(0)  # let the logger / root level decide
    root.addHandler(handler)
    return handler
