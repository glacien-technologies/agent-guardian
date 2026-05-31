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

import json
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from agent_guardian._version import __version__
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier

if TYPE_CHECKING:
    from agent_guardian.core.swarm import SwarmCommander, SwarmEvent

__all__ = [
    "PARTIAL_SCAN_FILENAME",
    "build_partial_scan",
    "is_terminal_scan_on_disk",
    "make_partial_writer",
    "partial_scan_path",
    "read_partial_scan",
    "write_partial_scan",
]

_LOG = logging.getLogger(__name__)


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

    # Per-ASI score: 100 minus a coarse penalty per finding category, clamped
    # to [0, 100]. This mirrors the direction of compute_aivss without
    # depending on it -- the final score lands when the swarm's finalise
    # phase writes scan.raw.json. Categories with no findings yet stay at
    # 100, which the view-model interprets as "covered, clean so far".
    per_asi_findings: dict[AsiCategory, int] = {cat: 0 for cat in AsiCategory}
    for finding in findings:
        per_asi_findings[finding.asi] = per_asi_findings.get(finding.asi, 0) + 1
    asi_scores: dict[AsiCategory, float] = {}
    for cat, count in per_asi_findings.items():
        # Only surface a score for categories whose agent has actually run --
        # the dashboard's _asi_rows() then renders the others as "queued"
        # rather than fabricating coverage we don't yet have.
        if any(r.asi_category is cat for r in swarm._agent_reports if r.asi_category is not None):
            asi_scores[cat] = max(0.0, 100.0 - 20.0 * count)

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
        created_at=datetime.now(tz=timezone.utc),
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
    return {
        "kind": str(event.kind),
        "timestamp": event.timestamp.isoformat(),
        "agent": event.agent,
        "asi": asi_val,
        "provisional_aivss": event.provisional_aivss,
        "decision": decision_val,
        "payload": safe_payload,
    }


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
    prior_observer = swarm.observer
    events_path = scan_dir / "events.jsonl"
    # Touch the file so the dashboard sees an empty (but present) log even
    # on the very first event-less moment of a scan. Open mode is "a" so
    # parallel writes from a paused-and-resumed scan append rather than
    # truncate.
    try:
        events_path.touch(exist_ok=True)
    except OSError as exc:  # pragma: no cover -- defensive
        _LOG.warning(
            "events_writer: failed to touch %s (%s: %s)",
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
