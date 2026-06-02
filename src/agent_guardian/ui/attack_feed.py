"""QA-005 — per-agent attack transparency feed for the CLI.

This module owns the CLI side of QA-005's "attack transparency" lock.
It defines :class:`AttackFeedRenderer` — the sink we attach to the
:class:`~agent_guardian.core.swarm.SwarmCommander`'s observer chain so
each ``SwarmEvent(kind="reflection")`` materialises as either:

* a Rich :class:`~rich.panel.Panel` printed ABOVE the Live region (the
  default ``--debug`` text mode), or
* a single NDJSON line on stdout (``--debug-format json``).

Both sinks consume the verbatim ``turn_record`` dict the agent loop
emits — so the PII redaction that already runs in
:meth:`agent_guardian.core.memory.SharedMemory.write_reflection`
propagates straight through. There is no second redaction path in this
module — the contract is "trust the memory writer's shape".

Design lock points (QA-005 §3):

* The renderer **composes** with the QA-002 Live region; it never
  creates its own Live. It writes via ``console.print(panel)`` which
  Rich serializes ABOVE the current Live frame as scrollback. That's
  the same code path log lines use, so a panel + a log + a Live update
  cannot tear the Live border.
* Default truncation: prompt / target_response / reasoning > 240 chars
  collapses to ``first 240 chars + "[+N chars, use --debug 2 to expand]"``.
  ``--debug 2`` (or ``debug_level=2`` / ``full=True``) disables truncation.
* Border colour is keyed off the verdict so the CLI's visual semantics
  match what the dashboard renders:

  * ``pass``           → ``verdict.pass`` (green)
  * ``fail``           → ``sev.high`` (red)
  * ``inconclusive``   → ``verdict.inconclusive`` (yellow)
  * otherwise          → ``status.pending`` (dim)

The NDJSON sink writes one line per reflection:

.. code-block:: json

   {"record_type":"reflection","scan_id":"<id>","timestamp":"<iso8601>",
    "payload": <turn_record>}

This shape is a drop-in match for the existing
``memory.jsonl`` line shape, so any ``jq`` pipeline a user already has
keeps working when they swap ``cat memory.jsonl`` for the live stream.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import IO, Any, Literal

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent_guardian.core.swarm import SwarmCommander, SwarmEvent
from agent_guardian.logging_setup import get_console

__all__ = [
    "AttackFeedRenderer",
    "DebugFormat",
    "DebugLevel",
    "build_curl_one_liner",
    "render_reflection_block",
]


# Public type aliases. ``DebugLevel`` is the int counter the CLI flag
# accepts (0 = no feed, 1 = text panels truncated, 2 = text panels
# untruncated). ``DebugFormat`` selects between Rich text and NDJSON.
DebugLevel = Literal[0, 1, 2]
DebugFormat = Literal["text", "json"]


_TRUNCATE_AT = 240
"""Character cap on prompt / target_response / reasoning at debug=1.

Chosen so a typical mobile-width terminal can show the full block plus
the truncation marker without wrapping the marker into a fourth line."""


_VERDICT_STYLE: dict[str, str] = {
    "pass": "verdict.pass",
    "fail": "sev.high",
    "inconclusive": "verdict.inconclusive",
}


@dataclass(frozen=True)
class _Section:
    """One labelled section in a reflection panel — dim header, then body."""

    label: str
    body: str
    style: str = ""


def _maybe_truncate(text: str, *, full: bool) -> str:
    """Truncate ``text`` to :data:`_TRUNCATE_AT` chars unless ``full`` is set.

    Adds the operator-facing marker that names the precise flag needed
    to recover the rest, so the truncation never feels mysterious.
    """
    if full or len(text) <= _TRUNCATE_AT:
        return text
    remainder = len(text) - _TRUNCATE_AT
    head = text[:_TRUNCATE_AT].rstrip()
    return f"{head}\n[+{remainder} chars, use --debug 2 to expand]"


def _verdict_style(verdict: str) -> str:
    """Map a verdict string to a theme token. Unknown verdicts → ``status.pending``."""
    return _VERDICT_STYLE.get(verdict, "status.pending")


def _format_atlas(turn: Mapping[str, Any]) -> str:
    """Render ATLAS techniques as a comma-joined string, ``—`` when missing."""
    techniques = turn.get("mitre_techniques") or []
    if isinstance(techniques, list) and techniques:
        return ", ".join(str(t) for t in techniques)
    return "—"


def _format_strategy(turn: Mapping[str, Any]) -> str:
    """Render the strategy line with rationale tail when present."""
    strategy = str(turn.get("strategy", "—"))
    meta = turn.get("strategy_metadata") or {}
    rationale = ""
    if isinstance(meta, Mapping):
        rationale = str(meta.get("rationale", "")).strip()
    # PhaseC — prefix a "[multi-turn]" badge when the strategy stack is a
    # MultiTurnPlanStrategy. The strategy's ``.name`` is "multi_turn_plan"
    # and its metadata stamps ``phase_c_c1_plan_name``; either signal is
    # sufficient evidence for the badge.
    is_multi_turn = strategy == "multi_turn_plan" or (
        isinstance(meta, Mapping) and bool(meta.get("phase_c_c1_plan_name"))
    )
    prefix = "[multi-turn] " if is_multi_turn else ""
    if rationale:
        return f"{prefix}{strategy} (rationale: {rationale})"
    return f"{prefix}{strategy}"


def _plan_name_for(turn: Mapping[str, Any]) -> str:
    """Resolve the active plan name from turn_record / strategy_metadata."""
    plan = turn.get("plan_name")
    if isinstance(plan, str) and plan.strip():
        return plan.strip()
    meta = turn.get("strategy_metadata")
    if isinstance(meta, Mapping):
        meta_name = meta.get("phase_c_c1_plan_name")
        if isinstance(meta_name, str) and meta_name.strip():
            return meta_name.strip()
    return ""


def _format_attachments(turn: Mapping[str, Any]) -> str:
    """One-line summary of probe attachments riding with this turn.

    Reads the redacted summary list ``attachments`` (mime_type / size_bytes
    / alt_text) — never the b64 payload — so PII/size hygiene is preserved
    and the renderer never decodes binary data. Returns ``"—"`` when none.
    """
    items = turn.get("attachments")
    if not isinstance(items, list) or not items:
        return "—"
    parts: list[str] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        mime = str(item.get("mime_type", "?"))
        alt = str(item.get("alt_text", "")).strip()
        size = item.get("size_bytes")
        size_str = f" {int(size):,}B" if isinstance(size, int) and size > 0 else ""
        if alt:
            parts.append(f"{mime}{size_str} '{alt}'")
        else:
            parts.append(f"{mime}{size_str}")
    if not parts:
        return "—"
    return f"{len(parts)} · " + ", ".join(parts)


def _build_panel_body(turn: Mapping[str, Any], *, full: bool) -> RenderableType:
    """Build the inner renderable for a reflection panel."""
    sections: list[_Section] = []

    sections.append(_Section(label="STRATEGY", body=_format_strategy(turn)))
    sections.append(_Section(label="ATLAS", body=_format_atlas(turn)))
    sections.append(_Section(label="CSA", body=str(turn.get("csa_category", "—"))))

    prompt = str(turn.get("prompt", "")).strip() or "—"
    response = str(turn.get("target_response", "")).strip() or "—"
    reasoning = str(turn.get("reasoning", "")).strip() or "—"

    sections.append(_Section(label="PROMPT", body=_maybe_truncate(prompt, full=full)))
    # PhaseC.C4 — surface probe attachments between PROMPT and TARGET
    # RESPONSE so an operator sees exactly what travelled with the prompt.
    attachments_body = _format_attachments(turn)
    if attachments_body != "—":
        sections.append(_Section(label="ATTACHMENTS", body=attachments_body))
    sections.append(_Section(label="TARGET RESPONSE", body=_maybe_truncate(response, full=full)))

    verdict = str(turn.get("verdict", "—"))
    confidence = turn.get("confidence")
    if isinstance(confidence, (int, float)):
        verdict_line = f"{verdict}  ·  conf {float(confidence):.2f}"
    else:
        verdict_line = verdict
    sections.append(_Section(label="VERDICT", body=verdict_line, style=_verdict_style(verdict)))
    sections.append(_Section(label="REASON", body=_maybe_truncate(reasoning, full=full)))

    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(width=15, no_wrap=True, justify="left")
    grid.add_column(ratio=1, overflow="fold")
    for section in sections:
        grid.add_row(
            Text(section.label, style="status.pending"),
            Text(section.body, style=section.style),
        )
    return grid


def _title_text(turn: Mapping[str, Any]) -> Text:
    """The panel title — cyan agent name then ASI · turn N/M · seed id.

    PhaseC — when the active strategy is a MultiTurnPlanStrategy the
    turn label is widened to ``turn N/M (plan: <plan-name>)`` so the
    operator sees the campaign label alongside the per-turn counter.
    """
    agent = str(turn.get("agent", "agent"))
    asi = str(turn.get("asi_category", "—"))
    turn_n = turn.get("turn")
    max_turns = turn.get("max_turns")
    if isinstance(turn_n, int) and isinstance(max_turns, int):
        turn_label = f"turn {turn_n}/{max_turns}"
    elif isinstance(turn_n, int):
        turn_label = f"turn {turn_n}"
    else:
        turn_label = "turn ?"
    plan_name = _plan_name_for(turn)
    if plan_name:
        turn_label = f"{turn_label} (plan: {plan_name})"
    seed_id = str(turn.get("seed_id", "")).strip()
    seed_label = f"seed {seed_id}" if seed_id else "seed —"
    asi_style = f"asi.{asi}" if asi.startswith("ASI") else "status.pending"
    title = Text()
    title.append(agent, style="status.running")
    title.append("  ·  ")
    title.append(asi, style=asi_style)
    title.append("  ·  ")
    title.append(turn_label, style="status.pending")
    title.append("  ·  ")
    title.append(seed_label, style="status.pending")
    return title


def render_reflection_block(turn: Mapping[str, Any], *, full: bool = False) -> RenderableType:
    """Build the Rich renderable for one reflection.

    Returns a :class:`rich.console.Group` of one :class:`rich.panel.Panel`
    so the caller can ``console.print(...)`` it directly. The verdict
    keys the panel's left border colour — that's the "severity-tied
    bar" QA-005 §3 calls for.
    """
    verdict = str(turn.get("verdict", "—"))
    border = _verdict_style(verdict)
    body = _build_panel_body(turn, full=full)
    panel = Panel(
        body,
        title=_title_text(turn),
        title_align="left",
        border_style=border,
        padding=(0, 1),
    )
    return Group(panel)


def build_curl_one_liner(*, endpoint: str, prompt: str, agent: str | None = None) -> str:
    """Reconstruct a curl invocation that replays the attack against an HTTP target.

    The dashboard's "copy as curl" button calls into an equivalent JS
    helper; we keep the Python side here so tests can assert on the
    exact string the operator would see in their terminal when they
    pipe a reflection through ``jq`` and a tiny helper.

    The body shape mirrors :class:`HttpAdapter`'s contract — POST to
    ``<endpoint>/<agent>/chat`` (or just ``<endpoint>``) with
    ``{"input": "<prompt>"}``.
    """
    # JSON-encode the body so embedded quotes / newlines survive the shell.
    body = json.dumps({"input": prompt}, separators=(",", ":"))
    url = endpoint.rstrip("/")
    if agent and "/chat" not in url:
        url = f"{url}/{agent}/chat"
    # Single-quote the body for bash so JSON's double quotes don't collide;
    # any single quote inside JSON is escaped as '\'' (closing, escaped,
    # reopening) which is the canonical safe-quoting pattern.
    safe_body = body.replace("'", "'\\''")
    return f"curl -sS -X POST {url} -H 'Content-Type: application/json' -d '{safe_body}'"


class AttackFeedRenderer:
    """Sink for ``SwarmEvent(kind="reflection")`` events (QA-005).

    Composes with the QA-002 Live region: panels print through
    ``console.print(...)`` so Rich serialises them ABOVE the Live frame
    as scrollback (same pathway log lines use). Tests assert the
    composition works without trampling.

    Modes:

    * ``DebugFormat="text"`` + ``DebugLevel in {1, 2}`` — render Rich
      panels through the shared :class:`~rich.console.Console`.
      ``level=1`` truncates; ``level=2`` does not.
    * ``DebugFormat="json"`` — write one NDJSON line per reflection to
      the supplied stream (default: :data:`sys.stdout`). No Rich.

    ``level=0`` is a no-op shaped like a renderer so the CLI can wire
    one in unconditionally; nothing renders.
    """

    def __init__(
        self,
        *,
        level: DebugLevel = 1,
        format: DebugFormat = "text",
        console: Console | None = None,
        stream: IO[str] | None = None,
        scan_id: str | None = None,
    ) -> None:
        self.level: DebugLevel = level
        self.format: DebugFormat = format
        self.scan_id = scan_id
        self._console = console if console is not None else get_console()
        self._stream = stream  # ``None`` → resolve at write time so tests can swap stdout.
        # Counter the dashboard cap mirrors. Read only for tests.
        self.rendered_count: int = 0

    # ------------------------------------------------------------------
    # Observer integration
    # ------------------------------------------------------------------

    def attach_to(self, swarm: SwarmCommander) -> None:
        """Wrap the swarm's observer so reflections fan out to this renderer.

        Preserves any prior observer (the QA-002 :class:`ScanTUI`
        observer typically) so the renderer composes rather than
        replaces.
        """
        prior = swarm.observer

        def _wrapped(event: SwarmEvent) -> None:
            if event.kind == "reflection":
                self.handle_event(event)
            if prior is not None:
                with contextlib.suppress(Exception):
                    prior(event)

        swarm.observer = _wrapped

    def handle_event(self, event: SwarmEvent) -> None:
        """Render one reflection event. Silent for ``level=0``."""
        if self.level == 0:
            return
        payload = event.payload
        if not isinstance(payload, Mapping):
            return
        # Stamp the event's agent name onto the payload copy when the
        # turn_record didn't already carry it (recon path uses a
        # slightly different shape).
        turn: dict[str, Any] = dict(payload)
        if "agent" not in turn and event.agent:
            turn["agent"] = event.agent
        self.emit(turn, timestamp=event.timestamp)

    # ------------------------------------------------------------------
    # Sink core — directly testable
    # ------------------------------------------------------------------

    def emit(
        self,
        turn: Mapping[str, Any],
        *,
        timestamp: datetime | None = None,
    ) -> None:
        """Render or stream one reflection turn record.

        Public so tests don't need to forge a SwarmEvent — they call
        this with a dict and assert on the recorded output.
        """
        if self.level == 0:
            return
        if self.format == "json":
            self._emit_json(turn, timestamp=timestamp)
        else:
            self._emit_text(turn)
        self.rendered_count += 1

    def _emit_text(self, turn: Mapping[str, Any]) -> None:
        full = self.level == 2
        renderable = render_reflection_block(turn, full=full)
        # ``console.print`` is the QA-002 lock: when a Live region owns
        # stdout, Rich routes this print above the Live frame.
        self._console.print(renderable)

    def _emit_json(self, turn: Mapping[str, Any], *, timestamp: datetime | None) -> None:
        ts = (timestamp or datetime.now(tz=UTC)).isoformat()
        record = {
            "record_type": "reflection",
            "scan_id": self.scan_id or "",
            "timestamp": ts,
            "payload": dict(turn),
        }
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        # Late-bind the stream so a test that monkeypatches sys.stdout
        # sees the swap. We re-read each call rather than caching.
        stream = self._stream if self._stream is not None else _stdout_sink()
        stream.write(line + "\n")
        with contextlib.suppress(AttributeError, OSError):
            stream.flush()


def _stdout_sink() -> IO[str]:
    """Late-bound default for the JSON stream — resolves at call time.

    Tests monkeypatch ``sys.stdout`` (rather than reaching into the
    renderer) so we look the attribute up each call.
    """
    import sys

    return sys.stdout
