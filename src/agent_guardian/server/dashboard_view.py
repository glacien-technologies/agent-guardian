"""View-model builder for the live scan dashboard (QA-003).

The Jinja templates under ``server/templates/dashboard/`` are intentionally
data-driven — they render whatever shape this module produces. Keeping the
view-model assembly out of the route handler means:

* The route stays a thin Starlette wrapper.
* The view-model is unit-testable in isolation (no FastAPI / TestClient needed
  for the snapshot golden tests).
* The same builder feeds the SSE ``/scans/<id>/live`` stream, so the live
  ``data-live=*`` updates always agree with the initial HTML render.

The builder works for both completed scans (``Scan`` instance) and in-flight
scans (``Scan = None``, ``is_running=True``) — every field gracefully degrades
to a placeholder when the data isn't ready yet.

Dashboard theme (QA-041)
------------------------

The dashboard ships a single theme — Executive — rendered from
``dashboard/executive/layout.html``. The earlier multi-theme switcher
(editorial / mission / narrative / executive) was retired in QA-041; the
non-Executive theme stylesheets, templates, and tests were deleted, and
the ``?theme=`` query param + ``$AGENT_GUARDIAN_DASHBOARD_THEME`` env var
are no longer honoured. Any incoming ``?theme=<anything>`` query param is
silently ignored — the response is always the Executive layout — so any
stale operator bookmark still resolves to a valid dashboard page rather
than 404-ing.
"""

from __future__ import annotations

import json
import logging
import math
import re
import time
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from agent_guardian.core.coverage import NOT_TESTED_EVENTS
from agent_guardian.core.run_aggregator import aggregate_run_verdicts
from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.finding import Finding
from agent_guardian.models.judge import normalize_verdict
from agent_guardian.models.run_result import AsiRunResult
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, SeverityBand

_LOG = logging.getLogger(__name__)

# Humanised labels for the Executive BAND tile (and any other surface that
# displays scan.band as visible text). The raw enum value (``not_evaluated``,
# ``EXCELLENT``, …) is an internal token — feedback-no-raw-enum-in-ui requires
# we never leak it verbatim to the operator. The mapping is intentionally
# verbose enough to stand on its own without an accompanying score number
# (the AIVSS hero already carries the number). The NOT_EVALUATED fallback
# uses the short ``NA`` short-code (QA-034) so the BAND tile fits one line
# in the ~9rem KPI column; the longer "didn't reach 95% coverage; raw AIVSS
# preserved for trend tracking" prose belongs in the tile's ⓘ tooltip
# (QA-028 sub-ask 1) — never in the label itself.
#
# QA-G6 (2026-06-03) — the CLI scan-end summary uses ``models.severity.
# humanise_band`` directly. Both surfaces ultimately share
# :class:`SeverityBand` as the single source of truth; the tile uses the
# shorter form below because the BAND KPI column is layout-constrained,
# the CLI uses the verbose ``Not Evaluated (stub mode)`` form because a
# terminal line has plenty of room. Any future band added to the enum
# must be added to BOTH maps simultaneously.
_BAND_LABELS: Final[Mapping[SeverityBand, str]] = {
    SeverityBand.EXCELLENT: "Excellent",
    SeverityBand.GOOD: "Good",
    SeverityBand.WARNING: "Warning",
    SeverityBand.POOR: "Poor",
    SeverityBand.CRITICAL: "Critical",
    SeverityBand.NOT_EVALUATED: "NA",
}


def _humanise_band(band: SeverityBand | None) -> str:
    """Return a humanised, user-facing label for an AIVSS band (dashboard tile).

    Uses the short ``NA`` short-code for :attr:`SeverityBand.NOT_EVALUATED` so
    the BAND KPI tile fits one line in the layout-constrained column. The CLI
    scan-end summary uses ``agent_guardian.models.severity.humanise_band``
    instead, which renders the verbose ``Not Evaluated (stub mode)`` form
    appropriate for a terminal line.

    Falls back to a title-cased best-effort rendering if a future band slips
    past the mapping — never returns the raw underscore-bearing enum value
    (see ``feedback_no_raw_enum_in_ui``).
    """
    if band is None:
        return "Pending"
    label = _BAND_LABELS.get(band)
    if label is not None:
        return label
    # Defensive fallback — strip underscores, title-case. The mapping above
    # covers every member of :class:`SeverityBand` so we should never hit
    # this branch in practice; it exists so a future enum addition can't
    # regress the "no raw enum text" guarantee.
    return band.value.replace("_", " ").title()


# Caps on the assembled lists. The probes_list is bounded so a long-running
# scan doesn't blow the page render time; the logs_tail is FIFO-trimmed so
# the operator always sees the most recent events. Both values are locked in
# the design doc (DESIGN_LOCK §3.3).
_PROBES_LIST_CAP: Final[int] = 500
# ``_LOGS_TAIL_CAP`` was 1000 until 2026-06-01 when the operator asked the
# Logs tab to surface every event regardless of count. Cap removed — the
# Executive Logs tab now renders every line from ``events.jsonl``. Browser
# memory is the only limit; the client-side filter toolbar (level chips +
# search) is the operator's primary tool for navigating large logs.
_LOGS_TAIL_CAP: Final[int | None] = None  # pyright: ignore[reportUnusedVariable]  # Consumed by test_dashboard_view_module_caps_are_locked — see DESIGN_LOCK §3.3

__all__ = [
    "DASHBOARD_TEMPLATE",
    "DashboardContext",
    "build_dashboard_context",
    "build_finding_slideover_ctx",
    "build_probe_group_slideover_ctx",
    "build_probe_slideover_ctx",
    "resolve_locality",
]


# Single Jinja template for the dashboard (QA-041 — theme switcher retired).
# Routes import this constant; never hard-code the path.
DASHBOARD_TEMPLATE: Final[str] = "dashboard/executive/layout.html"


# ASI row metadata — subtitle + weight (matches the saved design).
_ASI_ROW_META: dict[str, tuple[str, str, float, bool]] = {
    # code  : (title,                subtitle,                         weight, weight_high)
    "ASI01": ("Goal hijack", "Direct · indirect · multi-turn", 2.0, True),
    "ASI02": ("Tool misuse", "Scope · chaining · smuggling", 1.5, False),
    "ASI03": ("Privilege abuse", "JIT bypass · role inheritance", 1.5, False),
    "ASI04": ("Supply chain", "MCP poison · registry spoof", 1.0, False),
    "ASI05": ("Code execution", "Sandbox escape · eval smuggle", 1.5, False),
    "ASI06": ("Memory poisoning", "RAG triggers · cross-session", 2.0, True),
    "ASI07": ("Agent-to-agent", "Bus spoof · confused deputy", 1.0, False),
    "ASI08": ("Cascading failure", "Retry storm · blast radius", 1.0, False),
    "ASI09": ("Trust exploit", "Manufactured authority · citations", 1.0, False),
    "ASI10": ("Behavioural drift", "Long horizon · sandbagging", 1.0, False),
}


# QA-060 (2026-06-03) — friendly skip-reason strings keyed off the agent
# class name (matches :attr:`AsiAgent.name`). The swarm currently writes
# the generic ``"not applicable for fingerprint"`` for every gating
# predicate that fires in :meth:`AsiAgent.is_applicable`; operators reading
# the Recon panel's "Skipped agents" table need to know WHICH capability
# gap rejected the agent so they can either add the capability declaration
# (for a real target) or accept the skip as intentional. The map below
# encodes the predicate each known agent applies, in plain language. Any
# agent absent from the map (e.g. a future specialist) falls back to the
# original generic reason — no silent rewriting of unknown predicates.
_SKIP_REASON_BY_AGENT: dict[str, str] = {
    "memory-poison-agent": "target does not declare memory capability",
    "a2a-agent": "target is single-agent (no orchestrator surface)",
    "code-exec-agent": "target does not declare code-execution tools",
    "tool-abuse-agent": "target does not declare any tools",
}
# The placeholder we override when present. Reasons that don't match this
# token pass through unchanged — preserves any future custom reason a
# specialist agent might write.
_GENERIC_SKIP_REASON: Final[str] = "not applicable for fingerprint"


@dataclass(frozen=True)
class DashboardContext:
    """Resolved template context for ``dashboard/scan_detail.html``.

    Captured as a frozen dataclass so the route handler can pass the result
    straight to ``TemplateResponse(context=ctx.to_dict())`` and tests can
    introspect the fields without parsing HTML.
    """

    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def resolve_locality(base_url: str) -> tuple[bool, str, str, str, str]:
    """Resolve the locality pill state from the dashboard base URL.

    Returns ``(is_local, label, scheme, host_display, port_display)``.

    ``is_local`` is true iff the host is a loopback alias (``127.0.0.1``,
    ``localhost``, ``::1``) — matches the same check the ``serve`` command
    uses to decide whether to require an auth token.
    """
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    scheme = parsed.scheme or "http"
    port = parsed.port
    loopback = {"127.0.0.1", "localhost", "::1"}
    is_local = host in loopback
    label = "Local" if is_local else "Hosted · evidence-signed"
    port_display = f":{port}" if port is not None else ""
    return is_local, label, f"{scheme}:", host, port_display


def _fmt_pct(value: float) -> float:
    """Clamp a percentage value to [0, 100] and round to 1 decimal place."""
    return max(0.0, min(100.0, round(value, 1)))


def _aivss_to_needle(score: int | None) -> float | None:
    """Map an AIVSS score to a horizontal needle position on the band axis.

    The band-axis bar is segmented at 40% / 60% / 80% / 90% / 100%, so a
    linear ``score`` placement matches the visual.
    """
    if score is None:
        return None
    return _fmt_pct(float(score))


def _band_class(band: SeverityBand | None) -> str:
    if band is None:
        return "unknown"
    return band.value.lower()


def _humanise_seconds(seconds: float) -> str:
    """Render seconds as ``MM:SS`` for the elapsed clock."""
    if seconds < 0:
        seconds = 0.0
    total = round(seconds)
    minutes, secs = divmod(total, 60)
    return f"{minutes:02d}:{secs:02d}"


def _count_findings_by_asi(scan: Scan | None) -> dict[str, dict[str, int]]:
    """Return ``{asi_code: {critical, high, medium, low}}`` for the scan."""
    out: dict[str, dict[str, int]] = {
        c.value: {"critical": 0, "high": 0, "medium": 0, "low": 0} for c in AsiCategory
    }
    if scan is None:
        return out
    for f in scan.findings:
        bucket = out[f.asi.value]
        if f.severity is Severity.CRITICAL:
            bucket["critical"] += 1
        elif f.severity is Severity.HIGH:
            bucket["high"] += 1
        elif f.severity is Severity.MEDIUM:
            bucket["medium"] += 1
        elif f.severity is Severity.LOW:
            bucket["low"] += 1
    return out


def _build_kpi_hover_tables(
    *,
    counts: dict[str, int],
    findings_total: int,
) -> dict[str, list[dict[str, str]]]:
    """Build the FINDINGS-tile hover data-table payload.

    QA-044 (2026-06-02) introduced a per-tile hover data table on every
    KPI tile.

    QA-062 (2026-06-03) dropped the hover popover for every tile EXCEPT
    FINDINGS: the other tiles either restated the value already on the
    tile (AIVSS / BAND) or showed a fabricated 15/55/30 phase split
    (ELAPSED / COST) we never had real data for. Keeping only FINDINGS
    leaves the one tile where the breakdown is the actual signal — the
    per-severity count operators are reading to triage.

    Each row is a plain dict ``{"label": str, "value": str}`` (no
    ``class`` is needed today; the field is reserved for future
    severity-tinted rows).
    """
    findings_rows: list[dict[str, str]] = [
        {"label": "Critical", "value": str(counts.get("critical", 0))},
        {"label": "High", "value": str(counts.get("high", 0))},
        {"label": "Medium", "value": str(counts.get("medium", 0))},
        {"label": "Low", "value": str(counts.get("low", 0))},
        {"label": "Total", "value": str(findings_total)},
    ]
    return {"findings": findings_rows}


def _asi_rows(
    scan: Scan | None, findings_by_asi: dict[str, dict[str, int]]
) -> list[dict[str, Any]]:
    """Build the ten ASI breakdown rows."""
    rows: list[dict[str, Any]] = []
    asi_scores: dict[AsiCategory, float] = scan.asi_scores if scan is not None else {}
    for code, (title, subtitle, weight, weight_high) in _ASI_ROW_META.items():
        asi_enum = AsiCategory(code)
        score_raw = asi_scores.get(asi_enum)
        is_pending = score_raw is None
        score_val = float(score_raw) if score_raw is not None else 0.0
        findings = findings_by_asi.get(code, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        is_attention = (score_val < 70.0 and not is_pending) or findings["critical"] > 0
        status_label, status_class = _status_for_row(scan, is_pending)
        rows.append(
            {
                "code": code,
                "name": title,
                "subtitle": subtitle,
                "score_pct": _fmt_pct(score_val if not is_pending else 12.0),
                "score_label": f"{round(score_val)}",
                "is_pending": is_pending,
                "is_attention": is_attention,
                "weight_label": f"{weight:.1f}",
                "weight_high": weight_high,
                "findings": findings,
                "status_label": status_label,
                "status_class": status_class,
            }
        )
    return rows


def _status_for_row(scan: Scan | None, is_pending: bool) -> tuple[str, str]:
    """Return ``(label, class)`` for an ASI row's status pill."""
    if scan is not None and not is_pending:
        return ("complete", "done")
    # Partial snapshot: a category we haven't seen an asi_scores entry for is
    # queued, not "running" -- the dashboard subprocess sees only what the
    # last partial scan persisted. "queued" reads as "the swarm hasn't gotten
    # to this one yet" rather than the misleading "this one is in flight".
    if is_pending and scan is not None:
        return ("queued", "queued")
    if is_pending and scan is None:
        return ("running", "running")
    return ("running", "running")


def _findings_page(
    scan: Scan | None,
    *,
    page: int,
    per_page: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return ``(page_items, pagination_meta)`` for the findings feed.

    Findings are sorted severity DESC (critical → high → medium → low) then
    ASI ASC (ASI01 → ASI02 → …) so the QA-048 unified Findings table reads
    top-down by criticality with stable ASI grouping inside each band.
    """
    if scan is None:
        empty_pagination: dict[str, Any] = {
            "total": 0,
            "current": 1,
            "total_pages": 1,
            "start": 0,
            "end": 0,
            "pages": [],
        }
        return [], empty_pagination
    sev_rank = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    # QA-048 tie-breaker — sort by ``asi_code`` ASC inside a severity band so
    # the unified findings table groups rows of the same ASI together for
    # quick scanning. ``created_at`` falls in last as a final stable key.
    sorted_findings = sorted(
        scan.findings,
        key=lambda f: (sev_rank[f.severity], f.asi.value, f.created_at),
    )
    total = len(sorted_findings)
    page = max(1, page)
    per_page = max(1, min(per_page, 100))
    total_pages = max(1, math.ceil(total / per_page))
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = min(start + per_page, total)
    items: list[dict[str, Any]] = []
    for f in sorted_findings[start:end]:
        items.append(
            {
                "id": f.id,
                "asi_code": f.asi.value,
                "atlas": [t for t in f.mitre_atlas],
                "csa_code": f.csa_category.value,
                "probe_id": f.probe_id,
                "summary": f.summary,
                "severity_label": f.severity.value.upper(),
                "severity_class": f.severity.value.lower(),
                "created_label": f.created_at.strftime("%H:%M:%S"),
                # QA-051 — runtime agent name (e.g. ``goal-hijack-agent``)
                # populated in-place by ``_attach_evidence_to_findings`` from
                # the matched probe's ``agent`` field. Defaults to ``""`` so
                # the Findings table can render an em-dash when no probe
                # correlation exists (static / recon-derived findings).
                "agent_name": "",
            }
        )
    pagination: dict[str, Any] = {
        "total": total,
        "current": page,
        "total_pages": total_pages,
        "start": start + 1 if total > 0 else 0,
        "end": end,
        "pages": list(range(1, total_pages + 1)),
    }
    return items, pagination


# Per-finding evidence cap. Noisy attacks (10+ turns on a single probe_id) would
# otherwise blow the Findings card vertical rhythm — the operator can still
# drill into every turn from the Probes tab. We cap at 10 evidence rows per
# finding and surface ``evidence_truncated`` so the template can say
# "10 of N evidence event(s) shown".
_FINDING_EVIDENCE_CAP: Final[int] = 10

# Judge v2 (M0) — the verdicts that created a Finding (used to pick the
# representative turn). Legacy "fail" normalizes into ``exploited``.
_FINDING_VERDICT_SET: frozenset[str] = frozenset({"exploited", "vulnerable"})


# Judge v2 (M5 / Stage D) — the six-verdict taxonomy → operator-facing label.
# Keyed by the CANONICAL v2 value; legacy ``pass`` / ``fail`` / ``inconclusive``
# normalize through :func:`normalize_verdict` before lookup so there is one map,
# not two. ``feedback_no_raw_enum_in_ui`` — the operator never sees the raw enum.
_VERDICT_LABELS: Final[dict[str, str]] = {
    "exploited": "EXPLOITED",
    "vulnerable": "VULNERABLE",
    "needs_followup": "NEEDS FOLLOW-UP",
    "defended": "DEFENDED",
    "simulated_or_unverified": "UNVERIFIED",
}


def _verdict_label(verdict: str) -> str:
    """Map an internal verdict enum value to its operator-facing label.

    Honours ``feedback_no_raw_enum_in_ui`` — the table never shows
    ``fail`` / ``pass`` / ``inconclusive`` verbatim; the operator sees a clean
    label from the six-verdict taxonomy (``EXPLOITED`` / ``INFO LEAK`` /
    ``VULNERABLE`` / ``NEEDS FOLLOW-UP`` / ``DEFENDED`` / ``UNVERIFIED``).

    Judge v2 (M5 / Stage D) — legacy ``pass`` / ``fail`` / ``inconclusive``
    normalize through :func:`normalize_verdict` onto the v2 taxonomy first, so
    both old and new records resolve through the SAME label map. An empty /
    blank verdict (an un-graded live turn) renders ``PENDING``.
    """
    v = (verdict or "").strip().lower()
    if not v:
        return "PENDING"
    return _VERDICT_LABELS.get(normalize_verdict(v), "PENDING")


def _confidence_pct(value: Any) -> str:
    """Format a 0.0-1.0 confidence score as a ``73%`` string for child rows.

    Returns an empty string when the value is missing or unparseable so the
    template can render an em-dash via its standard fallback.
    """
    try:
        pct = float(value)
    except (TypeError, ValueError):
        return ""
    if pct <= 0.0:
        return ""
    return f"{round(pct * 100)}%"


def _attach_evidence_to_findings(
    findings_items: list[dict[str, Any]],
    probes_list: list[dict[str, Any]],
) -> None:
    """Mutate ``findings_items`` in place to add an ``evidence`` field per row.

    Correlation rule:

    1. Primary — match on ``probe_id``. A reflection record's ``probe_id``
       (derived from ``turn.seed_id``) equals the Finding's ``probe_id`` when
       both came from the same attack thread. This is the strongest signal
       and covers the common case where a finding rolls up its attempt_count
       turns.
    2. Fallback — when the finding has NO ``probe_id`` (e.g. static-analysis
       or recon-derived) or when no probe-attempt record matches by id, fall
       back to ``agent + asi_category`` (broader). This keeps the panel
       useful for findings that pre-date the seed_id wiring without
       polluting probe-id-matched findings with unrelated attempts.

    Each evidence row mirrors the probes_list record shape verbatim (the
    template can reuse the same Jinja access pattern as the Probes tab).
    Capped at :data:`_FINDING_EVIDENCE_CAP`; ``evidence_truncated`` /
    ``evidence_total`` are added when the unfiltered match-set was larger.
    Also attaches ``evidence_stats``: a dict counting verdicts in the
    capped slice (``fail`` / ``pass`` / ``inconclusive`` / ``unknown``)
    so the outer drawer summary can render "N events · X exploited ·
    Y defended · Z inconclusive" without re-iterating in Jinja.
    """
    if not findings_items or not probes_list:
        for item in findings_items:
            item.setdefault("evidence", [])
            item.setdefault("evidence_truncated", False)
            item.setdefault("evidence_total", 0)
            item.setdefault(
                "evidence_stats",
                {"fail": 0, "pass": 0, "inconclusive": 0, "unknown": 0},
            )
            # QA-051 — keep ``agent_name`` present (empty default from
            # ``_findings_page``) so callers / templates can rely on the
            # key existing even when no probes correlate.
            item.setdefault("agent_name", "")
        return
    # Pre-index probes_list by probe_id and by (agent, asi_category) so each
    # finding is O(1) lookup instead of an O(P) scan. probes_list is already
    # capped at _PROBES_LIST_CAP (500), so the index is small.
    by_probe_id: dict[str, list[dict[str, Any]]] = {}
    by_agent_asi: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for p in probes_list:
        pid = str(p.get("probe_id") or "")
        if pid:
            by_probe_id.setdefault(pid, []).append(p)
        key = (str(p.get("agent") or ""), str(p.get("asi_category") or ""))
        if key != ("", ""):
            by_agent_asi.setdefault(key, []).append(p)
    for item in findings_items:
        fid_probe = str(item.get("probe_id") or "")
        matched: list[dict[str, Any]] = []
        if fid_probe and fid_probe in by_probe_id:
            matched = by_probe_id[fid_probe]
        if not matched:
            # Fallback: agent + asi_category. The finding row doesn't carry
            # an ``agent`` field today, so this is keyed off asi_code alone
            # for now (we accept the broader match — the worst case is the
            # operator sees turn evidence from the right ASI bucket).
            asi = str(item.get("asi_code") or "")
            if asi:
                for key, records in by_agent_asi.items():
                    if key[1] == asi:
                        matched.extend(records)
        total = len(matched)
        capped = matched[:_FINDING_EVIDENCE_CAP]
        # Count verdicts in the capped slice. The badge text the template
        # renders reads the SAME enum keys ("fail" / "pass" / "inconclusive"),
        # so the counts and the colours can never disagree. Judge v2 (M0) — fold
        # the six v2 verdicts into those three colour buckets so legacy AND new
        # records tally consistently (exploited/info_leak->fail,
        # defended->pass, the ambiguous middle grounds->inconclusive).
        stats = {"fail": 0, "pass": 0, "inconclusive": 0, "unknown": 0}
        for p in capped:
            raw = str(p.get("verdict") or "")
            if not raw:
                stats["unknown"] += 1
                continue
            norm = normalize_verdict(raw)
            if norm == "exploited":
                stats["fail"] += 1
            elif norm == "defended":
                stats["pass"] += 1
            else:
                stats["inconclusive"] += 1
        item["evidence"] = capped
        item["evidence_total"] = total
        item["evidence_truncated"] = total > _FINDING_EVIDENCE_CAP
        item["evidence_stats"] = stats
        # QA-051 — surface the runtime agent name (e.g. ``goal-hijack-agent``)
        # on the finding row. The reflection records written by
        # ``agents/base.py`` carry an ``agent`` field that names the actual
        # specialist agent that produced the probe attempt; we pick the
        # first matched record's name so the Findings table's AGENT column
        # shows the agent the operator can grep for in logs. Findings with
        # no correlated probes keep the default empty string from
        # ``_findings_page`` (template renders an em-dash).
        if capped and not item.get("agent_name"):
            first_agent = str(capped[0].get("agent") or "").strip()
            if first_agent:
                item["agent_name"] = first_agent


def _sort_turns_in_order(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return ``records`` ordered by their ``turn`` index (stable).

    ``_assemble_probes_list`` reads ``memory.jsonl`` in file order; for a
    multi-turn attack thread the rows usually land in turn order, but that
    is not guaranteed once the ``agent + asi_category`` fallback pulls in
    records from interleaved threads. Sorting by ``turn`` here is what lets
    the chat conversation (and the representative-turn pick below) line up
    the right prompt with the right response with the right verdict.
    """
    return sorted(records, key=lambda r: int(r.get("turn", 0) or 0))


def _representative_turn(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the single turn whose prompt/response/verdict/reasoning best
    describe the exchange surfaced in the slide-over's top-level fields.

    The historical bug (operator: "the displayed values don't look correct")
    was that the top-level prompt/response came from ``capped[0]`` — the
    first record in file order, almost always turn 1 — while the top-level
    verdict was rolled up from the *finding* (``EXPLOITED`` for a successful
    multi-turn attack). On a multi-turn thread turn 1 is usually a defended
    (``pass``) exchange, so the operator saw the turn-1 prompt + turn-1
    response under an ``EXPLOITED`` verdict with turn-1's (defended)
    reasoning: three fields describing two different exchanges.

    The fix: surface the turn that actually flipped the attack — the first
    ``fail`` turn if any, else the last turn — so the prompt, the response,
    the verdict, AND the reasoning all describe the same exchange.
    """
    if not records:
        return {}
    ordered = _sort_turns_in_order(records)
    # Judge v2 (M0) — surface the strongest finding-creating turn (exploited /
    # info_leak / vulnerable); legacy "fail" normalizes to "exploited".
    for rec in ordered:
        if normalize_verdict(str(rec.get("verdict") or "")) in _FINDING_VERDICT_SET:
            return rec
    return ordered[-1]


def _conversation_turns(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build the per-turn chat-conversation rows for the slide-over.

    One entry per correlated turn record, in turn order. Each entry carries
    the verbatim attacker ``prompt`` and ``target_response`` (rendered as
    outgoing / incoming chat bubbles) plus that turn's own judge verdict,
    confidence, and reasoning — so every turn's verdict matches its own
    exchange rather than the rolled-up finding verdict.
    """
    out: list[dict[str, Any]] = []
    # 1-based position in the ordered thread. Recon turns all carry turn=0
    # (each probe is an iteration, not an attack turn), so the template numbers
    # them by ``iteration`` instead of repeating "turn 0".
    for idx, rec in enumerate(_sort_turns_in_order(records), start=1):
        raw_verdict = str(rec.get("verdict") or "")
        # Normalize the value onto the current taxonomy so the per-turn pill's
        # CSS class (exec-verdict-pill--<verdict>) is correct even for OLDER
        # scans whose saved verdicts use the pre-2026-06 vocabulary.
        verdict = normalize_verdict(raw_verdict) if raw_verdict else ""
        out.append(
            {
                "iteration": idx,
                "turn_no": int(rec.get("turn", 0) or 0),
                "max_turns": int(rec.get("max_turns", 0) or 0),
                "agent": str(rec.get("agent") or ""),
                "prompt": str(rec.get("prompt") or ""),
                "target_response": str(rec.get("target_response") or ""),
                "verdict": verdict or "unknown",
                "verdict_label": _verdict_label(raw_verdict),
                "confidence_pct": _confidence_pct(rec.get("confidence")),
                "reasoning": str(rec.get("reasoning") or ""),
                # Judge v2 (M5 / Stage D) — per-turn signals for the slide-over
                # chat thread. ``verify`` flips the turn header to a
                # "VERIFICATION PROBE" badge (the judge's drill-down turn vs an
                # attack turn); ``evaluator_attack`` shows a "⚠ evaluator-attack"
                # marker (attacker tried to manipulate the judge — not a target
                # exploit); ``evidence`` is the verbatim span the judge quoted as
                # proof. All default falsy / empty so legacy turns render with no
                # extra chrome.
                "verify": bool(rec.get("verify", False)),
                "evaluator_attack": bool(rec.get("evaluator_attack", False)),
                "evidence": str(rec.get("evidence") or ""),
            }
        )
    return out


def build_finding_slideover_ctx(
    finding: Finding,
    *,
    scan_dir: Path | None,
) -> dict[str, Any]:
    """Build the uniform ``ctx`` dict for the shared ``_slideover.html`` template.

    QA-049 / QA-055 — one polymorphic loader: the Finding-mode endpoint
    marshals the :class:`Finding` model + any correlated probe attempts
    from ``memory.jsonl`` into the SAME ctx shape the probe-mode
    endpoint uses, so the shared template renders the same audit
    detail (prompt + response + judge reasoning + per-turn chat
    conversation + reproduce-CLI) for both row sources.

    Correlation rule mirrors :func:`_attach_evidence_to_findings`:
    primary match on ``probe_id``; fallback on ``agent + asi_category``
    (broader). The correlated attempts are sorted into turn order; the
    *representative* turn (:func:`_representative_turn` — the turn that
    flipped the attack) fills the verbatim prompt / target_response /
    verdict / reasoning fields so those four values describe the SAME
    exchange. The full ordered set surfaces as the per-turn chat
    conversation.

    Genuinely-missing data renders as ``(no data available)`` in the
    template — a finding with no correlated probe attempts gets a
    placeholder for those fields.
    """
    probes = _assemble_probes_list(scan_dir)
    matched: list[dict[str, Any]] = []
    if finding.probe_id:
        for p in probes:
            if str(p.get("probe_id") or "") == finding.probe_id:
                matched.append(p)
    if not matched:
        asi_value = finding.asi.value
        for p in probes:
            if str(p.get("asi_category") or "") == asi_value:
                matched.append(p)
    capped = _sort_turns_in_order(matched)[:_FINDING_EVIDENCE_CAP]

    # The representative turn anchors the top-level prompt / response /
    # verdict / reasoning so all four describe the same exchange (the
    # exchange that flipped the attack on a successful finding). This is
    # the field-correctness fix for the operator's "values don't look
    # correct" report.
    rep = _representative_turn(capped)

    conversation = _conversation_turns(capped)

    # Roll up the finding-level verdict: a finding that succeeded
    # (``success=True``) is the "EXPLOITED" verdict regardless of which
    # specific turn flipped it; otherwise mirror the representative turn's
    # verdict so the header pill and the surfaced reasoning agree.
    if finding.success:
        # Judge v2 (M0) — prefer the finding's own v2 verdict when present so
        # an info_leak success header reads "INFO LEAK", not a generic
        # EXPLOITED; fall back to "exploited" for legacy findings.
        verdict = finding.verdict_v2 or "exploited"
    elif capped and all(normalize_verdict(str(c.get("verdict"))) == "defended" for c in capped):
        verdict = "defended"
    elif rep:
        verdict = normalize_verdict(str(rep.get("verdict") or "needs_followup"))
    else:
        verdict = "needs_followup"

    # Judge v2 (M5 / Stage D) — strongest-evidence run-result for the finding
    # drawer, derived from the correlated probe attempts.
    run_result = _run_result_view(capped)

    return {
        "run_result": run_result,
        "record_id": finding.id,
        "probe_id": finding.probe_id,
        "agent": str(rep.get("agent") or ""),
        "asi_category": finding.asi.value,
        "csa_category": finding.csa_category.value,
        "mitre_atlas": [t for t in finding.mitre_atlas],
        "severity": finding.severity.value,
        "severity_label": finding.severity.value.upper(),
        "severity_class": finding.severity.value.lower(),
        "tier_floor": "",
        "owasp_scenario": "",
        "source_yaml": "",
        "source_path": "",
        "turn": rep.get("turn") if rep else None,
        "timestamp_label": str(rep.get("timestamp_label") or "")
        or finding.created_at.strftime("%H:%M:%S"),
        "seed": "",
        "rng_seed": "",
        "strategy": str(rep.get("strategy") or ""),
        "mutator_operators": [],
        "attacker_refused": bool(rep.get("attacker_refused") or False),
        "prompt": str(rep.get("prompt") or finding.trigger_prompt or ""),
        "target_response": str(rep.get("target_response") or ""),
        "verdict": verdict,
        # Confidence comes from the representative turn's own judge call so
        # it matches the surfaced reasoning; the finding-level confidence is
        # an aggregate and could disagree with the shown exchange.
        "confidence": rep.get("confidence") if rep else finding.confidence,
        "panel_votes": [],
        "reasoning": str(rep.get("reasoning") or ""),
        # Judge v2 (M5 / Stage D) — verbatim judge evidence + evaluator-attack
        # marker for the single-turn (flat) layout. Sourced from the
        # representative turn so the surfaced evidence matches the shown verdict.
        "evidence": str(rep.get("evidence") or ""),
        "evaluator_attack": bool(rep.get("evaluator_attack", False)),
        "verify": bool(rep.get("verify", False)),
        # Chat conversation is only meaningful when there's more than one
        # turn; a single-turn finding uses the flat prompt/response layout.
        "conversation": conversation if len(conversation) > 1 else [],
        "summary": finding.summary,
    }


def build_probe_slideover_ctx(
    probe: dict[str, Any],
    *,
    probes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Adapt a ``_assemble_probes_list`` row into the shared ctx shape.

    The probes_list row already carries the locked Executive-tab fields;
    this rename layer is mostly a pure remap so the shared
    ``_slideover.html`` template can address the same keys for both kinds.

    When ``probes`` (the full assembled list) is supplied, sibling turn
    records sharing the clicked probe's ``probe_id`` are correlated into a
    per-turn chat conversation — so a multi-turn probe opens with the same
    conversation view as a multi-turn finding. The representative-turn rule
    keeps the top-level prompt / response / verdict / reasoning describing a
    single exchange.
    """
    pid = str(probe.get("probe_id") or "")
    siblings: list[dict[str, Any]] = []
    if probes and pid:
        siblings = [p for p in probes if str(p.get("probe_id") or "") == pid]
    # Always include the clicked record so a probe with no siblings still
    # has a well-defined representative turn.
    if not siblings:
        siblings = [probe]
    ordered = _sort_turns_in_order(siblings)
    conversation = _conversation_turns(ordered)
    # The clicked row is itself one turn of the thread; surface its own
    # prompt/response/verdict/reasoning verbatim (the operator clicked THAT
    # row), and keep the conversation as the multi-turn context.
    rep = probe

    # Judge v2 (M5 / Stage D) — strongest-evidence run-result for the single-
    # probe drawer too, derived from the clicked row's sibling turns.
    run_result = _run_result_view(ordered)

    return {
        "run_result": run_result,
        "record_id": rep.get("probe_id") or "",
        "probe_id": rep.get("probe_id") or "",
        "agent": rep.get("agent") or "",
        "asi_category": rep.get("asi_category") or "",
        "csa_category": rep.get("csa_category") or "",
        "mitre_atlas": rep.get("mitre_atlas") or [],
        "severity": rep.get("severity") or "",
        "severity_label": rep.get("severity_label") or "",
        "severity_class": "",
        "tier_floor": rep.get("tier_floor") or "",
        "owasp_scenario": rep.get("owasp_scenario") or "",
        "source_yaml": rep.get("source_yaml") or "",
        "source_path": rep.get("source_path") or "",
        "turn": rep.get("turn"),
        "timestamp_label": rep.get("timestamp_label") or "",
        "seed": rep.get("seed") or "",
        "rng_seed": rep.get("rng_seed") or "",
        "strategy": rep.get("strategy") or "",
        "mutator_operators": rep.get("mutator_operators") or [],
        "attacker_refused": bool(rep.get("attacker_refused") or False),
        "prompt": rep.get("prompt") or "",
        "target_response": rep.get("target_response") or "",
        "verdict": rep.get("verdict") or "",
        "confidence": rep.get("confidence"),
        "panel_votes": rep.get("panel_votes") or [],
        "reasoning": rep.get("reasoning") or "",
        # Judge v2 (M5 / Stage D) — verbatim judge evidence + evaluator-attack
        # marker for the single-turn (flat) layout.
        "evidence": str(rep.get("evidence") or ""),
        "evaluator_attack": bool(rep.get("evaluator_attack", False)),
        "verify": bool(rep.get("verify", False)),
        "conversation": conversation if len(conversation) > 1 else [],
        "summary": f"Probe {rep.get('probe_id')}" if rep.get("probe_id") else "Probe details",
    }


# Verdict precedence for the per-agent rollup. The grouped probe row shows a
# single verdict pill for the whole conversation; we surface the *worst*
# outcome the agent reached so a single ``fail`` turn in an otherwise-defended
# thread is never hidden behind a green pill. Higher number == worse.
_VERDICT_RANK: Final[dict[str, int]] = {
    # Legacy three.
    "fail": 6,
    "inconclusive": 2,
    "pass": 1,
    # Judge v2 (M0) six-value taxonomy — worst-case wins.
    "exploited": 6,
    "vulnerable": 4,
    "simulated_or_unverified": 3,
    "needs_followup": 2,
    "defended": 1,
}


def _rollup_verdict(turns: list[dict[str, Any]]) -> str:
    """Roll a multi-turn thread's per-turn verdicts up into one pill value.

    Worst-case wins (``fail`` > ``inconclusive`` > ``pass``) so the grouped
    row never masks an exploited turn behind a defended one. Empty / unknown
    turn verdicts contribute nothing; a thread with no graded turn rolls up to
    ``""`` (renders as PENDING — live recon turns that haven't been judged yet).
    """
    best = ""
    best_rank = 0
    for t in turns:
        raw = str(t.get("verdict") or "")
        if not raw:
            # Ungraded turn (e.g. a live recon turn) contributes nothing — keep
            # the thread at "" → PENDING rather than coercing it to a verdict.
            continue
        # Normalize each turn verdict onto the CURRENT taxonomy before ranking
        # (info_leak → exploited, weakness_observed → vulnerable, pass/fail/…),
        # so a row from an OLDER scan whose saved verdicts use the pre-2026-06
        # vocabulary still ranks and renders under the new pills instead of
        # falling through to PENDING.
        v = normalize_verdict(raw)
        rank = _VERDICT_RANK.get(v, 0)
        if rank > best_rank:
            best_rank = rank
            best = v
    return best


# Probes-table SUMMARY column cap — the one-line gloss is collapsed to a single
# line and truncated so the row stays scannable; the full reasoning is in the
# modal. Operator-untrusted text; the template autoescapes every cell.
_SUMMARY_CAP = 240


def _one_line_summary(text: str) -> str:
    """Collapse judge reasoning to one capped line for the Probes-table summary."""
    s = " ".join((text or "").split())
    if len(s) > _SUMMARY_CAP:
        s = s[: _SUMMARY_CAP - 1].rstrip() + "…"
    return s


def _run_result_view(turns: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive the per-agent run-result view-model from ordered turn records.

    Judge v2 (M5 / Stage D). The :class:`AsiRunResult` rollup is computed
    in-process on the agent and attached to its :class:`AgentReport`, but it is
    NOT persisted to ``memory.jsonl`` (the cross-process channel the dashboard
    reads). Rather than add a new persistence path, we recompute the SAME
    strongest-evidence rollup from the turn records the dashboard already reads
    — :func:`~agent_guardian.core.run_aggregator.aggregate_run_verdicts` is the
    single source of truth, so the dashboard's run verdict can never disagree
    with the report's.

    Returns a dict shaped for the probes table / drawer:

        {
          "has_run_result": bool,      # False ⇒ omit the row entirely
          "run_verdict": str,          # v2 verdict (pill value)
          "run_verdict_label": str,    # human label
          "run_confidence_pct": str,   # "95%" or ""
          "best_evidence_turn": int|None,  # operator-facing turn number
          "evaluator_attack": bool,    # any turn flagged an evaluator-attack
        }

    ``best_evidence_turn`` maps the aggregator's list INDEX onto the winning
    record's own ``turn`` number (falling back to 1-based position) so the
    operator reads "strongest evidence: turn N" in the transcript's own
    numbering. ``has_run_result`` is False for an empty / verdict-less thread
    (e.g. recon, which carries no graded turns) so the caller omits the row.
    """
    empty: dict[str, Any] = {
        "has_run_result": False,
        "run_verdict": "",
        "run_verdict_label": "",
        "run_confidence_pct": "",
        "best_evidence_turn": None,
        "evaluator_attack": False,
        "summary": "",
    }
    if not turns:
        return empty
    # Only graded turns contribute a meaningful run verdict; a thread with no
    # verdict at all (recon capability probing) rolls up to the neutral
    # needs_followup floor with best_evidence_turn = -1 — nothing was tested, so
    # we omit the row rather than show a misleading "NEEDS FOLLOW-UP".
    if not any(str(t.get("verdict") or t.get("verdict_v2") or "") for t in turns):
        return empty
    result: AsiRunResult = aggregate_run_verdicts(turns)
    if result.best_evidence_turn < 0:
        return empty
    idx = result.best_evidence_turn
    best_record = turns[idx] if 0 <= idx < len(turns) else {}
    best_turn_no = int(best_record.get("turn", 0) or 0) or (idx + 1)
    return {
        "has_run_result": True,
        "run_verdict": result.run_verdict,
        "run_verdict_label": _verdict_label(result.run_verdict),
        "run_confidence_pct": _confidence_pct(result.run_confidence),
        "best_evidence_turn": best_turn_no,
        "evaluator_attack": result.evaluator_attack_detected,
        # Probes-table SUMMARY column — a one-line "what we learned" gloss for
        # the row, from the strongest-evidence turn's judge reasoning.
        "summary": _one_line_summary(str(best_record.get("reasoning", ""))),
    }


def _group_key_for(probe: dict[str, Any]) -> str:
    """Return the grouping key for a probe/turn record.

    Operator feedback: recon emits ~17 individual turn records under one
    agent; rendering them as one row per turn buries the conversation. We
    group by ``agent`` so all of an agent's turns collapse into a single
    conversational entry.

    Recon writes turns with NO ``seed_id`` (empty ``probe_id``), so it can
    only be grouped by agent — there is no finer key to fall back on. For
    specialist agents that run several probe seeds we still key on the agent
    alone: "what this agent did" is the unit operators triage on, and the
    modal renders the full ordered conversation regardless of how many seeds
    it spans. (See ``build_probe_group_slideover_ctx`` implementation_notes.)
    """
    return str(probe.get("agent") or "")


def _load_probe_summaries(scan_dir: Path | None) -> dict[str, str]:
    """Read the AI-written per-agent summaries (``probe/summaries.json``).

    Written at scan finalization by
    :func:`agent_guardian.server.probe_summary.write_probe_summaries`. Returns
    an empty map when the file is absent (e.g. a live scan that hasn't finalized
    yet) or unreadable — the table then falls back to the reasoning gloss.
    """
    if scan_dir is None:
        return {}
    path = scan_dir / "probe" / "summaries.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    summaries = data.get("summaries") if isinstance(data, dict) else None
    if not isinstance(summaries, dict):
        return {}
    # Drop truncated / garbled AI summaries (a weak / safety-filtered model can
    # emit "The target" or "3:** No preamble,") so the row falls back to the
    # judge-reasoning gloss instead of showing junk.
    from agent_guardian.server.probe_summary import is_usable_summary

    return {str(k): str(v) for k, v in summaries.items() if is_usable_summary(str(v))}


def _agent_lifecycle_states(scan_dir: Path | None) -> dict[str, str]:
    """Map ``agent name -> "completed" | "skipped"`` from ``events.jsonl``.

    The authoritative per-agent run-status signal is the terminal SSE event the
    swarm appended to ``events.jsonl``: ``agent_done`` (an attack agent finished),
    ``recon_done`` (the recon agent finished its capability audit — recon does
    NOT emit ``agent_done``), or ``agent_skipped`` (not applicable to this
    target). An agent absent from this map has started but not finished — i.e. it
    is still running. ``has_run_result`` is NOT used here: it is true for any
    agent with a graded turn, including one mid-run, so it would mark an in-flight
    agent "done" prematurely.

    Never raises — a missing dir/file or corrupt line yields a partial map.
    """
    states: dict[str, str] = {}
    if scan_dir is None:
        return states
    path = scan_dir / "events.jsonl"
    if not path.is_file():
        return states
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    rec = json.loads(stripped)
                except (ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(rec, dict):
                    continue
                kind = rec.get("kind")
                if kind not in ("agent_done", "agent_skipped", "recon_done"):
                    continue
                agent = str(rec.get("agent") or "")
                if not agent:
                    continue
                states[agent] = "skipped" if kind == "agent_skipped" else "completed"
    except OSError as exc:  # pragma: no cover — defensive
        _LOG.debug("dashboard_view: events.jsonl lifecycle read failed (%s)", exc)
    return states


def _probe_status(
    agent: str, lifecycle: dict[str, str], *, scan_finalized: bool
) -> tuple[str, str]:
    """Return ``(label, css_class)`` for a probe row's run status.

    ``css_class`` is one of ``running`` / ``done`` / ``skipped`` (reusing the
    same colour grammar as the ASI compact-status pills). A finalized scan marks
    every agent done even without a per-agent terminal event.
    """
    st = lifecycle.get(agent)
    if st == "skipped":
        return ("Skipped", "skipped")
    if st == "completed" or scan_finalized:
        return ("Done", "done")
    return ("Running", "running")


def _assemble_probe_groups(
    probes_list: list[dict[str, Any]],
    summaries: dict[str, str] | None = None,
    *,
    lifecycle: dict[str, str] | None = None,
    scan_finalized: bool = False,
) -> list[dict[str, Any]]:
    """Collapse the flat per-turn probes list into ONE entry per agent.

    ``summaries`` (optional) maps a group key → the AI-written one-line summary
    (:func:`_load_probe_summaries`); attached as ``ai_summary`` on each group so
    the table prefers it over the strongest-turn reasoning gloss.

    The flat list (:func:`_assemble_probes_list`) carries one record per
    judged turn — recon alone can produce ~17. This groups those records by
    :func:`_group_key_for` (the agent) so the Probes table renders a single
    conversational row per agent. First-seen order is preserved (groups are
    keyed in the order their first turn appears in ``memory.jsonl``).

    Each returned entry is shaped for ``_probes_table.html``:

        {
          "group_key": str,          # the agent name (row identity + href)
          "agent": str,
          "asi_category": str,       # first non-empty asi seen in the group
          "probe_id": str,           # first non-empty seed_id (drawer header)
          "verdict": str,            # worst-case rollup across the turns
          "turn_count": int,         # how many turns this agent ran
          "timestamp_label": str,    # last turn's timestamp
          "turns": list[dict],       # the ordered turn records (modal source)
        }

    Never raises; an empty input yields an empty list.
    """
    buckets: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for p in probes_list:
        key = _group_key_for(p)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(p)

    groups: list[dict[str, Any]] = []
    for key in order:
        turns = _sort_turns_in_order(buckets[key])
        agent = next((str(t.get("agent") or "") for t in turns if t.get("agent")), key)
        asi = next((str(t.get("asi_category") or "") for t in turns if t.get("asi_category")), "")
        probe_id = next((str(t.get("probe_id") or "") for t in turns if t.get("probe_id")), "")
        # Last turn's timestamp is the most recent activity for this agent.
        timestamp_label = next(
            (
                str(t.get("timestamp_label") or "")
                for t in reversed(turns)
                if t.get("timestamp_label")
            ),
            "",
        )
        # Recon is capability probing, not a pass/fail attack — its turns carry
        # no verdict, so the worst-case rollup is empty and would render as a
        # misleading "PENDING". Mark it "recon" so the table shows a neutral
        # completed state instead.
        verdict = "recon" if agent == "recon-agent" else _rollup_verdict(turns)
        # Judge v2 (M5 / Stage D) — strongest-evidence run-result rollup
        # (run_verdict + best_evidence_turn + evaluator_attack), recomputed from
        # the same turns via the canonical aggregator. Recon (and any verdict-
        # less thread) returns ``has_run_result=False`` so the table / drawer
        # simply omits the row. Never overrides the worst-case ``verdict`` pill
        # the row already shows — it's an additive "strongest evidence" signal.
        run_result = (
            {"has_run_result": False} if agent == "recon-agent" else _run_result_view(turns)
        )
        _status_label, _status_class = _probe_status(
            agent, lifecycle or {}, scan_finalized=scan_finalized
        )
        groups.append(
            {
                "group_key": key,
                "agent": agent,
                "asi_category": asi,
                "probe_id": probe_id,
                "verdict": verdict,
                "turn_count": len(turns),
                "timestamp_label": timestamp_label,
                "turns": turns,
                "run_result": run_result,
                # Run-status pill — completed / running / skipped, from the
                # per-agent terminal events.jsonl signal (see _probe_status).
                "status_label": _status_label,
                "status_class": _status_class,
                # AI-written SUMMARY (empty until scan finalization writes it;
                # the template falls back to the reasoning gloss meanwhile).
                "ai_summary": (summaries or {}).get(key, ""),
            }
        )
    # Order rows by ASI number (ASI01 → ASI10) with recon-agent pinned at the
    # top, then agent name as a stable tiebreak so the two specialists that share
    # an ASI (e.g. output-handling + trust-exploit on ASI09) sit adjacent.
    groups.sort(key=_probe_group_sort_key)
    return groups


def _probe_group_sort_key(g: dict[str, Any]) -> tuple[int, int, str]:
    """Sort key for the Probes table: recon first, then by ASI number, then
    agent name. A non-ASI / unparseable category sorts after the numbered ones."""
    agent = str(g.get("agent") or "")
    if agent == "recon-agent":
        return (0, 0, "")
    asi = str(g.get("asi_category") or "")
    m = re.match(r"ASI0*(\d+)", asi)
    asi_num = int(m.group(1)) if m else 999
    return (1, asi_num, agent)


def build_probe_group_slideover_ctx(turns: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the shared slide-over ctx for a whole per-agent probe group.

    Sibling of :func:`build_probe_slideover_ctx`, but the unit of work is the
    full set of an agent's turns (recon's ~17 turns; a specialist's multi-turn
    attack thread) rather than one clicked turn. The ordered turns become the
    per-turn chat conversation; the representative turn (:func:`_representative_turn`
    — the turn that flipped the attack, else the last turn) fills the top-level
    prompt / response / verdict / reasoning so those four fields describe one
    exchange. The header verdict pill uses the worst-case rollup
    (:func:`_rollup_verdict`) so it agrees with the table row.
    """
    ordered = _sort_turns_in_order(turns)
    if not ordered:
        ordered = []
    rep = _representative_turn(ordered)
    conversation = _conversation_turns(ordered)
    agent = str(rep.get("agent") or "") or next(
        (str(t.get("agent") or "") for t in ordered if t.get("agent")), ""
    )
    probe_id = str(rep.get("probe_id") or "") or next(
        (str(t.get("probe_id") or "") for t in ordered if t.get("probe_id")), ""
    )
    rollup = _rollup_verdict(ordered) or str(rep.get("verdict") or "")
    summary = (
        f"{agent} — {len(ordered)} turn{'s' if len(ordered) != 1 else ''}"
        if agent
        else "Probe conversation"
    )
    # Recon is black-box capability probing, not an ASI attack: its turns carry
    # no probe_id / ASI / CSA / severity / strategy, so the finding-shaped
    # metadata + run-context blocks render all-"—". Flag it so the slide-over
    # collapses those empty sections and frames the modal as capability recon.
    is_recon = agent == "recon-agent"
    # Judge v2 (M5 / Stage D) — strongest-evidence run-result for the drawer
    # (run_verdict pill + "strongest evidence: turn N" + evaluator-attack flag).
    # Recon carries no graded turns, so this is omitted there.
    run_result = {"has_run_result": False} if is_recon else _run_result_view(ordered)
    return {
        "is_recon": is_recon,
        "run_result": run_result,
        "record_id": probe_id or agent,
        "probe_id": probe_id,
        "agent": agent,
        "asi_category": str(rep.get("asi_category") or ""),
        "csa_category": str(rep.get("csa_category") or ""),
        "mitre_atlas": rep.get("mitre_atlas") or [],
        "severity": rep.get("severity") or "",
        "severity_label": rep.get("severity_label") or "",
        "severity_class": "",
        "tier_floor": rep.get("tier_floor") or "",
        "owasp_scenario": rep.get("owasp_scenario") or "",
        "source_yaml": rep.get("source_yaml") or "",
        "source_path": rep.get("source_path") or "",
        # Recon turns all carry turn=0; the header title already says "N turns",
        # so suppress the redundant/misleading "turn 0" header chip for recon.
        "turn": None if is_recon else rep.get("turn"),
        "timestamp_label": str(rep.get("timestamp_label") or ""),
        "seed": rep.get("seed") or "",
        "rng_seed": rep.get("rng_seed") or "",
        "strategy": str(rep.get("strategy") or ""),
        "mutator_operators": rep.get("mutator_operators") or [],
        "attacker_refused": bool(rep.get("attacker_refused") or False),
        "prompt": str(rep.get("prompt") or ""),
        "target_response": str(rep.get("target_response") or ""),
        # Recon has no graded verdict (no probe_id / ASI). Surface the neutral
        # "recon" sentinel so the header pill reads RECON — matching the table
        # row — instead of falling through the empty-string path to PENDING.
        "verdict": "recon" if is_recon else rollup,
        "confidence": rep.get("confidence"),
        "panel_votes": rep.get("panel_votes") or [],
        "reasoning": str(rep.get("reasoning") or ""),
        # Always surface the conversation for a group — even a single-turn
        # agent reads as a one-message thread here (the row promised "all its
        # turns inline as the chat conversation").
        "conversation": conversation,
        "summary": summary,
    }


def _asi_dot_states(scan: Scan | None, findings_by_asi: dict[str, dict[str, int]]) -> list[str]:
    """Return 10 dot states ('done' / 'active' / 'queued') for the at-a-glance pill row."""
    states: list[str] = []
    for code in _ASI_ROW_META:
        bucket = findings_by_asi.get(code, {})
        has_findings = sum(bucket.values()) > 0
        if scan is None:
            states.append("active" if has_findings else "queued")
            continue
        # Completed scan -- every ASI category that the scan persisted is
        # considered covered, regardless of whether it found anything (the
        # at-a-glance pill row is "did we exercise it?", not "did we find?").
        states.append("done")
    return states


def _headline_qualifier(scan: Scan | None) -> str:
    """Editorial second line of the masthead headline."""
    if scan is None:
        return "It is <em>still ramping up.</em>"
    band = scan.band
    if band is SeverityBand.EXCELLENT:
        return "It is <em>excellent.</em>"
    if band is SeverityBand.GOOD:
        return "It is <em>good,</em> but not yet great."
    if band is SeverityBand.WARNING:
        return "It is <em>warning.</em>"
    if band is SeverityBand.POOR:
        return "It is <em>poor.</em>"
    if band is SeverityBand.CRITICAL:
        return "It is <em>critical.</em>"
    return "It is <em>not yet evaluated.</em>"


def _lede_html(scan: Scan | None, is_running: bool) -> str:
    """Hand-tuned lede paragraph that adapts to scan state.

    Uses ``<em>`` / ``<strong>`` for the editorial italics. Rendered as ``|safe``
    in the template because the markup is authored here, not user-provided.
    """
    if scan is None and is_running:
        return (
            "The swarm is <em>still ramping up</em>. Eleven specialist agents "
            "are dispatching probes against the target; the score, sub-scores, "
            "and per-ASI breakdown below will update <strong>live</strong> as "
            "each agent surfaces a verdict."
        )
    if scan is None:
        return (
            "Waiting on first verdict. As soon as the recon agent fingerprints "
            "the target, this page begins to update."
        )
    counts = scan.findings_summary()
    critical = counts["critical"]
    high = counts["high"]
    parts: list[str] = []
    if critical or high:
        penalty = critical * 2 + high * 0.4
        parts.append(
            f"<em>{critical}</em> critical and <em>{high}</em> high findings "
            f"weigh the aggregate down by <strong>{penalty:.1f} points</strong>."
        )
    parts.append(
        f"The scan ran on tier <strong>{scan.tier.value}</strong> across "
        f"<strong>{len(scan.findings)} findings</strong> with the "
        f"<em>{scan.mode}</em>-mode probe library."
    )
    return " ".join(parts)


def _adapter_label(scan: Scan | None) -> str:
    if scan is None:
        return "—"
    target_mode = scan.target_mode
    mapping = {
        "prompt": "Prompt (system-prompt)",
        "code": "Code (CodeAdapter)",
        "http": "HTTP endpoint",
        "framework": "Framework adapter",
    }
    return mapping.get(target_mode, target_mode)


def _tier_label(scan: Scan | None) -> str:
    if scan is None:
        return "—"
    return f"{scan.tier.value} (canonical)"


def _engine_field(scan: Scan | None, key: str, default: str = "—") -> str:
    if scan is None or scan.engine is None:
        return default
    return scan.engine.get(key, default)


# Per-mode estimated-cost band (USD). Mirrors ``ui.scan_plan_data.MODE_COST_USD``
# so the Overview "Scan plan" panel quotes the same figures the CLI's Phase-0
# scan-plan board prints. Duplicated (not imported) to keep this view module
# free of the CLI's heavier import chain.
_MODE_COST_USD: Final[dict[str, tuple[float, float]]] = {
    "fast": (0.005, 0.010),
    "smart": (0.020, 0.040),
    "full": (0.040, 0.080),
}


def _build_scan_plan(
    scan: Scan | None,
    *,
    base_url: str,
    locality_label: str,
    commander_model: str,
    attacker_model: str,
    evaluator_model: str,
    is_multi_agent: bool | None = None,
) -> dict[str, Any]:
    """Assemble the Overview "Scan plan" panel view-model.

    Mirrors the CLI's Phase-0 scan-plan board (``ui/scan_plan.py``) — the same
    TARGET / MODELS / BUDGET / OUTPUTS / DASHBOARD / SAFETY GUARDS sections — so
    the first thing an operator reads on the dashboard is the plan they
    confirmed in the terminal. Sourced entirely from the persisted ``Scan``
    record (plus the dashboard ``base_url``); fields a completed scan does not
    carry (live reachability latency, per-model preflight verdicts, server
    spawn state) render as ``"—"`` rather than being fabricated.
    """
    EM_DASH = "—"
    if scan is None:
        target_mode = EM_DASH
        mode = EM_DASH
        usd_cap = EM_DASH
        wall_cap = EM_DASH
        est_cost = EM_DASH
        roe_blocklist = EM_DASH
        authorization = EM_DASH
        egress = EM_DASH
    else:
        target_mode = scan.target_mode
        mode = scan.mode
        # USD cap: prefer the budget envelope's recorded cap; ``None`` = uncapped.
        if scan.budget is not None and scan.budget.cap_usd is not None:
            usd_cap = f"${scan.budget.cap_usd:.4f}"
        else:
            usd_cap = "uncapped"
        # No wall-clock cap field is persisted on the terminal Scan; an
        # absent cap means the run was uncapped (matches the CLI scan-plan).
        wall_cap = "uncapped"
        lo_hi = _MODE_COST_USD.get(scan.mode)
        if lo_hi is not None:
            est_cost = f"${lo_hi[0]:.4f} - ${lo_hi[1]:.4f} (typical for {scan.mode} mode)"
        else:
            est_cost = EM_DASH
        # SAFETY GUARDS — read from the RoE audit envelope when present.
        audit = scan.audit if isinstance(scan.audit, dict) else {}
        observed = audit.get("observed_blocklisted_tools")
        if isinstance(observed, list) and observed:
            roe_blocklist = ", ".join(str(t) for t in observed)
        else:
            roe_blocklist = "none"
        auth_ref = audit.get("authorization_ref")
        authorization = str(auth_ref) if auth_ref else "n/a"
        # Egress policy is not surfaced verbatim on the audit dict; the
        # default for a non-contract scan is unrestricted egress.
        egress = "unrestricted" if not audit else audit.get("egress_label", "unrestricted")

    # ``Reachable`` is a live preflight signal not retained on the terminal
    # Scan — but a scan that ran to completion necessarily reached the target,
    # so for a persisted scan we report it as reachable rather than "—".
    reachable = "✓ reachable" if scan is not None else EM_DASH
    # Likewise, the models were preflight-validated before the run started; a
    # persisted scan implies that passed.
    models_validated = "✓ validated" if scan is not None else EM_DASH
    # ``--output json`` is always written (report.json); surface it for a run.
    output_label = "json" if scan is not None else EM_DASH
    # ``Multi-agent`` comes from the recon fingerprint (memory.jsonl) — the
    # terminal Scan record does not carry it, so the caller threads through
    # the recon-derived flag. ``None`` ⇒ recon hasn't reported yet.
    if is_multi_agent is None:
        multi_agent = EM_DASH
    else:
        multi_agent = "yes (orchestrator declared)" if is_multi_agent else "no (single endpoint)"

    return {
        "target": {
            "url": scan.target_ref
            if (scan is not None and scan.target_mode == "http")
            else EM_DASH,
            "mode": target_mode,
            "reachable": reachable,
            "multi_agent": multi_agent,
        },
        "models": {
            "attacker": attacker_model,
            "evaluator": evaluator_model,
            "commander": commander_model,
            "validated": models_validated,
        },
        "budget": {
            "mode": mode,
            "wall_cap": wall_cap,
            "usd_cap": usd_cap,
            "estimated_cost": est_cost,
        },
        "outputs": {
            "output": output_label,
        },
        "dashboard": {
            "url": base_url or EM_DASH,
            "server_status": locality_label or EM_DASH,
        },
        "safety": {
            "roe_blocklist": roe_blocklist,
            "authorization": authorization,
            "egress_policy": egress,
        },
    }


def build_dashboard_context(
    *,
    scan_id: str,
    scan: Scan | None,
    is_running: bool,
    base_url: str,
    version_label: str,
    elapsed_seconds: float | None = None,
    started_at_label: str = "",
    page: int = 1,
    per_page: int = 15,
    is_terminal: bool | None = None,
    scan_dir: Path | None = None,
) -> DashboardContext:
    """Build the Jinja context for the live dashboard render.

    The function is intentionally pure — no I/O, no globals, no time.now() —
    so it is straightforward to unit-test and the SSE update path can reuse
    parts of it without surprises.
    """
    is_local, locality_label, url_scheme, url_host, url_port = resolve_locality(base_url)

    findings_by_asi = _count_findings_by_asi(scan)
    empty_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    counts = scan.findings_summary() if scan is not None else empty_counts
    findings_total = sum(counts.values())

    if scan is not None:
        aivss_label: str | int = scan.aivss
        band_label = _humanise_band(scan.band)
        band_class = _band_class(scan.band)
        needle_pct = _aivss_to_needle(scan.aivss)
        aggregate = scan.aivss + counts["critical"] * 2 + counts["high"] * 0.4
        score_sublabel = "tier-weighted, signed evidence"
    else:
        aivss_label = "—"
        band_label = "Pending"
        band_class = "unknown"
        needle_pct = None
        aggregate = 0.0
        score_sublabel = "tier-weighted, provisional"

    asi_rows = _asi_rows(scan, findings_by_asi)
    findings_page, pagination = _findings_page(scan, page=page, per_page=per_page)
    # Evidence wiring: attach the verbatim probe attempts (prompt / response /
    # reasoning) that correlate to each finding row. Done post-_findings_page
    # so the function signature stays stable and other callers (SSE diff,
    # report exporter) don't have to re-derive the join.
    _probes_list_for_evidence = _assemble_probes_list(scan_dir)
    _attach_evidence_to_findings(findings_page, _probes_list_for_evidence)
    # ``scan_finalized`` must be the REAL "scan has finished" signal, NOT
    # ``scan is not None``: during a live scan the dashboard loads a PARTIAL
    # ``Scan`` from the on-disk snapshot, so ``scan`` is non-None while the scan
    # is still running. Using ``scan is not None`` marked every agent "Done" the
    # moment a partial snapshot existed. ``is_running`` is the authoritative flag
    # (the same one that drives the "In progress" vs "Completed" header), so an
    # agent is only "Done" when it actually emitted ``agent_done`` (lifecycle) or
    # the whole scan has finalised.
    _probe_groups = _assemble_probe_groups(
        _probes_list_for_evidence,
        _load_probe_summaries(scan_dir),
        lifecycle=_agent_lifecycle_states(scan_dir),
        scan_finalized=not is_running,
    )
    # QA-066 (2026-06-04) — PROBES KPI tile. "How many probes did we actually
    # run." ``completeness.turns_used`` is the authoritative, uncapped count of
    # probe turns sent (one turn == one probe); the assembled ``probes_list``
    # is display-capped at ``_PROBES_LIST_CAP`` so its length would undercount
    # a long scan. We prefer the completeness figure when the scan has
    # finalised and fall back to the live (uncapped-until-500) list length
    # while a scan is still streaming, so the tile counts up in real time.
    _probes_executed = (
        scan.completeness.turns_used
        if scan is not None and scan.completeness is not None and scan.completeness.turns_used
        else len(_probes_list_for_evidence)
    )
    _probes_agents = len(_probe_groups)
    asi_dot_states = _asi_dot_states(scan, findings_by_asi)
    # QA-070 (2026-06-04) — COVERAGE = ASI dimensions actually EXERCISED, not
    # the subset that produced findings. The old count
    # (``categories with >=1 finding``) made a well-defended target read as
    # under-covered: a category that ran and came back clean (zero findings) is
    # fully covered, yet didn't count. It also never reconciled with the
    # "skipped agents" panel — a single-agent target skips ASI07 (orchestration
    # is N/A), so operators expect 9/10, not "7/10 with only 1 skipped".
    # A category is exercised once at least one probe is dispatched for it; we
    # count distinct ASI codes seen across the assembled probe list. This is 0
    # before any agent runs, climbs live as agents dispatch, and settles at
    # ``10 - <skipped>`` — so coverage + skipped now sum to the full taxonomy.
    asi_covered = len(
        {
            code
            for probe in _probes_list_for_evidence
            if (code := str(probe.get("asi_category", "")).strip().upper()) in findings_by_asi
        }
    )

    if scan is not None:
        commander_model = _engine_field(scan, "commander", "stub")
        attacker_model = _engine_field(scan, "attacker", "stub")
        evaluator_model = _engine_field(scan, "evaluator", "stub")
    else:
        commander_model = attacker_model = evaluator_model = "—"

    # Recon-derived view-model (read once; reused by the Overview recon panel
    # AND the Scan plan panel's Multi-agent row, which the terminal Scan record
    # cannot supply on its own).
    recon_summary = _assemble_recon_summary(scan_dir)
    _recon_multi_agent = (
        bool(recon_summary.get("is_multi_agent")) if recon_summary.get("has_data") else None
    )
    scan_plan = _build_scan_plan(
        scan,
        base_url=base_url,
        locality_label=locality_label,
        commander_model=commander_model,
        attacker_model=attacker_model,
        evaluator_model=evaluator_model,
        is_multi_agent=_recon_multi_agent,
    )

    elapsed = (
        elapsed_seconds
        if elapsed_seconds is not None
        else (scan.duration_seconds if scan is not None else 0.0)
    )

    # ``started_at_unix`` is the STABLE float-seconds anchor the client-side
    # ElapsedTicker counts up from (it never parses an ISO timestamp — Safari
    # ``Date.parse`` returns NaN on naive datetimes, critic patch G16/P9).
    #
    # Bug fix: a terminal scan anchors to ``scan.created_at`` as before, but an
    # IN-FLIGHT scan (``scan is None`` / partial-on-disk) previously produced
    # ``None`` here — so the ticker had nothing to seed from, never stamped its
    # anchor, and the KPI ELAPSED tile fell back to the server's ``elapsed``
    # label which the snapshot patcher rewrote each poll, flickering between
    # "00:00" and "00:01". We now derive the anchor as ``now - elapsed``: a
    # single ``time.time()`` read per render that yields a steady wall-clock
    # start the ticker can animate against from the very first paint, before
    # the recon agent has written anything. (This is the one intentional clock
    # read in this otherwise-pure builder — both terms move together, so
    # re-renders agree on the same anchor.)
    if scan is not None:
        started_at_unix: float | None = scan.created_at.timestamp()
    elif elapsed_seconds is not None:
        # Floor to a whole second so the anchor is STABLE across the live
        # SSE poll loop (``live_snapshot`` recomputes the context every
        # poll; an un-floored ``time.time()`` would jitter by milliseconds
        # each call and defeat the stream's duplicate-snapshot suppression).
        # The ELAPSED clock only renders MM:SS, so 1-second granularity is
        # exact for display purposes.
        started_at_unix = float(int(time.time() - elapsed_seconds))
    else:
        started_at_unix = None

    probe_library_version = scan.probe_library_version if scan is not None else "—"
    package_version = scan.package_version if scan is not None else version_label
    aivss_formula_version = scan.aivss_formula_version if scan is not None else "aivss-v1"

    # Reproducibility fingerprint. We surface the scan id as the visible
    # anchor when no on-disk signature has been written yet; the signed
    # bundle work attaches the real Ed25519 fingerprint to the scan output
    # via ``reports.signing`` — we read it from ``scan.audit`` when present.
    evidence_fingerprint = scan_id.upper()
    if scan is not None and isinstance(scan.audit, dict):
        fp = scan.audit.get("evidence_fingerprint")
        if isinstance(fp, str) and fp:
            evidence_fingerprint = fp

    # ``is_terminal`` is True iff a fully-completed (terminal) Scan has been
    # loaded from disk AND no one is still actively producing more events.
    # The dashboard template uses this -- not ``is_running`` -- to decide
    # whether to short-circuit the SSE auto-refresh: a mid-flight scan with
    # only a partial snapshot on disk (cross-process) MUST keep polling so
    # the AIVSS / ASI / at-a-glance widgets pick up the live numbers as the
    # swarm writes new partial snapshots. The route handler passes the
    # disk-backed signal (terminal file present); when not threaded through
    # we fall back to ``scan is not None and not is_running`` for back-compat
    # with library callers that haven't been updated.
    resolved_is_terminal = (
        is_terminal if is_terminal is not None else (scan is not None and not is_running)
    )
    payload: dict[str, Any] = {
        "page_title": f"Scan {scan_id}",
        "scan_id": scan_id,
        "is_running": is_running,
        "is_terminal": resolved_is_terminal,
        "version": version_label,
        # Topbar
        "base_url": base_url,
        "is_local": is_local,
        "locality_label": locality_label,
        "url_scheme": url_scheme,
        "url_host": url_host,
        "url_port": url_port,
        # Masthead
        "started_at_label": started_at_label or "—",
        "elapsed_label": _humanise_seconds(elapsed),
        "aivss_label": aivss_label,
        "headline_qualifier": _headline_qualifier(scan),
        "lede_html": _lede_html(scan, is_running),
        "target_ref": scan.target_ref if scan is not None else "—",
        "adapter_label": _adapter_label(scan),
        "tier_label": _tier_label(scan),
        "commander_model": commander_model,
        "attacker_model": attacker_model,
        "evaluator_model": evaluator_model,
        "probe_library_version": probe_library_version,
        # Score card
        "score_sublabel": score_sublabel,
        "band_label": band_label,
        "band_class": band_class,
        # KPI tile descriptions — one-line subtitles for the eight tiles in
        # ``_kpi_strip.html``. Kept here (not in the template) so they can be
        # unit-tested and overridden by callers without forking Jinja.
        #
        # QA-028 sub-ask 1: descriptions now render inside a hover-only
        # ``ⓘ`` popover (``.exec-kpi__desc-popover``) instead of an always-on
        # ``.exec-kpi__desc`` block — payload key is unchanged, only the
        # template render mode flipped.
        # QA-039 / QA-044 / QA-067 (2026-06-03) — these prose explainers
        # are surfaced behind the ``ⓘ`` button. They are written in
        # sentence case (acronyms preserved: AIVSS, ASI, USD) and read as
        # short body-scale paragraphs in ``.kpi-info-popover`` (see
        # ``executive.css`` §3 — the popover renders without
        # ``text-transform: uppercase`` and without letter-spacing).
        # QA-062 (2026-06-03) — hover data tables were dropped from every
        # tile except FINDINGS, so the "hover the tile for X" callouts
        # were removed from the other tiles' prose to avoid pointing the
        # operator at a surface that no longer exists.
        "kpi_descriptions": {
            "aivss": (
                "Composite agent safety score on a 0-100 scale. It is a "
                "weighted average across the ten OWASP ASI sub-scores, "
                "blended with the tier-specific scoring formula. The band "
                "below maps the score to a risk tier: 0-39 critical, 40-59 "
                "poor, 60-79 warning, 80-89 good, and 90-100 excellent."
            ),
            "findings": (
                "Total exploit attempts the evaluator graded as valid. "
                "Hover the tile for the per-severity breakdown."
            ),
            "probes": (
                "Total probe attempts actually dispatched to the target "
                "across every attack agent — one per conversation turn. "
                "FINDINGS counts only the subset the evaluator graded as a "
                "valid exploit."
            ),
            "elapsed": (
                "Wall-clock duration of the scan, measured from the "
                "first probe dispatch through the final evaluator "
                "verdict."
            ),
            "cost": (
                "Estimated model spend for this scan in USD, summed "
                "across the commander, attacker, and evaluator phases."
            ),
            "coverage": (
                "How many of the ten OWASP ASI dimensions were actually "
                "exercised — at least one probe dispatched. Dimensions the "
                "recon phase ruled not applicable to this target (shown under "
                "Skipped agents) are not counted; coverage plus skipped span "
                "the full taxonomy. A category that ran and stayed clean still "
                "counts as covered."
            ),
        },
        # QA-044 (2026-06-02) — structured hover data tables. Each entry
        # is a list of ``{label, value, class?}`` dicts that ``_kpi_strip.html``
        # renders as a small table inside ``.exec-kpi__hover-table``. We
        # build it here rather than in Jinja so the row order stays Python-
        # sorted and the breakdown matches what unit tests assert against.
        # QA-062 (2026-06-03) — only FINDINGS still surfaces a hover table;
        # the other tiles dropped the popover so we only build the one row.
        "kpi_hover_tables": _build_kpi_hover_tables(
            counts=counts,
            findings_total=findings_total,
        ),
        # QA-028 sub-ask 2 — per-tile inline-SVG mini-charts. The KPI strip
        # template reads this dict to draw a 64px-tall visualisation inside
        # each tile (radial gauge / band axis segment / stacked severity bar
        # / progress bar / pie segments). Fields are derived from existing
        # payload values; no new sources of truth.
        "kpi_chart_data": {
            "aivss_pct": _fmt_pct(float(scan.aivss)) if scan is not None else 0.0,
            "severity_mix": {
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
            },
            # QA-027: ``elapsed`` + ``cost`` may be uncapped — render a flat
            # "no cap" indicator when the cap is None / 0. We pre-compute the
            # boolean so the template stays declarative.
            "elapsed_uncapped": True,
            "cost_uncapped": False,
            "elapsed_pct": _fmt_pct((elapsed / 900.0) * 100.0 if elapsed else 0.0),
            "cost_pct": _fmt_pct(((scan.cost_usd / 5.0) * 100.0) if scan is not None else 0.0),
            "coverage_covered": asi_covered,
            "coverage_total": 10,
        },
        "needle_pct": needle_pct,
        "aggregate_label": f"{aggregate:.1f}",
        # Unicode MINUS SIGN (U+2212) is the typographically correct glyph for
        # the receipt-style penalty table; HYPHEN-MINUS would be visually
        # misaligned against the proportional Source Serif digits.
        "critical_penalty_label": (
            f"−{counts['critical'] * 2:.1f}" if counts["critical"] else "0.0"  # noqa: RUF001
        ),
        "high_penalty_label": (
            f"−{counts['high'] * 0.4:.1f}" if counts["high"] else "0.0"  # noqa: RUF001
        ),
        "counts": counts,
        # At a glance
        "budget_label": "15:00 budget",
        "elapsed_pct": _fmt_pct((elapsed / 900.0) * 100.0 if elapsed else 0.0),
        "probes_label": str(_probes_estimate(scan)),
        "probes_pct": 62.0 if scan is not None else 0.0,
        # QA-066 (2026-06-04) — PROBES KPI tile values.
        "probes_executed": _probes_executed,
        "probes_agents_label": (
            f"{_probes_agents} agent" if _probes_agents == 1 else f"{_probes_agents} agents"
        ),
        "tokens_label": _humanise_int(scan.tokens_total if scan is not None else 0),
        "tokens_cap_label": "10 M",
        "tokens_pct": _fmt_pct(
            ((scan.tokens_total / 10_000_000.0) * 100.0) if scan is not None else 0.0
        ),
        "usd_label": f"$ {scan.cost_usd:.2f}" if scan is not None else "$ 0.00",
        "usd_cap_label": "$ 5.00",
        "usd_pct": _fmt_pct(((scan.cost_usd / 5.0) * 100.0) if scan is not None else 0.0),
        "findings_total": findings_total,
        "asi_covered": asi_covered,
        "asi_dot_states": asi_dot_states,
        "tier_number": (scan.tier.value if scan is not None else "T2").lstrip("T")[:1] or "2",
        # ASI breakdown
        "asi_rows": asi_rows,
        # Findings feed
        "findings_page": findings_page,
        "pagination": pagination,
        # Reproducibility
        "package_version": package_version,
        "aivss_formula_version": aivss_formula_version,
        "rng_seed": "—",
        "evidence_fingerprint": evidence_fingerprint,
        # Executive theme — Probes + Logs tabs (additive; other themes ignore).
        # Both lists are always present (empty when scan_dir is None or files
        # are missing) so template authors can iterate without guarding.
        # ``_probes_list_for_evidence`` is reused here (already assembled
        # above for the Findings tab evidence join) so we don't read
        # memory.jsonl twice per render. ``probes_list`` stays the FLAT
        # per-turn list — it's still the source the Findings evidence join
        # and the ``/probe?index=N`` drawer fast-path index into.
        "probes_list": _probes_list_for_evidence,
        # Per-agent grouping (operator feedback 2026-06-03): recon emits
        # ~17 individual turn records, one row per turn buries the
        # conversation. ``probe_groups`` collapses the flat list into ONE
        # entry per agent so the Probes table renders one conversational row
        # per agent; clicking it opens the modal with that agent's full
        # turn-by-turn chat. Derived from the SAME flat list (no extra disk
        # read).
        "probe_groups": _probe_groups,
        # BUG-1 (2026-06-02) — the legacy ``probes_payload_json`` was a
        # centralised JSON-island wall the slideover JS read on click.
        # It was removed because it dumped the full prompt + target
        # response + judge reasoning of every probe as a single ``<script
        # type="application/json">`` blob below the table — visible to
        # anyone who inspected the source. The drawer now reads each
        # probe's payload from a per-row ``data-probe-payload`` attribute
        # (``tojson`` in the template), so no centralised dump is needed.
        "logs_tail": _assemble_logs_tail(scan_dir),
        # QA-047 (2026-06-02) — Overview "Recon findings about this agent"
        # panel. Reads the latest fingerprint + agent-skipped records
        # from memory.jsonl and projects them into a key-value sheet:
        # framework / target / capability chips / discovered tools /
        # refusal baseline / system-prompt clues / skipped agents. Empty
        # / disabled when no fingerprint has been written yet.
        "recon_summary": recon_summary,
        # Overview "Scan plan" panel — mirrors the CLI Phase-0 scan-plan board
        # (TARGET / MODELS / BUDGET / OUTPUTS / DASHBOARD / SAFETY GUARDS).
        # Replaced the framework-internal "Scan identity" fingerprint card.
        "scan_plan": scan_plan,
        # SSE Phase 1, Step 2 — phase-spine snapshot. ``phase_state`` carries
        # the four-phase state machine (recon / decompose / parallel /
        # finalise) replayed from events.jsonl; ``started_at_unix`` is the
        # float-seconds anchor the client-side ``ElapsedTicker`` reads (never
        # parses ISO timestamps — Safari ``Date.parse`` returns NaN on naive
        # datetimes, critic patch G16/P9). Both surface verbatim on the
        # ``/scans/<id>/live`` snapshot via :func:`live_snapshot`.
        "phase_state": _compute_phase_state(scan_dir),
        "started_at_unix": started_at_unix,
    }
    return DashboardContext(payload=payload)


def _assemble_probes_list(scan_dir: Path | None) -> list[dict[str, Any]]:
    """Read every ``record_type=reflection`` row from ``<scan_dir>/memory.jsonl``.

    Each reflection record's ``payload.content`` is a JSON-encoded ``turn_record``
    written by ``agents/base.py``. We decode the inner JSON, surface the locked
    Executive-tab fields, and emit a flat dict ready for the Jinja template.

    Capped at :data:`_PROBES_LIST_CAP` entries (keeps the oldest ``N`` —
    chronological order preserved); the cap protects long-running scans from
    blowing the page render.

    Returns an empty list when ``scan_dir`` is ``None``, the file is missing,
    or every line is malformed. Never raises — disk / parse failures are
    swallowed (warned at DEBUG level) so a corrupt memory.jsonl never 500s the
    dashboard.
    """
    if scan_dir is None:
        return []
    path = scan_dir / "memory.jsonl"
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                record = _parse_reflection_line(stripped)
                if record is not None:
                    out.append(record)
                if len(out) >= _PROBES_LIST_CAP:
                    break
    except OSError as exc:  # pragma: no cover — disk-level failure
        _LOG.debug("dashboard_view: memory.jsonl read failed (%s)", exc)
        return []
    return out


def _assemble_recon_summary(scan_dir: Path | None) -> dict[str, Any]:
    """Read the recon-derived view-model from ``<scan_dir>/memory.jsonl``.

    QA-047 (2026-06-02). Reads two record types from ``memory.jsonl``:

    * ``record_type=fingerprint`` — the latest wins. Carries the
      :class:`TargetFingerprint` payload (mode, framework, declared tools,
      capability flags, inferred goal / domain, declared guardrails,
      profile source + confidence). Surfaced in the Overview "Recon
      findings about this agent" panel as a key-value sheet.
    * ``record_type=agent_skipped`` — each is one row in the "skipped
      agents" table (which ASI agent was skipped + the recon-derived
      reason, e.g. ``"not applicable for fingerprint"``).

    Returns a dict shaped for the ``_recon_panel.html`` template:

        {
          "has_data": bool,             # False ⇒ empty / pending render path
          "framework_family": str,
          "target_model": str,
          "target_mode": str,
          "target_ref": str,
          "has_tools": bool,
          "tool_count": int,
          "tool_sample": list[str],
          "discovered_tools": list[str],   # full list for the collapsible
          "has_memory": bool,
          "memory_keys": list[str],
          "is_multi_agent": bool,
          "touches_pii": bool,
          "inferred_goal": str,
          "domain": str,
          "sensitive_actions": list[str],
          "declared_guardrails": list[str],
          "guardrail_posture": str,            # "none"/"weak"/... or ""
          "requires_confirmation": bool|None,  # None ⇒ omit the row
          "data_exposure": list[str],          # observed disclosures
          "behavioral_flags": list[str],       # behavioural observations
          "tool_descriptions": dict[str,str],  # tool -> one-line purpose
          "recon_coverage": dict[str,str],     # band -> coverage state
          "recon_probe_count": int,            # probes fired in the audit
          "profile_source": str,
          "profile_confidence": float,
          "skipped_agents": list[{agent, asi, reason}],
        }

    QA-059 (2026-06-03) — the ``system_prompt_clues`` /
    ``system_prompt_clues_full`` fields were removed: the recon panel
    no longer surfaces the legacy "Recon context" row (operators read
    the raw `TargetFingerprint.notes` either as a leaked prompt or as
    duplicative recon metadata, neither helpful). The capability chips
    + endpoint row carry the same signal in a clearer shape.

    QA-060 (2026-06-03) — ``skipped_agents[*].reason`` is rewritten
    from the swarm's generic ``"not applicable for fingerprint"`` to
    the specific capability gap that gated the agent off (e.g.
    ``"target does not declare memory capability"``). The mapping
    keys off the agent class name and lives in
    :data:`_SKIP_REASON_BY_AGENT`. Reasons that don't match the
    generic placeholder pass through unchanged.

    Returns an empty / disabled dict when ``scan_dir`` is ``None``, the
    file is missing, or no fingerprint record has been written yet
    (early in a running scan).

    Never raises — disk / parse failures swallowed (logged at DEBUG).
    """
    empty: dict[str, Any] = {
        "has_data": False,
        "framework_family": "—",
        "target_model": "—",
        "target_mode": "—",
        "target_ref": "—",
        "has_tools": False,
        "tool_count": 0,
        "tool_sample": [],
        "discovered_tools": [],
        "has_memory": False,
        "memory_keys": [],
        "is_multi_agent": False,
        "touches_pii": False,
        "inferred_goal": "",
        "domain": "",
        "sensitive_actions": [],
        "declared_guardrails": [],
        "guardrail_posture": "",
        "requires_confirmation": None,
        "data_exposure": [],
        "behavioral_flags": [],
        "tool_descriptions": {},
        "recon_coverage": {},
        "recon_probe_count": 0,
        "profile_source": "",
        "profile_confidence": 0.0,
        "skipped_agents": [],
    }
    if scan_dir is None:
        return empty
    path = scan_dir / "memory.jsonl"
    if not path.is_file():
        return empty
    latest_fp: dict[str, Any] | None = None
    skipped: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    rec = json.loads(stripped)
                except (ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(rec, dict):
                    continue
                rtype = rec.get("record_type")
                if rtype == "fingerprint":
                    payload = rec.get("payload")
                    if isinstance(payload, dict):
                        latest_fp = payload
                elif rtype == "agent_skipped":
                    payload = rec.get("payload")
                    if isinstance(payload, dict):
                        agent_name = str(payload.get("agent", ""))
                        raw_reason = str(payload.get("reason", ""))
                        # QA-060 — rewrite the swarm's generic
                        # "not applicable for fingerprint" placeholder
                        # to the specific capability gap that gated
                        # this agent off. Any agent absent from
                        # `_SKIP_REASON_BY_AGENT` keeps the raw reason
                        # (covers future specialists + any custom
                        # reason a specialist already writes).
                        if raw_reason == _GENERIC_SKIP_REASON:
                            reason = _SKIP_REASON_BY_AGENT.get(agent_name, raw_reason)
                        else:
                            reason = raw_reason
                        skipped.append(
                            {
                                "agent": agent_name,
                                "asi": str(payload.get("asi", "")),
                                "reason": reason,
                            }
                        )
    except OSError as exc:  # pragma: no cover — disk-level failure
        _LOG.debug("dashboard_view: recon read failed (%s)", exc)
        return empty
    if latest_fp is None:
        # No fingerprint written yet. Still surface skipped agents (rare,
        # but possible if the swarm bypassed agents on a pre-existing
        # cached fingerprint that was deleted off-disk).
        if not skipped:
            return empty
        out = dict(empty)
        out["skipped_agents"] = skipped
        return out

    declared_tools = list(latest_fp.get("declared_tools") or [])
    declared_memory_keys = list(latest_fp.get("declared_memory_keys") or [])
    return {
        "has_data": True,
        "framework_family": (
            str(latest_fp.get("framework")) if latest_fp.get("framework") else "Unknown"
        ),
        # No model name in the fingerprint payload today — we surface the
        # target_ref (URL / module path / prompt id) and let the operator
        # pivot to the engine row in the reproducibility receipt for
        # commander/attacker/evaluator model ids.
        "target_model": str(latest_fp.get("ref") or "—"),
        "target_mode": str(latest_fp.get("mode") or "—"),
        "target_ref": str(latest_fp.get("ref") or "—"),
        "has_tools": bool(latest_fp.get("has_tools")),
        "tool_count": len(declared_tools),
        # Sample = first 3 tools for the chip strip; full list lives in
        # the collapsible <details>.
        "tool_sample": declared_tools[:3],
        "discovered_tools": declared_tools,
        "has_memory": bool(latest_fp.get("has_memory")),
        "memory_keys": declared_memory_keys,
        "is_multi_agent": bool(latest_fp.get("is_multi_agent")),
        "touches_pii": bool(latest_fp.get("touches_pii")),
        "inferred_goal": str(latest_fp.get("inferred_goal") or ""),
        "domain": str(latest_fp.get("domain") or ""),
        "sensitive_actions": list(latest_fp.get("sensitive_actions") or []),
        "declared_guardrails": list(latest_fp.get("declared_guardrails") or []),
        # Deeper evidence-grounded recon signals (additive). Older fingerprint
        # records lack these keys; the `or` defaults keep them rendering as
        # empty / omitted rows without raising.
        "guardrail_posture": str(latest_fp.get("guardrail_posture") or ""),
        "requires_confirmation": (
            bool(latest_fp.get("requires_confirmation"))
            if latest_fp.get("requires_confirmation") is not None
            else None
        ),
        "data_exposure": list(latest_fp.get("data_exposure") or []),
        "behavioral_flags": list(latest_fp.get("behavioral_flags") or []),
        "tool_descriptions": dict(latest_fp.get("tool_descriptions") or {}),
        "recon_coverage": dict(latest_fp.get("recon_coverage") or {}),
        "recon_probe_count": int(latest_fp.get("recon_probe_count") or 0),
        "profile_source": str(latest_fp.get("profile_source") or "heuristic"),
        "profile_confidence": float(latest_fp.get("profile_confidence") or 0.0),
        "skipped_agents": skipped,
    }


def _parse_reflection_line(raw: str) -> dict[str, Any] | None:
    """Parse a single ``memory.jsonl`` line into the locked probe shape.

    Returns ``None`` for non-reflection records and for malformed JSON — the
    caller filters those out. The inner ``turn_record`` lives JSON-encoded
    inside ``payload.content``; we decode it, then cherry-pick the locked
    fields with safe defaults.
    """
    try:
        rec = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(rec, dict):
        return None
    if rec.get("record_type") != "reflection":
        return None
    payload = rec.get("payload")
    if not isinstance(payload, dict):
        return None
    content_raw = payload.get("content")
    turn: dict[str, Any] = {}
    if isinstance(content_raw, str) and content_raw:
        try:
            decoded = json.loads(content_raw)
        except (ValueError, json.JSONDecodeError):
            decoded = None
        if isinstance(decoded, dict):
            turn = decoded
    # Not-tested lifecycle markers (egress_refused / attacker_refused) carry no
    # verdict and never reached the target — drop them so they don't render as a
    # junk turn-0 row in the Probes tab (matches coverage + probe-export).
    if turn.get("event") in NOT_TESTED_EVENTS:
        return None
    timestamp_label = _timestamp_label(rec.get("timestamp"))
    seed_id = turn.get("seed_id")
    probe_id = str(seed_id) if seed_id else ""
    # Judge v2 (M5 / Stage D) — a verify turn is the bounded drill-down re-probe
    # of a prior ``needs_followup`` claim. ``agents/base.py`` stamps the
    # turn_record with ``intent="verify"`` / ``verify=True`` (else
    # ``intent="attack"`` / ``verify=False``). Either flag, when truthy, marks
    # the turn as a verification probe; we OR them so a record carrying only one
    # still reads correctly. Missing keys default to a plain attack turn.
    is_verify = bool(turn.get("verify", False)) or str(turn.get("intent", "")) == "verify"
    return {
        "agent": str(turn.get("agent", payload.get("agent", ""))),
        "asi_category": str(turn.get("asi_category", "")),
        "csa_category": str(turn.get("csa_category", "")),
        "turn": int(turn.get("turn", 0) or 0),
        "strategy": str(turn.get("strategy", "")),
        "probe_id": probe_id,
        "prompt": str(turn.get("prompt", "")),
        "target_response": str(turn.get("target_response", "")),
        "verdict": str(turn.get("verdict", "")),
        "confidence": float(turn.get("confidence", 0.0) or 0.0),
        "reasoning": str(turn.get("reasoning", "")),
        "timestamp_label": timestamp_label,
        "attacker_refused": bool(turn.get("attacker_refused", False)),
        # Judge v2 (M5 / Stage D) — verify-turn + corroboration signals plumbed
        # through to the per-turn view-model. ``verdict_v2`` is the normalized
        # v2 verdict (prefer it over the legacy ``verdict`` for run rollup);
        # ``evaluator_attack`` flags an attacker prompt that tried to manipulate
        # the judge; ``evidence`` is the verbatim span proving the verdict;
        # ``intent`` / ``verify`` distinguish a verification probe from an
        # attack turn. All default safe so legacy records (which lack them)
        # render unchanged with no badge / no evidence row.
        "verdict_v2": str(turn.get("verdict_v2", "") or ""),
        "evaluator_attack": bool(turn.get("evaluator_attack", False)),
        "evidence": str(turn.get("evidence", "") or ""),
        "intent": str(turn.get("intent", "") or ""),
        "verify": is_verify,
    }


# SSE Phase 1, Step 2 — phase taxonomy. The four producer strings emitted
# by ``core/swarm.py``'s ``_emit_phase()`` helper (critic patch G1/P1). The
# order here is the on-screen pill order — Recon → Decompose → Parallel →
# Finalise — and the snapshot's ``phase_state.phases`` dict is keyed by
# these strings in the same order.
_PHASE_NAMES: Final[tuple[str, ...]] = ("recon", "decompose", "parallel", "finalise")


def _empty_phase_state() -> dict[str, Any]:
    """Return the cold-start ``phase_state`` snapshot (every phase pending).

    Shape locked by SSE Phase 1 Step 2: a top-level snapshot key keyed by the
    four producer phase strings, each phase carrying ``state``,
    ``agents_completed``, ``agents_total``. ``current_phase`` is ``None`` when
    no ``phase_start`` has fired yet.
    """
    return {
        "current_phase": None,
        "phases": {
            name: {"state": "pending", "agents_completed": 0, "agents_total": 0}
            for name in _PHASE_NAMES
        },
    }


def _compute_phase_state(scan_dir: Path | None) -> dict[str, Any]:
    """Compute the current ``phase_state`` snapshot by replaying ``events.jsonl``.

    SSE Phase 1, Step 2 — the snapshot's ``phase_state`` key drives the
    PhaseSpine in the dashboard shell. Each ``phase_start`` event flips its
    phase to ``running``; each ``phase_done`` event flips it to ``done`` and
    locks in the final ``agents_completed`` / ``agents_total`` numbers from
    the event payload. ``current_phase`` always points at the latest phase to
    have transitioned to ``running`` and not yet to ``done`` — if every
    started phase has also finished, ``current_phase`` snaps back to the
    most recent ``running``-then-``done`` phase so the spine still shows
    where the swarm last was. ``current_phase`` is ``None`` only on the
    cold-start path (no ``phase_*`` event has been written yet).

    Returns the cold-start ``_empty_phase_state()`` shape when ``scan_dir``
    is ``None``, the file is missing, or every line is malformed. Never
    raises — disk / parse failures are swallowed (warned at DEBUG level) so
    a corrupt events.jsonl never 500s the dashboard.

    Each phase state ∈ ``{"pending", "running", "done"}``. The four producer
    strings (``recon``, ``decompose``, ``parallel``, ``finalise``) are the
    canonical phase taxonomy — critic patch G1/P1.
    """
    state = _empty_phase_state()
    if scan_dir is None:
        return state
    path = scan_dir / "events.jsonl"
    if not path.is_file():
        return state
    current_phase: str | None = None
    last_running: str | None = None
    recon_probes = 0
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    rec = json.loads(stripped)
                except (ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(rec, dict):
                    continue
                kind = rec.get("kind")
                if kind == "recon_progress":
                    # Live capability-audit probe counter — surfaced on the
                    # recon pill so the dashboard shows recon working instead of
                    # a static "running" during the (otherwise silent) audit.
                    rp = rec.get("payload")
                    if isinstance(rp, dict):
                        sent = rp.get("probes_sent", 0)
                        if isinstance(sent, int) and sent > recon_probes:
                            recon_probes = sent
                    continue
                if kind not in ("phase_start", "phase_done"):
                    continue
                payload = rec.get("payload")
                if not isinstance(payload, dict):
                    continue
                phase = payload.get("phase")
                if phase not in _PHASE_NAMES:
                    continue
                # Pull the counter pair if present (Step 1 normalised these
                # onto every emit site). Missing values default to 0 so a
                # pre-Step-1 events.jsonl still parses without raising.
                try:
                    agents_completed = int(payload.get("agents_completed", 0) or 0)
                except (TypeError, ValueError):
                    agents_completed = 0
                try:
                    agents_total = int(payload.get("agents_total", 0) or 0)
                except (TypeError, ValueError):
                    agents_total = 0
                phase_slot = state["phases"][phase]
                if kind == "phase_start":
                    phase_slot["state"] = "running"
                    phase_slot["agents_completed"] = agents_completed
                    phase_slot["agents_total"] = agents_total
                    current_phase = phase
                    last_running = phase
                else:  # phase_done
                    phase_slot["state"] = "done"
                    phase_slot["agents_completed"] = agents_completed
                    phase_slot["agents_total"] = agents_total
                    # If the phase that just finished was the active one, the
                    # spine has no live ``running`` phase yet — keep the
                    # caption anchored to the most recently active phase so
                    # the pill highlight does not flicker back to ``recon``.
                    if current_phase == phase:
                        current_phase = None
    except OSError as exc:  # pragma: no cover — disk-level failure
        _LOG.debug("dashboard_view: events.jsonl read failed (%s)", exc)
        return _empty_phase_state()
    if current_phase is None and last_running is not None:
        current_phase = last_running
    state["current_phase"] = current_phase
    # Attach the live recon probe count so the PhaseSpine can caption the recon
    # pill ("N probes") while the audit runs.
    state["phases"]["recon"]["probes"] = recon_probes
    return state


def _assemble_logs_tail(scan_dir: Path | None) -> list[dict[str, Any]]:
    """Read ``<scan_dir>/events.jsonl`` and emit the locked log-tail shape.

    Each line is one ``SwarmEvent`` payload (see ``scan_store.event_to_payload``).
    We derive a ``level`` (``info`` / ``warn`` / ``error``) and a one-line
    ``summary`` from the event kind + payload so the Executive Logs tab can
    render a colour-coded feed without re-implementing the heuristics in Jinja.

    Uncapped as of 2026-06-01 — :data:`_LOGS_TAIL_CAP` is ``None`` so every
    event from ``events.jsonl`` reaches the renderer. The Logs tab's
    client-side filter toolbar is the operator's tool for navigating long
    runs. Returns an empty list when ``scan_dir`` is ``None`` or the file is
    missing. Never raises.
    """
    if scan_dir is None:
        return []
    path = scan_dir / "events.jsonl"
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                entry = _parse_event_line(stripped)
                if entry is not None:
                    out.append(entry)
    except OSError as exc:  # pragma: no cover — disk-level failure
        _LOG.debug("dashboard_view: events.jsonl read failed (%s)", exc)
        return []
    # No FIFO trim — cap removed 2026-06-01 (operator request). The list
    # stays chronological (append-only writer); the renderer iterates it in
    # full and the client-side filter is what the operator uses to find
    # specific events in a large log.
    return out


def _parse_event_line(raw: str) -> dict[str, Any] | None:
    """Parse a single ``events.jsonl`` line into the locked log entry shape.

    Returns ``None`` for malformed JSON or non-dict rows.
    """
    try:
        rec = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(rec, dict):
        return None
    kind = str(rec.get("kind", ""))
    agent = rec.get("agent")
    asi = rec.get("asi")
    decision = rec.get("decision")
    payload = rec.get("payload")
    payload_dict: dict[str, Any] = payload if isinstance(payload, dict) else {}
    level = _derive_log_level(kind, payload_dict)
    summary = _derive_log_summary(kind, payload_dict)
    payload_keys = sorted(str(k) for k in payload_dict)
    return {
        "timestamp_label": _timestamp_label(rec.get("timestamp")),
        "kind": kind,
        "agent": str(agent) if agent else "",
        "asi": str(asi) if asi else "",
        "decision": str(decision) if decision else "",
        "level": level,
        "summary": summary,
        "payload_keys": payload_keys,
    }


def _derive_log_level(kind: str, payload: dict[str, Any]) -> str:
    """Derive the log level from event kind + payload (locked rules).

    For ``kind == "log"`` records (Python logging handler output, see
    :class:`agent_guardian.server.partial_scan.JsonlLogHandler`), read
    ``payload["level"]`` and map Python log-level names to the renderer's
    four buckets — ``DEBUG`` → ``debug``, ``INFO`` → ``info``,
    ``WARNING``/``WARN`` → ``warn``, ``ERROR``/``CRITICAL`` → ``error``.
    Unknown values fall back to ``info``. All other ``kind`` values keep
    the original SwarmEvent heuristic.

    DEBUG used to collapse into the ``info`` bucket, hiding operator-opted-in
    debug events behind the INFO chip. Splitting it into its own bucket lets
    the Logs tab surface DEBUG events behind a dedicated, off-by-default
    filter chip — the renderer still emits every persisted DEBUG row, but
    the operator clicks "DEBUG" to drill in.
    """
    if kind == "log":
        raw_level = str(payload.get("level", "")).strip().upper()
        if raw_level == "DEBUG":
            return "debug"
        if raw_level in ("WARNING", "WARN"):
            return "warn"
        if raw_level in ("ERROR", "CRITICAL"):
            return "error"
        return "info"
    if kind == "agent_skipped":
        return "warn"
    if kind == "error" or bool(payload.get("error")):
        return "error"
    return "info"


def _derive_log_summary(kind: str, payload: dict[str, Any]) -> str:
    """Derive the one-line log summary (locked priority order).

    For ``kind == "log"`` records, return ``"<logger> — <message>"`` (no
    ``"log :: "`` prefix — the level pill already conveys the level and the
    kind pill is hidden by the renderer). If the logger name is missing,
    just return ``message``. If ``exc_info`` is present and the message is
    short, append the first traceback line. All other ``kind`` values keep
    the original SwarmEvent priority order (severity → reason → message →
    bare kind).
    """
    if kind == "log":
        message = str(payload.get("message", "")).strip()
        logger = str(payload.get("logger", "")).strip()
        if logger and message:
            return f"{logger} — {message}"
        if message:
            return message
        return logger or "log"
    severity = payload.get("severity")
    if severity:
        return f"{kind} :: severity={severity}"
    reason = payload.get("reason")
    if reason:
        return f"{kind} :: {reason}"
    raw_message = payload.get("message")
    if raw_message:
        return f"{kind} :: {raw_message}"
    return kind


def _timestamp_label(raw: Any) -> str:
    """Render an ISO-8601 timestamp string as ``HH:MM:SS`` UTC.

    Returns an empty string when ``raw`` is missing / not a string / unparseable.
    """
    if not isinstance(raw, str) or not raw:
        return ""
    try:
        # Tolerate both ``Z`` and explicit offsets.
        normalised = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalised)
    except ValueError:
        return ""
    return dt.strftime("%H:%M:%S")


def _probes_estimate(scan: Scan | None) -> int:
    """Best-effort probe-count estimate from completeness if present."""
    if scan is None:
        return 0
    if scan.completeness is not None:
        return scan.completeness.turns_used
    return len(scan.findings) * 4  # rough fallback


def _humanise_int(n: int) -> str:
    """Render large integers compactly: 1247 → '1,247', 820000 → '820k', 2_000_000 → '2M'."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M".rstrip("0").rstrip(".")
    if n >= 10_000:
        return f"{n // 1000}k"
    return f"{n:,}"


def live_snapshot(ctx: DashboardContext) -> dict[str, Any]:
    """Subset of the context the SSE ``snapshot`` event emits.

    Only the ``data-live=*`` keys are sent over the wire — the static template
    holds everything else.

    SSE Phase 1, Step 2 — ``phase_state`` and ``started_at_unix`` are surfaced
    at the top level so the PhaseSpine + ElapsedTicker client modules read
    them straight off the snapshot without a second fetch. ``phase_state``
    carries the four-phase machine (recon / decompose / parallel /
    finalise) replayed from ``events.jsonl``; ``started_at_unix`` is the
    float-seconds anchor for the elapsed ticker. Both default to a safe
    cold-start shape when the in-flight scan has not yet produced any phase
    boundaries.
    """
    p = ctx.payload
    counts = p.get("counts", {})
    snapshot: dict[str, Any] = {
        "aivss": p.get("aivss_label"),
        # QA-065 (2026-06-04) — the standalone BAND tile (``data-live="band"``)
        # was removed; the band label now lives only on the AIVSS tile's
        # sub-caption, which the snapshot patcher targets via ``band-sub``.
        "band-sub": p.get("band_label"),
        "needle": p.get("needle_pct"),
        "aivss-total": p.get("aivss_label"),
        "elapsed": p.get("elapsed_label"),
        "elapsed-bar": p.get("elapsed_pct"),
        "probes": p.get("probes_label"),
        "probes-bar": p.get("probes_pct"),
        # QA-066 (2026-06-04) — PROBES KPI tile live keys. The count climbs as
        # memory.jsonl gains turn records mid-scan; the agent sub-caption
        # updates as new agents come online.
        "probes-count": p.get("probes_executed"),
        "probes-agents": p.get("probes_agents_label"),
        "tokens": p.get("tokens_label"),
        "tokens-bar": p.get("tokens_pct"),
        "usd": p.get("usd_label"),
        "usd-bar": p.get("usd_pct"),
        "findings": p.get("findings_total"),
        "findings-total": p.get("findings_total"),
        "asi-covered": f"{p.get('asi_covered', 0)} / 10",
        # QA-069 (2026-06-04) — per-category ASI radar values, aligned 1:1 with
        # the radar's fixed axis order (``asi_rows`` order). Pending categories
        # plot at 0. ``executive_charts.js`` reads this off the snapshot and
        # updates the radar dataset in place so the shape fills in live instead
        # of staying frozen at its first-paint state until an F5.
        "asi_radar": [
            0.0 if row.get("is_pending") else row.get("score_pct", 0.0)
            for row in p.get("asi_rows", [])
        ],
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        # SSE Phase 1, Step 2 — top-level snapshot additions.
        "phase_state": p.get("phase_state") or _empty_phase_state(),
        "started_at_unix": p.get("started_at_unix"),
    }
    return snapshot


def asi_categories() -> Iterable[AsiCategory]:
    """Public re-export for callers that need the canonical list of ASI codes."""
    return list(AsiCategory)


def asi_human_label(code: str) -> str:
    """Return the canonical human-readable name for an ASI code (e.g. ``ASI01``)."""
    return asi_description(AsiCategory(code))
