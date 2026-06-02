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
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from agent_guardian.models.asi import AsiCategory, asi_description
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
_BAND_LABELS: Final[Mapping[SeverityBand, str]] = {
    SeverityBand.EXCELLENT: "Excellent",
    SeverityBand.GOOD: "Good",
    SeverityBand.WARNING: "Warning",
    SeverityBand.POOR: "Poor",
    SeverityBand.CRITICAL: "Critical",
    SeverityBand.NOT_EVALUATED: "NA",
}


def _humanise_band(band: SeverityBand | None) -> str:
    """Return a humanised, user-facing label for an AIVSS band.

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
_LOGS_TAIL_CAP: Final[int | None] = None

__all__ = [
    "DASHBOARD_TEMPLATE",
    "DashboardContext",
    "build_dashboard_context",
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


def _band_segment_index(band: SeverityBand | None) -> int:
    """Return the 0-4 segment index for the BAND tile mini-chart.

    QA-028 sub-ask 2: the BAND tile renders a 5-segment horizontal bar
    (Critical · Poor · Warning · Good · Excellent, left → right). The
    highlighted segment matches the current band. ``-1`` for an
    unknown / not-evaluated band so the partial renders an all-muted
    bar with no active segment.
    """
    mapping = {
        SeverityBand.CRITICAL: 0,
        SeverityBand.POOR: 1,
        SeverityBand.WARNING: 2,
        SeverityBand.GOOD: 3,
        SeverityBand.EXCELLENT: 4,
    }
    if band is None:
        return -1
    return mapping.get(band, -1)


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
    scan: Scan | None,
    counts: dict[str, int],
    findings_total: int,
    asi_rows: list[dict[str, Any]],
    elapsed: float,
    elapsed_label: str,
    asi_covered: int,
) -> dict[str, list[dict[str, str]]]:
    """Build the per-tile hover data-table payload.

    QA-044 (2026-06-02) — every KPI tile now reveals a small data table
    on hover. Rather than build the strings in Jinja, we assemble them
    here so the row order is deterministic and unit-testable.

    Each value is a plain dict ``{"label": str, "value": str}`` (no
    ``class`` is needed today; the field is reserved for future
    severity-tinted rows).
    """
    score_val = float(scan.aivss) if scan is not None else 0.0
    cost_total = float(scan.cost_usd) if scan is not None else 0.0
    tokens_total = int(scan.tokens_total) if scan is not None else 0

    # AIVSS — top 5 ASI sub-scores so the hover table fits the tile width.
    aivss_rows: list[dict[str, str]] = []
    for row in asi_rows[:5]:
        aivss_rows.append(
            {"label": str(row.get("code", "—")), "value": f"{row.get('score_label', '—')}"}
        )
    aivss_rows.append({"label": "Composite", "value": f"{score_val:.0f}"})

    # BAND — the threshold scale (mirrors the gauge bands).
    band_rows: list[dict[str, str]] = [
        {"label": "Critical", "value": "0-39"},
        {"label": "Poor", "value": "40-59"},
        {"label": "Warning", "value": "60-79"},
        {"label": "Good", "value": "80-89"},
        {"label": "Excellent", "value": "90-100"},
    ]

    # FINDINGS — severity counts.
    findings_rows: list[dict[str, str]] = [
        {"label": "Critical", "value": str(counts.get("critical", 0))},
        {"label": "High", "value": str(counts.get("high", 0))},
        {"label": "Medium", "value": str(counts.get("medium", 0))},
        {"label": "Low", "value": str(counts.get("low", 0))},
        {"label": "Total", "value": str(findings_total)},
    ]

    # ELAPSED — best-effort phase split. The Scan model does not surface
    # per-phase wall-clock today; we approximate from the overall elapsed
    # so the tile renders something meaningful while the real per-phase
    # roll-up is being threaded through (TODO: wire ``scan.audit['phases']``
    # when the swarm runner emits it).
    elapsed_rows: list[dict[str, str]] = [
        {"label": "Total", "value": elapsed_label},
    ]
    if elapsed > 0:
        # 15/55/30 split is the historical AIVSS test-runner ratio
        # (commander dispatch vs attacker probes vs evaluator grading);
        # used here as a presentation default — replace once the runner
        # surfaces real per-phase durations.
        elapsed_rows.append(
            {"label": "Commander", "value": _humanise_seconds(elapsed * 0.15)}
        )
        elapsed_rows.append(
            {"label": "Attacker", "value": _humanise_seconds(elapsed * 0.55)}
        )
        elapsed_rows.append(
            {"label": "Evaluator", "value": _humanise_seconds(elapsed * 0.30)}
        )

    # COST — token-spend by phase (same caveat as elapsed).
    cost_rows: list[dict[str, str]] = [
        {"label": "Total", "value": f"$ {cost_total:.2f}"},
        {"label": "Tokens", "value": _humanise_int(tokens_total)},
    ]
    if cost_total > 0:
        cost_rows.append(
            {"label": "Commander", "value": f"$ {cost_total * 0.15:.2f}"}
        )
        cost_rows.append(
            {"label": "Attacker", "value": f"$ {cost_total * 0.55:.2f}"}
        )
        cost_rows.append(
            {"label": "Evaluator", "value": f"$ {cost_total * 0.30:.2f}"}
        )

    # COVERAGE — per-ASI status (the 10 OWASP categories).
    coverage_rows: list[dict[str, str]] = []
    for row in asi_rows:
        coverage_rows.append(
            {
                "label": str(row.get("code", "—")),
                "value": (
                    "covered"
                    if sum((row.get("findings") or {}).values()) > 0
                    else "—"
                ),
            }
        )
    coverage_rows.append(
        {"label": "Covered", "value": f"{asi_covered}/10"}
    )

    return {
        "aivss": aivss_rows,
        "band": band_rows,
        "findings": findings_rows,
        "elapsed": elapsed_rows,
        "cost": cost_rows,
        "coverage": coverage_rows,
    }


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
        # so the counts and the colours can never disagree.
        stats = {"fail": 0, "pass": 0, "inconclusive": 0, "unknown": 0}
        for p in capped:
            v = str(p.get("verdict") or "")
            if v in ("fail", "pass", "inconclusive"):
                stats[v] += 1
            else:
                stats["unknown"] += 1
        item["evidence"] = capped
        item["evidence_total"] = total
        item["evidence_truncated"] = total > _FINDING_EVIDENCE_CAP
        item["evidence_stats"] = stats


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
    asi_dot_states = _asi_dot_states(scan, findings_by_asi)
    asi_covered = sum(1 for b in findings_by_asi.values() if sum(b.values()) > 0)

    if scan is not None:
        commander_model = _engine_field(scan, "commander", "stub")
        attacker_model = _engine_field(scan, "attacker", "stub")
        evaluator_model = _engine_field(scan, "evaluator", "stub")
    else:
        commander_model = attacker_model = evaluator_model = "—"

    elapsed = (
        elapsed_seconds
        if elapsed_seconds is not None
        else (scan.duration_seconds if scan is not None else 0.0)
    )

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
        # QA-039 / QA-044 (2026-06-02) — these prose explainers are now
        # surfaced behind the ``ⓘ`` button (separate from the hover data
        # table). They are deliberately rendered in sentence case + body
        # type (see ``.kpi-info-popover`` in executive.css); the previous
        # ALL-CAPS + tight letter-spacing look was dropped.
        "kpi_descriptions": {
            "aivss": (
                "Composite agent safety score (0-100). A weighted average "
                "across the ten OWASP ASI sub-scores, blended with the "
                "tier-specific scoring formula."
            ),
            "band": (
                "Risk tier mapped from the AIVSS composite. Thresholds "
                "are 0-39 critical, 40-59 poor, 60-79 warning, 80-89 good, "
                "90-100 excellent."
            ),
            "findings": (
                "Total exploit attempts the evaluator graded as valid. "
                "Hover the tile for the per-severity breakdown."
            ),
            "elapsed": (
                "Wall-clock duration of the scan from the first probe "
                "dispatch through the final evaluator verdict."
            ),
            "cost": (
                "Estimated model spend in USD for this scan, summed "
                "across the commander, attacker, and evaluator phases."
            ),
            "coverage": (
                "Probe categories exercised out of the ten OWASP ASI "
                "dimensions. Hover the tile for the per-category status."
            ),
        },
        # QA-044 (2026-06-02) — structured hover data tables. Each entry
        # is a list of ``{label, value, class?}`` dicts that ``_kpi_strip.html``
        # renders as a small table inside ``.exec-kpi__hover-table``. We
        # build it here rather than in Jinja so the row order stays Python-
        # sorted and the breakdown matches what unit tests assert against.
        "kpi_hover_tables": _build_kpi_hover_tables(
            scan=scan,
            counts=counts,
            findings_total=findings_total,
            asi_rows=asi_rows,
            elapsed=elapsed,
            elapsed_label=_humanise_seconds(elapsed),
            asi_covered=asi_covered,
        ),
        # QA-028 sub-ask 2 — per-tile inline-SVG mini-charts. The KPI strip
        # template reads this dict to draw a 64px-tall visualisation inside
        # each tile (radial gauge / band axis segment / stacked severity bar
        # / progress bar / pie segments). Fields are derived from existing
        # payload values; no new sources of truth.
        "kpi_chart_data": {
            "aivss_pct": _fmt_pct(float(scan.aivss)) if scan is not None else 0.0,
            "band_index": _band_segment_index(scan.band if scan is not None else None),
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
        "tokens_label": _humanise_int(scan.tokens_total if scan is not None else 0),
        "tokens_cap_label": "2 M",
        "tokens_pct": _fmt_pct(
            ((scan.tokens_total / 2_000_000.0) * 100.0) if scan is not None else 0.0
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
        # memory.jsonl twice per render.
        "probes_list": _probes_list_for_evidence,
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
        "recon_summary": _assemble_recon_summary(scan_dir),
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
          "profile_source": str,
          "profile_confidence": float,
          "system_prompt_clues": str,   # truncated notes/clue field
          "system_prompt_clues_full": str,  # full text for "view raw"
          "skipped_agents": list[{agent, asi, reason}],
        }

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
        "profile_source": "",
        "profile_confidence": 0.0,
        "system_prompt_clues": "",
        "system_prompt_clues_full": "",
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
                        skipped.append(
                            {
                                "agent": str(payload.get("agent", "")),
                                "asi": str(payload.get("asi", "")),
                                "reason": str(payload.get("reason", "")),
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
    notes_full = str(latest_fp.get("notes") or "")
    # Truncate clues to ~160 chars for the inline render; the full text
    # lives behind the <details> raw view.
    if len(notes_full) > 160:
        clues_short = notes_full[:160].rsplit(" ", 1)[0] + "…"
    else:
        clues_short = notes_full
    return {
        "has_data": True,
        "framework_family": (
            str(latest_fp.get("framework"))
            if latest_fp.get("framework")
            else "Unknown"
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
        "profile_source": str(latest_fp.get("profile_source") or "heuristic"),
        "profile_confidence": float(latest_fp.get("profile_confidence") or 0.0),
        "system_prompt_clues": clues_short,
        "system_prompt_clues_full": notes_full,
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
    timestamp_label = _timestamp_label(rec.get("timestamp"))
    seed_id = turn.get("seed_id")
    probe_id = str(seed_id) if seed_id else ""
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
    }


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
    """
    p = ctx.payload
    counts = p.get("counts", {})
    snapshot: dict[str, Any] = {
        "aivss": p.get("aivss_label"),
        "band": p.get("band_label"),
        "needle": p.get("needle_pct"),
        "aivss-total": p.get("aivss_label"),
        "elapsed": p.get("elapsed_label"),
        "elapsed-bar": p.get("elapsed_pct"),
        "probes": p.get("probes_label"),
        "probes-bar": p.get("probes_pct"),
        "tokens": p.get("tokens_label"),
        "tokens-bar": p.get("tokens_pct"),
        "usd": p.get("usd_label"),
        "usd-bar": p.get("usd_pct"),
        "findings": p.get("findings_total"),
        "findings-total": p.get("findings_total"),
        "asi-covered": f"{p.get('asi_covered', 0)} / 10",
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
    }
    return snapshot


def asi_categories() -> Iterable[AsiCategory]:
    """Public re-export for callers that need the canonical list of ASI codes."""
    return list(AsiCategory)


def asi_human_label(code: str) -> str:
    """Return the canonical human-readable name for an ASI code (e.g. ``ASI01``)."""
    return asi_description(AsiCategory(code))
