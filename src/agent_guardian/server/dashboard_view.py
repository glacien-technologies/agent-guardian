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

Theme switcher (QA-020)
-----------------------

The :func:`resolve_theme` helper decides which Jinja root template the route
hands the shared view-model to. The view-model itself is theme-agnostic — all
four themes consume the exact same payload dict produced by
:func:`build_dashboard_context`. The route calls :func:`resolve_theme` to pick
between the four locked template paths:

* ``editorial`` → ``dashboard/scan_detail.html`` (UNCHANGED current design)
* ``mission``   → ``dashboard/mission/layout.html``
* ``narrative`` → ``dashboard/narrative/layout.html``
* ``ide``       → ``dashboard/ide/layout.html``

Precedence is: query param ``?theme=`` > ``$AGENT_GUARDIAN_DASHBOARD_THEME``
env var > ``editorial`` default. Invalid theme names (including empty strings,
typos, or names not in the locked set) fall through silently to the next
priority — never raise. This guarantees a request without ``?theme=`` is
byte-for-byte equivalent to the pre-QA-020 behaviour.
"""

from __future__ import annotations

import json
import logging
import math
import os
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

# Caps on the assembled lists. The probes_list is bounded so a long-running
# scan doesn't blow the page render time; the logs_tail is FIFO-trimmed so
# the operator always sees the most recent events. Both values are locked in
# the design doc (DESIGN_LOCK §3.3).
_PROBES_LIST_CAP: Final[int] = 500
_LOGS_TAIL_CAP: Final[int] = 1000

__all__ = [
    "AGENT_GUARDIAN_DASHBOARD_THEME_ENV",
    "DASHBOARD_THEMES",
    "DASHBOARD_THEME_DEFAULT",
    "DASHBOARD_THEME_TEMPLATES",
    "DashboardContext",
    "build_dashboard_context",
    "resolve_locality",
    "resolve_theme",
    "resolve_theme_from_env",
]


# Theme registry — single source of truth for slugs, env-var name, default,
# and template path. Routes import these constants; never hard-code a slug.
AGENT_GUARDIAN_DASHBOARD_THEME_ENV: Final[str] = "AGENT_GUARDIAN_DASHBOARD_THEME"
DASHBOARD_THEME_DEFAULT: Final[str] = "editorial"
DASHBOARD_THEMES: Final[tuple[str, ...]] = (
    "editorial",
    "mission",
    "narrative",
    "ide",
    "executive",
)
DASHBOARD_THEME_TEMPLATES: Final[Mapping[str, str]] = {
    "editorial": "dashboard/scan_detail.html",
    "mission": "dashboard/mission/layout.html",
    "narrative": "dashboard/narrative/layout.html",
    "ide": "dashboard/ide/layout.html",
    "executive": "dashboard/executive/layout.html",
}


def resolve_theme(
    query_theme: str | None,
    env_value: str | None,
) -> str:
    """Resolve the active dashboard theme slug.

    Precedence (LOCKED — do not reorder):

    1. ``query_theme`` — the ``?theme=`` query-string parameter from the
       incoming request. ``None`` means the query string was absent.
    2. ``env_value`` — the value of ``$AGENT_GUARDIAN_DASHBOARD_THEME`` (or
       any caller-supplied operator-default). ``None`` means unset.
    3. :data:`DASHBOARD_THEME_DEFAULT` (``"editorial"``).

    Invalid theme names (not in :data:`DASHBOARD_THEMES`, including the empty
    string and any whitespace-only value) fall through *silently* to the next
    priority — never raise. The caller can rely on the return value always
    being one of :data:`DASHBOARD_THEMES`.

    The function is pure (no ``os.environ`` reads, no I/O) so the route can
    test it in isolation and the env-var resolution is the route's
    responsibility. A small convenience wrapper, :func:`resolve_theme_from_env`,
    handles the env lookup for production callers.
    """
    candidates: tuple[str | None, ...] = (query_theme, env_value)
    for raw in candidates:
        if raw is None:
            continue
        normalised = raw.strip().lower()
        if normalised in DASHBOARD_THEMES:
            return normalised
    return DASHBOARD_THEME_DEFAULT


def resolve_theme_from_env(query_theme: str | None) -> str:
    """Production helper — reads the env var, then delegates to :func:`resolve_theme`.

    Kept separate from :func:`resolve_theme` so unit tests can drive the pure
    function without monkeypatching ``os.environ``.
    """
    env_raw = os.environ.get(AGENT_GUARDIAN_DASHBOARD_THEME_ENV)
    return resolve_theme(query_theme, env_raw)


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
        status_label, status_class = _status_for_row(scan, is_pending, score_val)
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


def _status_for_row(scan: Scan | None, is_pending: bool, score: float) -> tuple[str, str]:
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

    Findings are sorted critical → high → medium → low, then by creation time.
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
    sorted_findings = sorted(scan.findings, key=lambda f: (sev_rank[f.severity], f.created_at))
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
        band_label = scan.band.value
        band_class = _band_class(scan.band)
        needle_pct = _aivss_to_needle(scan.aivss)
        aggregate = scan.aivss + counts["critical"] * 2 + counts["high"] * 0.4
        score_sublabel = "tier-weighted, signed evidence"
    else:
        aivss_label = "—"
        band_label = "PENDING"
        band_class = "unknown"
        needle_pct = None
        aggregate = 0.0
        score_sublabel = "tier-weighted, provisional"

    asi_rows = _asi_rows(scan, findings_by_asi)
    findings_page, pagination = _findings_page(scan, page=page, per_page=per_page)
    asi_dot_states = _asi_dot_states(scan, findings_by_asi)
    asi_covered = sum(1 for code, b in findings_by_asi.items() if sum(b.values()) > 0)

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
        "probes_list": _assemble_probes_list(scan_dir),
        "logs_tail": _assemble_logs_tail(scan_dir),
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

    FIFO-capped at :data:`_LOGS_TAIL_CAP` entries — keeps the most recent
    ``N``. Returns an empty list when ``scan_dir`` is ``None`` or the file is
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
    # FIFO tail — drop oldest beyond the cap so the operator always sees the
    # freshest events. The list is already chronological (append-only writer).
    if len(out) > _LOGS_TAIL_CAP:
        out = out[-_LOGS_TAIL_CAP:]
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
    """Derive the log level from event kind + payload (locked rules)."""
    if kind == "agent_skipped":
        return "warn"
    if kind == "error" or bool(payload.get("error")):
        return "error"
    return "info"


def _derive_log_summary(kind: str, payload: dict[str, Any]) -> str:
    """Derive the one-line log summary (locked priority order)."""
    severity = payload.get("severity")
    if severity:
        return f"{kind} :: severity={severity}"
    reason = payload.get("reason")
    if reason:
        return f"{kind} :: {reason}"
    message = payload.get("message")
    if message:
        return f"{kind} :: {message}"
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
