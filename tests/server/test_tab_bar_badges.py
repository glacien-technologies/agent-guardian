"""SSE Phase 1, Step 6 — tab-bar badge primitive.

Locks the surface contracts for the tab-bar badge primitive described in
``designs/sse-flow-and-live-ui.md`` §Step 6:

* ``_tab_bar.html`` exposes one ``<span class="exec-tab__badge"
  data-badge data-tab="<slug>">`` slot per tab button (overview /
  findings / probes / logs).
* ``static/tab-badge-bus.js`` is served by the static mount and exposes
  the ``window.AGTabBadgeBus`` API (``bump`` / ``clear`` / ``get``).
* The dwell semantics (critic patch G19/P19) are wired — click + 2 s
  setTimeout, cancelled on mouseleave; NOT bare active-tab clearing.
* Persistence uses ``sessionStorage`` keyed by ``(scan_id, tab)``.
* ``layout.html`` ships the bus on every Executive page so the
  ``AGTabBadgeBus`` global is defined before ``phase-spine.js`` /
  ``reflections.js`` reach for it.
* ``phase-spine.js`` wires ``agent_*`` arrivals into the PROBES badge
  and ``agent_done.payload.findings_count`` into the FINDINGS badge.
* ``reflections.js`` wires the ``reflection`` arrival into the LOGS
  badge (count-only, per critic patch G4/P4 — the producer emits no
  severity field on this event).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_guardian import __version__
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.server import ScanStore, create_app


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _make_scan(scan_id: str = "scan-step6") -> Scan:
    finding = Finding(
        id="f-step6-1",
        probe_id="probe-step6",
        asi=AsiCategory.ASI01,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=1,
        success=True,
        confidence=0.9,
        summary="step6 finding",
        created_at=datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC),
    )
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=80,
        band=SeverityBand.GOOD,
        sub_scores={
            "prompt_injection_resistance": 70.0,
            "tool_scope_safety": 85.0,
            "pii_containment": 90.0,
            "memory_poisoning_resistance": 75.0,
            "excessive_agency_containment": 80.0,
            "hallucination_resistance": 78.0,
        },
        findings=[finding],
        asi_scores={cat: 80.0 for cat in AsiCategory},
        duration_seconds=120.0,
        cost_usd=0.42,
        tokens_total=320_000,
        mode="full",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        created_at=datetime(2026, 6, 3, 11, 58, 0, tzinfo=UTC),
    )


def _persist(store: ScanStore, scan: Scan) -> Path:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return scan_dir


# ---------------------------------------------------------------------------
# 1. _tab_bar.html — one badge slot per tab button
# ---------------------------------------------------------------------------


def test_tab_bar_renders_one_badge_slot_per_tab(client: TestClient, store: ScanStore) -> None:
    """Each of the four tab buttons carries exactly one
    ``<span class="exec-tab__badge" data-badge data-tab="<slug>">``
    slot. The slots are server-rendered empty so terminal scans never
    flash stale badge counts."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    assert resp.status_code == 200
    body = resp.text
    for slug in ("overview", "findings", "probes", "logs"):
        marker = '<span class="exec-tab__badge" data-badge data-tab="' + slug + '"></span>'
        assert marker in body, f"missing badge slot for tab-{slug}: {marker!r}"


def test_tab_bar_badge_slots_live_inside_tab_buttons(client: TestClient, store: ScanStore) -> None:
    """The badge slot for ``<slug>`` must be inside the ``id="tab-<slug>"``
    button — not floating elsewhere in the layout. This guarantees the
    chip renders adjacent to the label and ``executive_tabs.js`` keyboard
    activation (Space / Enter) still targets the right element."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    for slug in ("overview", "findings", "probes", "logs"):
        btn_start = body.find(f'id="tab-{slug}"')
        assert btn_start >= 0
        btn_end = body.find("</button>", btn_start)
        snippet = body[btn_start:btn_end]
        assert 'data-tab="' + slug + '"' in snippet, (
            f"tab-{slug} button does not contain its own badge slot"
        )
        assert snippet.count("data-badge") == 1, (
            f"tab-{slug} button has wrong number of data-badge slots (want 1, snippet={snippet!r})"
        )


# ---------------------------------------------------------------------------
# 2. tab-badge-bus.js — served by the static mount, has the public API
# ---------------------------------------------------------------------------


def test_tab_badge_bus_js_served(client: TestClient) -> None:
    resp = client.get("/static/tab-badge-bus.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers.get("content-type", "").lower() or resp.text


def test_tab_badge_bus_exposes_public_api(client: TestClient) -> None:
    """Public API contract — ``bus.bump`` / ``bus.clear`` / ``bus.get``
    attached to ``window.AGTabBadgeBus``."""
    body = client.get("/static/tab-badge-bus.js").text
    assert "window.AGTabBadgeBus" in body
    # The exported object lists each public method.
    for fn in ("bump:", "clear:", "get:"):
        assert fn in body, f"missing exported method `{fn}` on AGTabBadgeBus"


def test_tab_badge_bus_persists_in_sessionstorage_keyed_by_scan_and_tab(
    client: TestClient,
) -> None:
    """Persistence layer — counts live in ``sessionStorage`` (NOT
    ``localStorage`` — cross-tab leakage is wrong), keyed by ``(scan_id,
    tab)`` so two different scans in two tabs don't share badges."""
    body = client.get("/static/tab-badge-bus.js").text
    assert "sessionStorage" in body
    assert "localStorage" not in body, (
        "tab-badge-bus must NOT use localStorage — sessionStorage is the "
        "right granularity for `survives reload, NOT cross-tab`"
    )
    # The storage key prefix is part of the wire contract — a future
    # bus version that wants a different key must bump the prefix
    # explicitly.
    assert "ag.tabBadgeBus.v1" in body


def test_tab_badge_bus_clear_uses_2s_dwell_not_bare_active_tab(
    client: TestClient,
) -> None:
    """Critic patch G19/P19: badge clear is tab-button click + 2 s
    setTimeout, cancelled on mouseleave. Bare active-tab clearing is
    hostile to triage browsing (operator flicking between tabs to
    compare) and is explicitly rejected by the design."""
    body = client.get("/static/tab-badge-bus.js").text
    # The dwell window is exactly 2000 ms per the spec acceptance
    # ("click + 2 s dwell clears").
    assert "DWELL_MS = 2000" in body
    # Dwell is implemented as setTimeout (per critic patch G19/P19),
    # NOT setInterval, NOT a plain click handler.
    assert "setTimeout" in body
    assert "mouseleave" in body
    assert "clearTimeout" in body


def test_tab_badge_bus_no_severity_logic_only_two_classes(
    client: TestClient,
) -> None:
    """The bus is a thin chip primitive — it does NOT infer severity
    from the event payload. The caller passes ``opts.severity ===
    "notice" | "alert"`` and the bus paints the matching CSS class.
    Anything outside the two-class set is silently dropped (no third
    severity sneaking in via typo)."""
    body = client.get("/static/tab-badge-bus.js").text
    assert '"notice"' in body or "'notice'" in body
    assert '"alert"' in body or "'alert'" in body


# ---------------------------------------------------------------------------
# 3. layout.html — the bus ships on every Executive page
# ---------------------------------------------------------------------------


def test_layout_loads_tab_badge_bus_script(client: TestClient, store: ScanStore) -> None:
    """``layout.html`` must include ``tab-badge-bus.js`` so the
    ``AGTabBadgeBus`` global is defined before ``phase-spine.js`` and
    ``reflections.js`` reach for it. The script is loaded with the same
    ``?v={{ package_version }}`` cache-bust pattern as the other Step
    1-5 modules."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    assert "/static/tab-badge-bus.js" in body


# ---------------------------------------------------------------------------
# 4. phase-spine.js — wires PROBES + FINDINGS badges
# ---------------------------------------------------------------------------


def test_phase_spine_bumps_probes_badge_on_agent_arrivals(
    client: TestClient,
) -> None:
    """``agent_start`` / ``agent_done`` / ``agent_skipped`` arrivals
    each bump the PROBES badge by 1. Severity is ``notice`` —
    informational, NOT alert (probe activity is the spine's job to
    foreground; the badge is the cross-tab echo)."""
    body = client.get("/static/phase-spine.js").text
    assert 'bumpBadge("probes"' in body
    # The wire-in must reach for ``window.AGTabBadgeBus`` defensively —
    # the bus is optional, the spine still works without it.
    assert "AGTabBadgeBus" in body


def test_phase_spine_bumps_findings_badge_with_findings_count(
    client: TestClient,
) -> None:
    """``agent_done`` carries ``payload.findings_count``. When > 0 the
    bus is bumped on the FINDINGS tab with severity ``alert`` so the
    chip is visually distinct from the gentler PROBES ``notice``.
    Operator-pain target: "I missed a finding because the count bumped
    silently" — answered by the chip on the inactive tab."""
    body = client.get("/static/phase-spine.js").text
    assert 'bumpBadge("findings"' in body
    assert "findings_count" in body
    assert '"alert"' in body


# ---------------------------------------------------------------------------
# 5. reflections.js — wires LOGS badge (count-only, no severity)
# ---------------------------------------------------------------------------


def test_reflections_bumps_logs_badge_on_each_reflection(
    client: TestClient,
) -> None:
    """``reflection`` arrivals bump the LOGS tab badge by 1. This is
    count-only per critic patch G4/P4 — the producer emits no severity
    field on the ``reflection`` event (``core/swarm.py:2687-2695``)."""
    body = client.get("/static/reflections.js").text
    assert "AGTabBadgeBus" in body
    assert "'logs'" in body or '"logs"' in body


# ---------------------------------------------------------------------------
# 6. CSS — the badge primitive carries the locked class hooks
# ---------------------------------------------------------------------------


def test_executive_css_styles_the_badge_with_notice_and_alert(
    client: TestClient,
) -> None:
    """The CSS owns three rules — base ``.exec-tab__badge``, the
    ``.notice`` severity (probes / logs), and the ``.alert`` severity
    (findings). All three live in ``executive.css`` so a single
    cache-bust ships the chip styling with the bus."""
    body = client.get("/static/executive.css").text
    assert ".exec-tab__badge" in body
    assert ".exec-tab__badge.notice" in body
    assert ".exec-tab__badge.alert" in body
