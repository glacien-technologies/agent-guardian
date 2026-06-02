"""QA-023 — Executive Dashboard (Theme E) rendering tests.

Covers:

* Route returns 200 for ``?theme=executive``.
* Sticky topbar + KPI strip + WAI-ARIA tab bar render with the locked
  positioning and DOM marker classes.
* 4 tab panels render with the locked WAI-ARIA roles, ids, ``aria-selected``
  / ``aria-controls`` / ``aria-labelledby`` / ``tabindex`` attributes
  (Overview / Findings / Probes / Logs — the Agents tab was deleted in
  QA-030; its per-ASI breakdown lives on Overview via QA-033).
* The locked literal heading ``All findings so far.`` appears inside the
  Findings tabpanel.
* ``probes_list`` payload (from ``memory.jsonl``) is rendered into the
  Probes tab; ``logs_tail`` (from ``events.jsonl``) is rendered into the
  Logs tab.
* The ``clean_control`` sentry is preserved: a scan with zero findings,
  zero probes, and zero log events still renders all 4 panes with the
  locked empty-state copy.
* The shared theme switcher dropdown carries the 5th option
  ``Executive Dashboard``.
* The Executive entry stylesheet + tab JS are served by the static mount.
"""

from __future__ import annotations

import json
import re
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

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _make_finding(
    fid: str,
    severity: Severity,
    asi: AsiCategory = AsiCategory.ASI01,
) -> Finding:
    return Finding(
        id=fid,
        probe_id=f"probe-{fid}",
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=severity,
        attempt_count=2,
        success=True,
        confidence=0.91,
        summary=f"finding {fid}: prompt injection observed",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
    )


def _make_scan(scan_id: str = "cli-executive-001", *, with_findings: bool = True) -> Scan:
    findings: list[Finding] = []
    if with_findings:
        findings = [
            _make_finding("f-crit-1", Severity.CRITICAL, AsiCategory.ASI01),
            _make_finding("f-high-1", Severity.HIGH, AsiCategory.ASI02),
            _make_finding("f-med-1", Severity.MEDIUM, AsiCategory.ASI03),
        ]
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=84,
        band=SeverityBand.GOOD,
        sub_scores={
            "prompt_injection_resistance": 72.0,
            "tool_scope_safety": 88.0,
            "pii_containment": 95.0,
            "memory_poisoning_resistance": 68.0,
            "excessive_agency_containment": 84.0,
            "hallucination_resistance": 79.0,
        },
        findings=findings,
        asi_scores={cat: 80.0 for cat in AsiCategory},
        duration_seconds=252.0,
        cost_usd=0.84,
        tokens_total=820_000,
        mode="full",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=UTC),
    )


def _persist(store: ScanStore, scan: Scan) -> Path:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return scan_dir


def _seed_memory_jsonl(scan_dir: Path, *, count: int = 2) -> list[dict[str, object]]:
    """Write `count` reflection records to memory.jsonl and return the inner turn dicts."""
    turns: list[dict[str, object]] = []
    lines: list[str] = []
    for i in range(count):
        turn = {
            "agent": f"agent-{i}",
            "asi_category": "ASI01",
            "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
            "turn": i + 1,
            "strategy": "direct_injection",
            "prompt": f"verbatim attacker prompt {i}",
            "target_response": f"target response text {i}",
            "verdict": "vulnerable" if i % 2 == 0 else "robust",
            "confidence": 0.85,
            "reasoning": f"judge reasoning sample {i}",
            "seed_id": f"PROBE-{i:03d}",
            "attacker_refused": False,
        }
        record = {
            "timestamp": f"2026-05-27T12:{30 + i:02d}:00+00:00",
            "record_type": "reflection",
            "payload": {
                "agent": turn["agent"],
                "content": json.dumps(turn),
            },
        }
        turns.append(turn)
        lines.append(json.dumps(record))
    (scan_dir / "memory.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return turns


def _seed_events_jsonl(scan_dir: Path) -> list[dict[str, object]]:
    """Write 3 SwarmEvent payloads and return them."""
    events: list[dict[str, object]] = [
        {
            "kind": "scan_started",
            "agent": None,
            "asi": None,
            "provisional_aivss": None,
            "decision": None,
            "timestamp": "2026-05-27T12:00:00+00:00",
            "payload": {"message": "boot"},
        },
        {
            "kind": "agent_skipped",
            "agent": "asi02-tool",
            "asi": "ASI02",
            "provisional_aivss": 75,
            "decision": None,
            "timestamp": "2026-05-27T12:01:00+00:00",
            "payload": {"reason": "out of budget"},
        },
        {
            "kind": "finding_emitted",
            "agent": "asi01-goal",
            "asi": "ASI01",
            "provisional_aivss": 60,
            "decision": "continue",
            "timestamp": "2026-05-27T12:02:00+00:00",
            "payload": {"severity": "critical"},
        },
    ]
    lines = [json.dumps(ev) for ev in events]
    (scan_dir / "events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return events


# ---------------------------------------------------------------------------
# 1. Route smoke test
# ---------------------------------------------------------------------------


def test_executive_route_returns_200_with_seeded_scan(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    assert resp.status_code == 200
    assert 'data-theme="executive"' in resp.text


# ---------------------------------------------------------------------------
# 2. Sticky topbar + KPI strip
# ---------------------------------------------------------------------------


def test_executive_renders_topbar_and_kpi_strip(client: TestClient, store: ScanStore) -> None:
    """The sticky topbar + KPI strip render with the 6 remaining tile labels.

    QA-043 (2026-06-02) — CRITICAL + HIGH tiles dropped; the strip now ships
    six tiles (AIVSS / Band / Findings / Elapsed / Cost / Coverage) and the
    grid renders 6 columns.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # Topbar marker
    assert 'class="exec-topbar"' in body
    assert "AgentGuardian" in body
    # KPI strip marker + the 6 locked tile labels. Each label now lives
    # inside its eyebrow span beside an inline-SVG icon, so we check the
    # tile+label pair via a per-key regex instead of a tight ">Label<".
    assert 'class="exec-kpi-strip"' in body
    for key, label in (
        ("aivss", "AIVSS"),
        ("band", "Band"),
        ("findings", "Findings"),
        ("elapsed", "Elapsed"),
        ("cost", "Cost"),
        ("coverage", "Coverage"),
    ):
        pattern = re.compile(
            rf'data-kpi="{key}".*?<span class="exec-kpi__label">.*?{label}.*?</span>',
            re.DOTALL,
        )
        assert pattern.search(body), f"missing KPI tile {key!r} with label {label!r}"
    # And the dropped tiles are gone.
    assert 'data-kpi="critical"' not in body
    assert 'data-kpi="high"' not in body


def test_executive_sticky_css_loaded(client: TestClient) -> None:
    """The Executive stylesheet must be reachable through the /static mount."""
    resp = client.get("/static/executive.css")
    assert resp.status_code == 200
    body = resp.text
    # Sticky positioning is load-bearing for the 3-layer header.
    assert "position: sticky" in body
    assert ".exec-topbar" in body
    assert ".exec-kpi-strip" in body
    assert ".exec-tabbar" in body
    # Dark default + light variant
    assert "prefers-color-scheme" in body


def test_executive_tabs_js_loaded(client: TestClient) -> None:
    """The Executive tab JS must be reachable through the /static mount."""
    resp = client.get("/static/executive_tabs.js")
    assert resp.status_code == 200
    body = resp.text
    assert "aria-selected" in body
    assert "history.replaceState" in body
    assert "ag.dashboard.executive.tab" in body


# ---------------------------------------------------------------------------
# 3. WAI-ARIA tablist + tabpanels
# ---------------------------------------------------------------------------


def test_executive_renders_4_tabs_with_aria_attributes(
    client: TestClient, store: ScanStore
) -> None:
    """All 4 tab buttons are present with correct ARIA + tabindex roving.

    Note: the Agents tab was deleted in QA-030; this assertion was previously
    keyed on 5 tabs (Overview / Findings / Probes / Agents / Logs)."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # tablist container
    assert 'role="tablist"' in body
    assert 'aria-labelledby="executive-tablist-label"' in body
    # Each tab id present with role + aria-controls
    for slug in ("overview", "findings", "probes", "logs"):
        assert f'id="tab-{slug}"' in body, f"missing tab button id tab-{slug}"
        assert f'aria-controls="tabpanel-{slug}"' in body
    # Exactly one tab carries aria-selected="true" (Overview) and three carry
    # aria-selected="false". The tab buttons are multi-line so we check the
    # short window after each tab id rather than relying on a single-line
    # attribute order.
    selected_true = 0
    selected_false = 0
    for slug in ("overview", "findings", "probes", "logs"):
        idx = body.find(f'id="tab-{slug}"')
        # Slice only up to the closing > of THIS button (before next button).
        close_idx = body.find("</button>", idx)
        snippet = body[idx:close_idx]
        if 'aria-selected="true"' in snippet:
            selected_true += 1
        if 'aria-selected="false"' in snippet:
            selected_false += 1
    assert selected_true == 1
    assert selected_false == 3


def test_executive_renders_4_tabpanels_with_aria_attributes(
    client: TestClient, store: ScanStore
) -> None:
    """All 4 tabpanels are present; only Overview lacks the ``hidden`` attribute.

    Note: the Agents tab was deleted in QA-030; this assertion was previously
    keyed on 5 tabpanels."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    for slug in ("overview", "findings", "probes", "logs"):
        assert f'id="tabpanel-{slug}"' in body, f"missing tabpanel id tabpanel-{slug}"
        assert f'aria-labelledby="tab-{slug}"' in body, (
            f"missing aria-labelledby on tabpanel-{slug}"
        )
    # Overview is the default visible tabpanel: no ``hidden`` attribute on it.
    # The other three panels carry ``hidden``.
    assert (
        'id="tabpanel-overview"\n         role="tabpanel"' in body
        or '<section id="tabpanel-overview"' in body
    )
    for slug in ("findings", "probes", "logs"):
        # Each hidden tabpanel section ends with the ``hidden>`` attribute.
        anchor = f'id="tabpanel-{slug}"'
        idx = body.find(anchor)
        assert idx >= 0
        # Look forward up to 300 chars for ``hidden>`` close
        snippet = body[idx : idx + 300]
        assert "hidden>" in snippet, f"tabpanel {slug} missing hidden attribute"


def test_executive_default_tab_is_overview(client: TestClient, store: ScanStore) -> None:
    """The server-side default active tab is Overview (matches the locked spec)."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    # The Overview tab carries aria-selected="true" + tabindex="0"
    assert 'id="tab-overview"' in body
    idx = body.find('id="tab-overview"')
    snippet = body[idx : idx + 200]
    assert 'aria-selected="true"' in snippet
    assert 'tabindex="0"' in snippet


# ---------------------------------------------------------------------------
# 4. The literal heading lives on the Findings tab
# ---------------------------------------------------------------------------


def test_executive_findings_tab_contains_locked_heading(
    client: TestClient, store: ScanStore
) -> None:
    """The verbatim ``All findings so far.`` string is in the Findings tabpanel."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # Locked literal — same string the other 4 themes carry.
    assert "All findings so far." in body
    # Specifically inside the Findings tabpanel block.
    idx = body.find('id="tabpanel-findings"')
    assert idx >= 0
    # The heading appears after the tabpanel opening tag, before the
    # next tabpanel (Probes) opens.
    next_panel_idx = body.find('id="tabpanel-probes"', idx)
    assert next_panel_idx >= 0
    findings_pane = body[idx:next_panel_idx]
    assert "All findings so far." in findings_pane


# ---------------------------------------------------------------------------
# 5. Probes tab renders probes_list payload
# ---------------------------------------------------------------------------


def test_executive_probes_tab_renders_probes_list_entries(
    client: TestClient, store: ScanStore
) -> None:
    """Seeded reflection records in memory.jsonl appear in the Probes tabpanel."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turns = _seed_memory_jsonl(scan_dir, count=2)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    idx = body.find('id="tabpanel-probes"')
    next_panel_idx = body.find('id="tabpanel-logs"', idx)
    probes_pane = body[idx:next_panel_idx]
    for turn in turns:
        assert str(turn["seed_id"]) in probes_pane
        assert str(turn["agent"]) in probes_pane


def test_executive_probes_tab_empty_state_when_no_memory_jsonl(
    client: TestClient, store: ScanStore
) -> None:
    """No memory.jsonl → the Probes pane renders the empty-state copy."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    assert "No probe attempts recorded yet." in body


# ---------------------------------------------------------------------------
# 6. Logs tab renders logs_tail payload
# ---------------------------------------------------------------------------


def test_executive_logs_tab_renders_logs_tail_entries(client: TestClient, store: ScanStore) -> None:
    """Seeded events.jsonl rows appear in the Logs tabpanel with kind + level."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    events = _seed_events_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    idx = body.find('id="tabpanel-logs"')
    logs_pane = body[idx:]
    for ev in events:
        assert str(ev["kind"]) in logs_pane
    # Level derivation: scan_started → INFO; agent_skipped → WARN
    assert "INFO" in logs_pane
    assert "WARN" in logs_pane


def test_executive_logs_tab_empty_state_when_no_events_jsonl(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    assert "No log events recorded yet." in body


# ---------------------------------------------------------------------------
# 7. Theme switcher dropdown — retired in QA-041, the switcher must NOT render
# ---------------------------------------------------------------------------


def test_executive_theme_switcher_dropdown_is_not_rendered(
    client: TestClient, store: ScanStore
) -> None:
    """QA-041: the multi-theme switcher dropdown was removed alongside the
    non-Executive themes. The topbar must no longer carry the shared
    ``ag-theme-switcher`` partial markers.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    body = resp.text
    assert resp.status_code == 200
    assert "ag-theme-switcher" not in body
    assert "Mission Control" not in body
    assert "Narrative Report" not in body


# ---------------------------------------------------------------------------
# 8. clean_control sentry — 0 findings + 0 probes + 0 logs
# ---------------------------------------------------------------------------


def test_executive_clean_control_renders_all_4_tabs(client: TestClient, store: ScanStore) -> None:
    """Zero findings / probes / logs → all 4 panes render with empty-state copy.

    Note: the Agents tab was deleted in QA-030; this assertion was previously
    keyed on 5 tabpanels."""
    scan = _make_scan(with_findings=False)
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # All 4 tabpanels present
    for slug in ("overview", "findings", "probes", "logs"):
        assert f'id="tabpanel-{slug}"' in body
    # Locked empty-state copy across the 3 data-driven panes.
    assert "Nothing flagged yet." in body
    assert "No probe attempts recorded yet." in body
    assert "No log events recorded yet." in body


# ---------------------------------------------------------------------------
# 9. Agents tab DOM absence (QA-030 — tab deleted)
# ---------------------------------------------------------------------------


def test_executive_no_agents_tab_in_dom(client: TestClient, store: ScanStore) -> None:
    """The Agents tab was deleted in QA-030. No DOM artefact of it may remain.

    Asserts:
      * ``id="tab-agents"`` does not appear (tab button gone).
      * ``id="tabpanel-agents"`` does not appear (tabpanel gone).
      * Exactly 4 ``role="tab"`` buttons render in the tablist.
      * Exactly 4 ``id="tabpanel-`` panes render in <main>.
      * The four surviving tabs appear in the locked order:
        Overview → Findings → Probes → Logs.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # No leftover agents button / pane.
    assert 'id="tab-agents"' not in body, "stray tab-agents button in DOM"
    assert 'id="tabpanel-agents"' not in body, "stray tabpanel-agents in DOM"
    # The tablist carries exactly 4 role=tab buttons.
    assert body.count('role="tab"') == 4
    # And exactly 4 tabpanel ids.
    assert body.count('id="tabpanel-') == 4
    # Locked order: Overview before Findings before Probes before Logs.
    idx_overview = body.find('id="tab-overview"')
    idx_findings = body.find('id="tab-findings"')
    idx_probes = body.find('id="tab-probes"')
    idx_logs = body.find('id="tab-logs"')
    assert idx_overview >= 0
    assert idx_findings > idx_overview
    assert idx_probes > idx_findings
    assert idx_logs > idx_probes


# ---------------------------------------------------------------------------
# 10. Layout structure — the 3 sticky layers are in the right order
# ---------------------------------------------------------------------------


def test_executive_sticky_layer_order_is_locked(client: TestClient, store: ScanStore) -> None:
    """Sticky shell order: topbar precedes tabbar. KPI strip is inside the
    Overview tabpanel (not the shell), so it must appear AFTER the tabbar
    and within the tabpanel-overview section."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    topbar_idx = body.find('class="exec-topbar"')
    tabbar_idx = body.find('class="exec-tabbar"')
    overview_start = body.find('id="tabpanel-overview"')
    # The end of the overview pane = start of the next tabpanel.
    overview_end = body.find('id="tabpanel-findings"')
    kpi_idx = body.find('class="exec-kpi-strip"')
    assert topbar_idx >= 0
    assert tabbar_idx >= 0
    assert overview_start >= 0
    assert overview_end > overview_start
    assert kpi_idx >= 0
    # Shell order: topbar before tabbar, no KPI strip between them.
    assert topbar_idx < tabbar_idx
    # KPI strip lives inside the Overview tabpanel.
    assert overview_start < kpi_idx < overview_end
    # And only once in the document (it is not duplicated to other panes).
    assert body.count('class="exec-kpi-strip"') == 1


# ---------------------------------------------------------------------------
# 11. Keyboard nav — server-side ARIA attributes match the WAI-ARIA pattern
# ---------------------------------------------------------------------------


def test_executive_keyboard_nav_aria_attributes_correct(
    client: TestClient, store: ScanStore
) -> None:
    """Roving tabindex: only the active tab has tabindex='0'; rest are '-1'.

    This is the server-side default state — the JS keyboard handler flips
    these on Space/Enter activation, but the initial paint must already
    conform to the WAI-ARIA manual-activation pattern.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    # Locate each tab anchor and check its tabindex.
    for slug in ("overview", "findings", "probes", "logs"):
        idx = body.find(f'id="tab-{slug}"')
        assert idx >= 0
        snippet = body[idx : idx + 200]
        if slug == "overview":
            assert 'tabindex="0"' in snippet, f"{slug} should have tabindex=0"
            assert 'aria-selected="true"' in snippet
        else:
            assert 'tabindex="-1"' in snippet, f"{slug} should have tabindex=-1"
            assert 'aria-selected="false"' in snippet


# ---------------------------------------------------------------------------
# 12. Stale ?theme= query param ignored — Executive renders regardless
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stale_theme",
    ["editorial", "mission", "narrative", "executive", "ide", "totally-bogus"],
)
def test_stale_theme_query_param_renders_executive(
    client: TestClient, store: ScanStore, stale_theme: str
) -> None:
    """QA-041: the ``?theme=`` query param is silently ignored. Any value —
    a former theme slug, the retired ``ide`` slug, or pure garbage — still
    resolves to the Executive layout (``data-theme="executive"``) so stale
    operator bookmarks never 404. The greppable findings literal renders
    every time.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme={stale_theme}")
    assert resp.status_code == 200, resp.text[:500]
    assert 'data-theme="executive"' in resp.text
    assert "All findings so far." in resp.text


# ---------------------------------------------------------------------------
# 13. QA-024 — Narrative-styled partials wired into the 5 tabs
# ---------------------------------------------------------------------------


def test_executive_overview_no_longer_renders_aivss_hero_partial(
    client: TestClient, store: ScanStore
) -> None:
    """QA-042 (2026-06-02) — the AIVSS hero card (big serif numeric + 5-band
    horizontal axis) is no longer included on Overview. Its information now
    lives in the AIVSS KPI tile horseshoe gauge introduced in QA-040, so
    the duplicate ``aivss-block`` + ``exec-hero__number`` + ``exec-bandaxis``
    markup MUST NOT appear in the Overview pane.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    assert 'data-component="aivss-hero"' not in overview_pane
    assert "exec-hero__number" not in overview_pane
    assert "exec-bandaxis" not in overview_pane
    # But the AIVSS gauge MUST be present in its place.
    assert 'data-component="aivss-gauge"' in overview_pane


def test_executive_overview_renders_severity_bars_partial(
    client: TestClient, store: ScanStore
) -> None:
    """The severity bar chart renders in the Overview tab with all 4 labels."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    assert 'data-component="severity-bars"' in overview_pane
    # Canvas id is tab-scoped (overview vs findings) to avoid duplicate-id
    # collisions when the partial is included in both tabs.
    assert 'id="exec-severity-bar-overview"' in overview_pane
    # QA-028 sub-ask 3b dropped the FIG. 1 / FIG. 2 academic eyebrows from
    # _severity_bars.html + _asi_radar.html — the locked headline is now
    # the only above-the-chart label.
    assert "Findings by severity" in overview_pane


def test_executive_findings_tab_keeps_severity_jump_anchors(
    client: TestClient, store: ScanStore
) -> None:
    """The Findings tab carries the per-severity jump anchors
    (#exec-sev-{key}) the bucket-grouped table relies on.

    QA-029 sub-ask 1 deleted the duplicate severity bar chart from the
    Findings tab (kept only in Overview). The negative assertion lives in
    ``tests/server/test_executive_findings_table_and_slideover.py``; this
    test asserts the surviving anchor invariant only.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    idx = body.find('id="tabpanel-findings"')
    next_idx = body.find('id="tabpanel-probes"', idx)
    findings_pane = body[idx:next_idx]
    # The fixture seeds critical / high / medium → at least these anchors must
    # be present (low has no findings → no bucket → no anchor).
    assert 'id="exec-sev-critical"' in findings_pane
    assert 'id="exec-sev-high"' in findings_pane
    assert 'id="exec-sev-medium"' in findings_pane


def test_executive_overview_renders_asi_radar_partial(client: TestClient, store: ScanStore) -> None:
    """The ASI radar chart renders in the Overview tab with the FIG. 1
    eyebrow and the locked headline."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    assert 'data-component="asi-radar"' in overview_pane
    assert 'id="exec-asi-radar"' in overview_pane
    # QA-028 sub-ask 3b dropped the FIG. 1 / FIG. 2 academic eyebrows from
    # the chart partials. The locked headline is the only above-chart label.
    assert "Adversarial Surface Index" in overview_pane


def test_executive_reproducibility_renders_in_each_data_tab(
    client: TestClient, store: ScanStore
) -> None:
    """The reproducibility receipt renders ONLY on the Overview tab.

    Timeline:
      * 2026-05-31 — receipt moved off the layout footer into per-tab partials.
      * QA-029     — narrowed include set to Overview + Probes.
      * BUG-2 (2026-06-02) — receipt removed from Probes too, since
        surfacing the same receipt twice was the bug. Per-probe
        reproduction is covered by the drawer's "Reproduce" CLI button
        (QA-049). Overview is the single source of truth for the
        canonical scan-level receipt.

    Findings + Logs continue to omit it.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # Overview only after BUG-2 — exactly 1 include.
    assert body.count('data-component="reproducibility"') == 1
    # The 7 mono row labels appear at least once.
    for label in (
        "SCAN_ID",
        "SEED",
        "GUARDIAN",
        "AIVSS",
        "PROBES",
        "TARGET",
        "EVIDENCE",
    ):
        assert label in body, f"reproducibility missing label {label}"
    # The REPRODUCIBILITY mono eyebrow renders exactly once.
    assert body.count("REPRODUCIBILITY") == 1
    # The Copy button hook is the same across all includes (Copy logic
    # iterates [data-copy-target] via querySelectorAll).
    assert body.count('data-copy-target="#exec-repro-command"') == 1


def test_executive_charts_js_is_served_with_token_reads(client: TestClient) -> None:
    """The Executive chart bootstrapper is reachable + reads the --exec-*
    palette tokens (so the chart colours pick up the Narrative palette)."""
    resp = client.get("/static/executive_charts.js")
    assert resp.status_code == 200
    body = resp.text
    assert "exec-asi-radar" in body
    assert "exec-severity-bar" in body
    assert "--exec-brand" in body
    assert "--exec-sev-" in body
    assert "mountCopyButtons" in body


def test_executive_css_carries_narrative_palette_tokens(client: TestClient) -> None:
    """The Executive stylesheet declares the Narrative palette tokens with
    the --exec- prefix (Source Serif Pro headlines, JetBrains Mono eyebrows,
    cream parchment background, violet brand, amber high, red critical)."""
    resp = client.get("/static/executive.css")
    assert resp.status_code == 200
    body = resp.text
    # Token declarations.
    assert "--exec-font-serif" in body
    assert "Source Serif Pro" in body
    assert "--exec-font-mono" in body
    assert "JetBrains Mono" in body
    # Palette literals — Narrative palette migrated verbatim into Executive.
    assert "#8b5cf6" in body  # brand violet
    assert "#7c3aed" in body  # brand-strong
    assert "#fafaf7" in body  # cream parchment background
    assert "#d97706" in body  # high amber
    assert "#b91c1c" in body  # critical red
    # The hero number ports the Narrative big-numeric serif treatment.
    assert ".exec-hero__number" in body
    assert "var(--exec-font-serif)" in body
    # Severity tokens are key for executive_charts.js readToken().
    assert "--exec-sev-critical" in body
    assert "--exec-sev-high" in body
    assert "--exec-sev-medium" in body
    assert "--exec-sev-low" in body


def test_executive_clean_control_renders_all_new_partials(
    client: TestClient, store: ScanStore
) -> None:
    """The clean_control sentry survives the Narrative partial migration —
    every surviving partial renders with the 0-findings fixture without error.

    Note: the ``asi-rows`` partial was removed in QA-030 along with the
    Agents tab; its per-ASI breakdown is now on Overview via
    ``_asi_compact_table.html`` (QA-033)."""
    scan = _make_scan(with_findings=False)
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # All surviving partials present even when the scan flagged nothing.
    # QA-042 (2026-06-02) — the AIVSS hero card was removed from Overview;
    # its information moved into the AIVSS KPI tile horseshoe gauge (QA-040).
    assert 'data-component="aivss-gauge"' in body
    assert 'data-component="severity-bars"' in body
    assert 'data-component="asi-radar"' in body
    assert 'data-component="reproducibility"' in body
    # The deleted partials must NOT render anywhere.
    assert 'data-component="aivss-hero"' not in body
    assert 'data-component="asi-rows"' not in body
    # The findings empty-state copy is still wired through.
    assert "Nothing flagged yet." in body


# ---------------------------------------------------------------------------
# Judge-reasoning fallback (judge-reasoning-empty bug)
# ---------------------------------------------------------------------------


def _seed_memory_jsonl_without_judge(scan_dir: Path) -> dict[str, object]:
    """Write one reflection record whose turn carries no judge reasoning /
    confidence (mirrors recon-only attempts that never reached a judge).
    Returns the inner turn dict.
    """
    turn = {
        "agent": "asi01-recon",
        "asi_category": "ASI01",
        "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
        "turn": 1,
        "strategy": "recon",
        "prompt": "probe attempt without judge verdict",
        "target_response": "target response without judge verdict",
        # No verdict, confidence == 0, empty reasoning — by design.
        "verdict": "",
        "confidence": 0.0,
        "reasoning": "",
        "seed_id": "PROBE-RECON-001",
        "attacker_refused": False,
    }
    record = {
        "timestamp": "2026-05-27T12:30:00+00:00",
        "record_type": "reflection",
        "payload": {
            "agent": turn["agent"],
            "content": json.dumps(turn),
        },
    }
    (scan_dir / "memory.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    return turn


def _fetch_probe_drawers(
    client: TestClient, scan_id: str, count: int
) -> list[str]:
    """Fetch the server-rendered drawer fragment for each probe index.

    BUG-1 (2026-06-02) — the legacy ``<script type="application/json"
    id="exec-probes-payload">`` JSON-island wall was retired. The drawer
    body is now rendered on demand by ``GET /scan/<id>/probe?index=<N>``
    when an operator opens a row. This helper retrieves each fragment so
    the per-row content assertions can still run; the initial Probes-tab
    HTML never carries the verbatim prompt / response / reasoning text.
    """
    out: list[str] = []
    for idx in range(count):
        resp = client.get(f"/scan/{scan_id}/probe?index={idx}")
        if resp.status_code == 200:
            out.append(resp.text)
    return out


def test_executive_probes_tab_initial_html_never_leaks_payload(
    client: TestClient, store: ScanStore
) -> None:
    """The initial Probes-tab HTML carries NO verbatim prompt /
    target-response / judge-reasoning text — even for probes whose
    fields would otherwise pose no obvious sensitivity. BUG-1
    (2026-06-02) moved the per-probe payload from the centralised JSON
    island onto the lazy-loaded drawer fragment; the only data that
    appears in the initial page is the 5-column scannable row.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turn = _seed_memory_jsonl_without_judge(scan_dir)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200

    idx = body.find('id="tabpanel-probes"')
    next_panel_idx = body.find('id="tabpanel-logs"', idx)
    probes_pane = body[idx:next_panel_idx]

    # The legacy JSON-island wall + per-row payload attribute are gone.
    assert '<script type="application/json" id="exec-probes-payload">' not in probes_pane
    assert "data-probe-payload" not in probes_pane
    # The verbatim prompt + target response never enter the initial HTML.
    assert turn["prompt"] not in probes_pane
    assert turn["target_response"] not in probes_pane


def test_executive_probe_drawer_route_serves_empty_reasoning_fallback(
    client: TestClient, store: ScanStore
) -> None:
    """When a probe carries no judge reasoning (empty string) and
    confidence is 0.0, the on-demand drawer fragment falls back to the
    humanised empty-state copy ("Not graded per-turn — see the Findings
    tab for the rolled-up judge verdict.").
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl_without_judge(scan_dir)
    resp = client.get(f"/scan/{scan.id}/probe?index=0")
    assert resp.status_code == 200
    body = resp.text
    assert "Not graded per-turn" in body, (
        "empty-reasoning fallback prose missing from the drawer fragment"
    )


def test_executive_probe_drawer_route_serves_real_reasoning(
    client: TestClient, store: ScanStore
) -> None:
    """When a probe DOES carry judge reasoning + non-zero confidence,
    the on-demand drawer fragment surfaces both verbatim.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turns = _seed_memory_jsonl(scan_dir, count=1)
    resp = client.get(f"/scan/{scan.id}/probe?index=0")
    assert resp.status_code == 200
    body = resp.text
    assert turns[0]["reasoning"] in body
    assert "0.85" in body


# ---------------------------------------------------------------------------
# 10. Findings tab — per-finding evidence expansion
# ---------------------------------------------------------------------------


def _seed_memory_jsonl_for_finding(
    scan_dir: Path,
    *,
    seed_id: str,
    agent: str = "asi01-goal",
    asi_category: str = "ASI01",
    count: int = 2,
) -> list[dict[str, object]]:
    """Write ``count`` reflection records all carrying the same ``seed_id`` so
    they correlate to a finding whose ``probe_id`` equals that ``seed_id``."""
    turns: list[dict[str, object]] = []
    lines: list[str] = []
    for i in range(count):
        turn = {
            "agent": agent,
            "asi_category": asi_category,
            "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
            "turn": i + 1,
            "strategy": "direct_injection",
            "prompt": f"finding-evidence prompt {i}",
            "target_response": f"finding-evidence target response {i}",
            "verdict": "vulnerable",
            "confidence": 0.91,
            "reasoning": f"finding-evidence judge reasoning {i}",
            "seed_id": seed_id,
            "attacker_refused": False,
        }
        record = {
            "timestamp": f"2026-05-27T13:{30 + i:02d}:00+00:00",
            "record_type": "reflection",
            "payload": {
                "agent": turn["agent"],
                "content": json.dumps(turn),
            },
        }
        turns.append(turn)
        lines.append(json.dumps(record))
    (scan_dir / "memory.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return turns


def test_executive_findings_tab_finding_row_exposes_slideover_hooks(
    client: TestClient, store: ScanStore
) -> None:
    """A finding row renders the slide-over hookup attributes
    (``data-finding-id``, ``aria-controls="exec-finding-slideover"``,
    ``tabindex="0"``, ``role="button"``) so the QA-031 shared slide-over
    JS can mount click + keyboard handlers.

    QA-031 replaced the per-card ``<details class="exec-finding__evidence">``
    inline DOM with a 4-col findings table + shared slide-over. The actual
    evidence payload is served client-side via the
    ``#exec-findings-payload`` JSON island (wired in dashboard_view); the
    deep verification of that payload's contents lives in the
    ``test_executive_findings_table_and_slideover`` suite (see
    ``test_executive_findings_json_island_carries_payload``).
    """
    # Build a scan with exactly one CRITICAL finding whose probe_id we control.
    finding = _make_finding("f-crit-1", Severity.CRITICAL, AsiCategory.ASI01)
    # _make_finding sets probe_id="probe-<fid>" → "probe-f-crit-1".
    seed_id = finding.probe_id
    scan = Scan(
        id="cli-evidence-001",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=84,
        band=SeverityBand.GOOD,
        sub_scores={
            "prompt_injection_resistance": 72.0,
            "tool_scope_safety": 88.0,
            "pii_containment": 95.0,
            "memory_poisoning_resistance": 68.0,
            "excessive_agency_containment": 84.0,
            "hallucination_resistance": 79.0,
        },
        findings=[finding],
        asi_scores={cat: 80.0 for cat in AsiCategory},
        duration_seconds=252.0,
        cost_usd=0.84,
        tokens_total=820_000,
        mode="full",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=UTC),
    )
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl_for_finding(scan_dir, seed_id=seed_id, count=2)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # Scope to the findings tab to avoid catching Probes-tab markup.
    idx = body.find('id="tabpanel-findings"')
    next_panel_idx = body.find('id="tabpanel-probes"', idx)
    findings_pane = body[idx:next_panel_idx]
    # Row-level slide-over wiring is locked.
    assert 'data-finding-id="f-crit-1"' in findings_pane
    assert 'aria-controls="exec-finding-slideover"' in findings_pane
    assert 'role="button"' in findings_pane
    assert 'tabindex="0"' in findings_pane
    # The shared slide-over component is mounted exactly once.
    assert findings_pane.count('id="exec-finding-slideover"') == 1
    # The JSON-island host element exists (the payload contents are verified
    # in test_executive_findings_table_and_slideover.py).
    assert 'id="exec-findings-payload"' in findings_pane


def test_executive_findings_tab_omits_evidence_when_none(
    client: TestClient, store: ScanStore
) -> None:
    """A finding with no matching probe-attempt records (no memory.jsonl) must
    NOT render a ``<details class="exec-finding__evidence">``."""
    scan = _make_scan(scan_id="cli-evidence-empty-001")  # 3 findings, no memory.jsonl
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    idx = body.find('id="tabpanel-findings"')
    next_panel_idx = body.find('id="tabpanel-probes"', idx)
    findings_pane = body[idx:next_panel_idx]
    assert 'class="exec-finding__evidence"' not in findings_pane
    assert 'class="exec-finding__evidence-row"' not in findings_pane


# ---------------------------------------------------------------------------
# kind="log" CLI-style running log rendering (Executive Logs tab)
# ---------------------------------------------------------------------------


def test_executive_logs_tab_renders_kind_log_records_inline(
    client: TestClient, store: ScanStore
) -> None:
    """Seed events.jsonl with one SwarmEvent + two ``kind='log'`` records and
    assert all 3 render with the right level pill + summary text + that the
    log rows omit the kind pill and agent column (locked decision #4)."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    events: list[dict[str, object]] = [
        {
            "kind": "scan_started",
            "agent": None,
            "asi": None,
            "provisional_aivss": None,
            "decision": None,
            "timestamp": "2026-05-31T12:00:00+00:00",
            "payload": {"message": "boot"},
        },
        {
            "kind": "log",
            "agent": None,
            "asi": None,
            "provisional_aivss": None,
            "decision": None,
            "timestamp": "2026-05-31T12:00:01+00:00",
            "payload": {
                "level": "INFO",
                "logger": "httpx",
                "message": "HTTP Request: POST https://api.example/v1 200 OK",
            },
        },
        {
            "kind": "log",
            "agent": None,
            "asi": None,
            "provisional_aivss": None,
            "decision": None,
            "timestamp": "2026-05-31T12:00:02+00:00",
            "payload": {
                "level": "ERROR",
                "logger": "agent_guardian.core.swarm",
                "message": "commander timed out",
                "exc_info": "Traceback (most recent call last):\n  RuntimeError: t/o",
            },
        },
    ]
    (scan_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )

    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    idx = body.find('id="tabpanel-logs"')
    logs_pane = body[idx:]

    # SwarmEvent row renders with its kind label visible.
    assert "scan_started" in logs_pane
    # Both log rows render their formatted summary text.
    assert "HTTP Request: POST https://api.example/v1 200 OK" in logs_pane
    assert "commander timed out" in logs_pane
    # The httpx logger name is prepended to the summary (em dash separator).
    assert "httpx" in logs_pane
    # Level pills carry the right level word (uppercased by the template).
    assert "INFO" in logs_pane
    assert "ERROR" in logs_pane
    # CLI-style monospace marker class is applied to log rows.
    assert "exec-log__msg--mono" in logs_pane
    # The kind pill text "log" must NOT render inside its own pill element
    # for kind='log' rows (the kind pill is hidden by the template). We
    # verify by checking that no ``<span class="exec-log__kind">log</span>``
    # appears in the logs pane.
    assert '<span class="exec-log__kind">log</span>' not in logs_pane


def test_executive_logs_tab_log_kind_does_not_render_agent_column(
    client: TestClient, store: ScanStore
) -> None:
    """When kind='log', the agent column is hidden even if agent is set
    (logger name is already in the summary). Locked decision #4."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    record = {
        "kind": "log",
        "agent": "should-not-render",
        "asi": None,
        "provisional_aivss": None,
        "decision": None,
        "timestamp": "2026-05-31T12:00:01+00:00",
        "payload": {
            "level": "INFO",
            "logger": "httpx",
            "message": "ping",
        },
    }
    (scan_dir / "events.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    idx = body.find('id="tabpanel-logs"')
    logs_pane = body[idx:]
    # The agent column span must not appear with the suspect agent value.
    assert '<span class="exec-log__agent">should-not-render</span>' not in logs_pane
    # The summary text still renders.
    assert "ping" in logs_pane
