"""QA-023 — Executive Dashboard (Theme E) rendering tests.

Covers:

* Route returns 200 for ``?theme=executive``.
* Sticky topbar + KPI strip + WAI-ARIA tab bar render with the locked
  positioning and DOM marker classes.
* 5 tab panels render with the locked WAI-ARIA roles, ids, ``aria-selected``
  / ``aria-controls`` / ``aria-labelledby`` / ``tabindex`` attributes.
* The locked literal heading ``All findings so far.`` appears inside the
  Findings tabpanel.
* ``probes_list`` payload (from ``memory.jsonl``) is rendered into the
  Probes tab; ``logs_tail`` (from ``events.jsonl``) is rendered into the
  Logs tab.
* The ``clean_control`` sentry is preserved: a scan with zero findings,
  zero probes, and zero log events still renders all 5 panes with the
  locked empty-state copy.
* The shared theme switcher dropdown carries the 5th option
  ``Executive Dashboard``.
* The Executive entry stylesheet + tab JS are served by the static mount.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
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
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
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
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=timezone.utc),
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
    """The sticky topbar + KPI strip render with all 8 KPI labels."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # Topbar marker
    assert 'class="exec-topbar"' in body
    assert "AgentGuardian" in body
    # KPI strip marker + the 8 locked tile labels
    assert 'class="exec-kpi-strip"' in body
    for label in ("AIVSS", "Band", "Findings", "Critical", "High", "Elapsed", "Cost", "Coverage"):
        assert f">{label}<" in body, f"missing KPI tile label {label!r}"


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


def test_executive_renders_5_tabs_with_aria_attributes(
    client: TestClient, store: ScanStore
) -> None:
    """All 5 tab buttons are present with correct ARIA + tabindex roving."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # tablist container
    assert 'role="tablist"' in body
    assert 'aria-labelledby="executive-tablist-label"' in body
    # Each tab id present with role + aria-controls
    for slug in ("overview", "findings", "probes", "agents", "logs"):
        assert f'id="tab-{slug}"' in body, f"missing tab button id tab-{slug}"
        assert f'aria-controls="tabpanel-{slug}"' in body
    # Exactly one tab carries aria-selected="true" (Overview) and four carry
    # aria-selected="false". The tab buttons are multi-line so we check the
    # short window after each tab id rather than relying on a single-line
    # attribute order.
    selected_true = 0
    selected_false = 0
    for slug in ("overview", "findings", "probes", "agents", "logs"):
        idx = body.find(f'id="tab-{slug}"')
        # Slice only up to the closing > of THIS button (before next button).
        close_idx = body.find("</button>", idx)
        snippet = body[idx:close_idx]
        if 'aria-selected="true"' in snippet:
            selected_true += 1
        if 'aria-selected="false"' in snippet:
            selected_false += 1
    assert selected_true == 1
    assert selected_false == 4


def test_executive_renders_5_tabpanels_with_aria_attributes(
    client: TestClient, store: ScanStore
) -> None:
    """All 5 tabpanels are present; only Overview lacks the ``hidden`` attribute."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    for slug in ("overview", "findings", "probes", "agents", "logs"):
        assert f'id="tabpanel-{slug}"' in body, f"missing tabpanel id tabpanel-{slug}"
        assert f'aria-labelledby="tab-{slug}"' in body, (
            f"missing aria-labelledby on tabpanel-{slug}"
        )
    # Overview is the default visible tabpanel: no ``hidden`` attribute on it.
    # The other four panels carry ``hidden``.
    assert (
        'id="tabpanel-overview"\n         role="tabpanel"' in body
        or '<section id="tabpanel-overview"' in body
    )
    for slug in ("findings", "probes", "agents", "logs"):
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
    next_panel_idx = body.find('id="tabpanel-agents"', idx)
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
# 7. Theme switcher dropdown lists Executive (5th option)
# ---------------------------------------------------------------------------


def test_executive_theme_switcher_dropdown_includes_executive_option(
    client: TestClient, store: ScanStore
) -> None:
    """The shared dropdown must include the 5th option labelled 'Executive Dashboard'."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    assert 'value="executive"' in body
    assert "Executive Dashboard" in body


# ---------------------------------------------------------------------------
# 8. clean_control sentry — 0 findings + 0 probes + 0 logs
# ---------------------------------------------------------------------------


def test_executive_clean_control_renders_all_5_tabs(client: TestClient, store: ScanStore) -> None:
    """Zero findings / probes / logs → all 5 panes render with empty-state copy."""
    scan = _make_scan(with_findings=False)
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    # All 5 tabpanels present
    for slug in ("overview", "findings", "probes", "agents", "logs"):
        assert f'id="tabpanel-{slug}"' in body
    # Locked empty-state copy across the 3 data-driven panes.
    assert "Nothing flagged yet." in body
    assert "No probe attempts recorded yet." in body
    assert "No log events recorded yet." in body


# ---------------------------------------------------------------------------
# 9. Agents tab aggregates per-agent probe + flagged counts
# ---------------------------------------------------------------------------


def test_executive_agents_tab_aggregates_probes_per_agent(
    client: TestClient, store: ScanStore
) -> None:
    """The Agents pane lists every distinct probe.agent from probes_list."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turns = _seed_memory_jsonl(scan_dir, count=2)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200
    idx = body.find('id="tabpanel-agents"')
    next_panel_idx = body.find('id="tabpanel-logs"', idx)
    agents_pane = body[idx:next_panel_idx]
    # Each seeded agent name appears in the agents table.
    for turn in turns:
        assert str(turn["agent"]) in agents_pane
    assert "Probes" in agents_pane
    assert "Flagged" in agents_pane


# ---------------------------------------------------------------------------
# 10. Layout structure — the 3 sticky layers are in the right order
# ---------------------------------------------------------------------------


def test_executive_sticky_layer_order_is_locked(client: TestClient, store: ScanStore) -> None:
    """Topbar appears before KPI strip; KPI strip appears before tab bar."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    topbar_idx = body.find('class="exec-topbar"')
    kpi_idx = body.find('class="exec-kpi-strip"')
    tabbar_idx = body.find('class="exec-tabbar"')
    assert topbar_idx >= 0
    assert kpi_idx >= 0
    assert tabbar_idx >= 0
    assert topbar_idx < kpi_idx < tabbar_idx


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
    for slug in ("overview", "findings", "probes", "agents", "logs"):
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
# 12. Cross-check — all four prior themes also carry the literal heading
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "theme",
    ["editorial", "mission", "narrative", "ide", "executive"],
)
def test_every_theme_renders_locked_findings_literal(
    client: TestClient, store: ScanStore, theme: str
) -> None:
    """The greppable ``All findings so far.`` literal renders in every theme."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme={theme}")
    assert resp.status_code == 200, resp.text[:500]
    assert "All findings so far." in resp.text
