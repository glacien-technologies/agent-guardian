"""QA-029 + QA-031 — Executive Findings tab redesign tests.

Covers:
* Findings tab no longer renders the duplicate severity bar chart
  (QA-029 sub-ask 1).
* Findings tab no longer renders the reproducibility receipt
  (QA-029 sub-ask 3, Findings half).
* Logs tab no longer renders the reproducibility receipt
  (QA-029 sub-ask 3, Logs half).
* Findings tab renders the new 4-column ``exec-findings-table`` per
  severity bucket (QA-031 acceptance 1).
* Table has NO ID column and NO LAST SEEN column (QA-031 acceptance 1).
* Slide-over partial is mounted once at the bottom of the Findings
  tabpanel (QA-031 acceptance 3).
* The JSON island carries the finding payloads for the slide-over
  (QA-031 scope step 2 — MVP picks the hidden-JSON-island approach).
* The bucket jump anchors (#exec-sev-{key}) are preserved so Overview's
  FIG. 1 click-to-jump still resolves (QA-031 acceptance 7).
* The reproducibility receipt now renders in exactly 2 tabs
  (Overview + Probes), down from 4 (QA-029 acceptance 5).
"""

from __future__ import annotations

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


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _make_finding(fid: str, severity: Severity, asi: AsiCategory) -> Finding:
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


def _make_scan() -> Scan:
    return Scan(
        id="cli-findings-redesign-001",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=72,
        band=SeverityBand.WARNING,
        sub_scores={
            "prompt_injection_resistance": 72.0,
            "tool_scope_safety": 88.0,
            "pii_containment": 95.0,
            "memory_poisoning_resistance": 68.0,
            "excessive_agency_containment": 84.0,
            "hallucination_resistance": 79.0,
        },
        findings=[
            _make_finding("f-crit-1", Severity.CRITICAL, AsiCategory.ASI01),
            _make_finding("f-high-1", Severity.HIGH, AsiCategory.ASI02),
            _make_finding("f-med-1", Severity.MEDIUM, AsiCategory.ASI03),
        ],
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


def _slice(body: str, start_marker: str, end_marker: str) -> str:
    start = body.find(start_marker)
    assert start != -1, f"missing {start_marker}"
    end = body.find(end_marker, start)
    if end == -1:
        end = len(body)
    return body[start:end]


def _findings_pane(body: str) -> str:
    return _slice(body, 'id="tabpanel-findings"', 'id="tabpanel-probes"')


def _logs_pane(body: str) -> str:
    start = body.find('id="tabpanel-logs"')
    assert start != -1
    end = body.find("</main>", start)
    return body[start : end if end != -1 else len(body)]


# ----------------------------------------------------------------------
# QA-029 sub-ask 1 — drop duplicated severity chart at top of Findings
# ----------------------------------------------------------------------


def test_executive_findings_tab_omits_severity_bars(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    pane = _findings_pane(body)
    assert 'data-component="severity-bars"' not in pane
    assert 'id="exec-severity-bar-findings"' not in pane
    # Overview's instance must remain — it's the canonical one.
    assert 'data-component="severity-bars"' in body


# ----------------------------------------------------------------------
# QA-031 acceptance 1 — 4-column table, no ID column, no LAST SEEN
# ----------------------------------------------------------------------


def test_executive_findings_renders_table_not_card_list(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    assert 'class="exec-findings-table"' in pane
    # The old card markers are gone.
    assert 'class="exec-findings-list"' not in pane
    assert 'class="exec-finding"' not in pane


def test_executive_findings_table_has_4_columns(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # Header labels — verbatim from the partial.
    for col in ("Severity", "Agent", "ASI", "Probe", "Summary"):
        assert col in pane, f"findings table missing column header {col}"


def test_executive_findings_table_has_no_id_column(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # No "ID" or "Finding ID" column header in the Findings table thead.
    assert '<th scope="col" class="exec-findings-table__col--id">' not in pane
    assert ">ID</th>" not in pane


def test_executive_findings_table_has_no_last_seen_column(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    assert "Last seen" not in pane


# ----------------------------------------------------------------------
# QA-031 acceptance 3 + 7 — slide-over mount + bucket anchors preserved
# ----------------------------------------------------------------------


def test_executive_findings_slideover_partial_mounted(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    assert 'id="exec-finding-slideover"' in pane
    assert 'class="exec-slideover"' in pane
    # Mounted exactly once.
    assert pane.count('id="exec-finding-slideover"') == 1


def test_executive_findings_jump_anchors_preserved(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    assert 'id="exec-sev-critical"' in pane
    assert 'id="exec-sev-high"' in pane
    assert 'id="exec-sev-medium"' in pane


def test_executive_findings_json_island_carries_payload(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    assert 'id="exec-findings-payload"' in pane
    assert 'type="application/json"' in pane
    assert "f-crit-1" in pane


def test_executive_findings_row_carries_finding_id_and_tabindex(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    assert 'data-finding-id="f-crit-1"' in pane
    assert 'tabindex="0"' in pane
    assert 'aria-controls="exec-finding-slideover"' in pane


# ----------------------------------------------------------------------
# QA-029 sub-ask 3 — reproducibility off Findings AND Logs
# ----------------------------------------------------------------------


def test_executive_findings_tab_omits_reproducibility(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    assert 'data-component="reproducibility"' not in pane


def test_executive_logs_tab_omits_reproducibility(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _logs_pane(resp.text)
    assert 'data-component="reproducibility"' not in pane


def test_executive_reproducibility_count_is_2(client: TestClient, store: ScanStore) -> None:
    """After QA-029, the receipt renders in exactly 2 tabs: Overview + Probes."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert body.count('data-component="reproducibility"') == 2
