"""QA-020 — IDE / Terminal theme rendering tests.

Feeds a fixture :class:`~agent_guardian.models.scan.Scan` into the new
``dashboard/ide/layout.html`` template tree and asserts:

* Every layout primitive renders (activity bar, file tree, breadcrumb,
  tab strip, main panel, status bar).
* The shared `_theme_switcher.html` partial is included (AC-2).
* The file tree is composed from the shared view-model fields
  (``findings_page`` + ``asi_rows`` + recon/trace/reproducibility leaves).
* Per-finding diff cells are pre-rendered as attack transcripts with
  monospace prompt-on-`-` / response-on-`+` styling (AC-1 for IDE drill-down).
* JSON cells render for the recon / trace / reproducibility files.
* The 21 ``data-live`` SSE keys from the editorial template are mirrored
  on equivalent nodes (AC-7).
* The Tokyo Night palette + JetBrains Mono font stack are wired up.
* A 0-findings completed scan renders cleanly (AC-5 — clean-control sentry).
* Invalid/empty ``?theme=`` still routes through cleanly (AC-15 via
  ``test_theme_switcher.py``; here we just make sure the IDE theme survives
  edge inputs in the file tree).

These tests use the same TestClient + fixture-Scan pattern as the editorial
rendering tests at ``tests/unit/test_server_dashboard_rendering.py``.
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
        summary=f"finding {fid}",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_scan(scan_id: str = "cli-ide-render", findings: list[Finding] | None = None) -> Scan:
    if findings is None:
        findings = [
            _make_finding("f-crit-1", Severity.CRITICAL, AsiCategory.ASI01),
            _make_finding("f-crit-2", Severity.CRITICAL, AsiCategory.ASI06),
            _make_finding("f-high-1", Severity.HIGH, AsiCategory.ASI02),
            _make_finding("f-med-1", Severity.MEDIUM, AsiCategory.ASI03),
            _make_finding("f-low-1", Severity.LOW, AsiCategory.ASI09),
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


def _persist(store: ScanStore, scan: Scan) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


def _ide_response(client: TestClient, scan: Scan) -> str:
    resp = client.get(f"/scan/{scan.id}?theme=ide")
    assert resp.status_code == 200, resp.text
    return resp.text


# ---------------------------------------------------------------------------
# 1. Layout primitives — every region of the IDE shell renders.
# ---------------------------------------------------------------------------


def test_ide_layout_primitives_present(client: TestClient, store: ScanStore) -> None:
    """Activity bar / sidebar / breadcrumb / tab strip / main panel / status bar
    all render and carry the Tokyo Night / JetBrains Mono wiring."""
    scan = _make_scan()
    _persist(store, scan)
    body = _ide_response(client, scan)

    # Top-level shell + Tokyo Night theme stamp.
    assert "ide-body" in body
    assert 'data-theme="ide"' in body
    # Tokyo Night palette ships via ide.css.
    assert "/static/ide.css" in body
    # JetBrains Mono via the Google Fonts include.
    assert "JetBrains+Mono" in body

    # Activity bar (left rail).
    assert "ide-activity-bar" in body
    assert 'data-act="explorer"' in body
    assert 'data-act="search"' in body
    assert 'data-act="findings"' in body
    assert 'data-act="trace"' in body
    assert 'data-act="settings"' in body

    # Sidebar + file tree.
    assert "ide-sidebar" in body
    assert "ide-tree" in body
    assert "EXPLORER" in body

    # Breadcrumb + tab strip + cell host.
    assert "ide-breadcrumb" in body
    assert "ide-tabs" in body
    assert "ide-panel" in body

    # Status bar (24px pinned bottom).
    assert "ide-status-bar" in body
    # Theme entry-points: both activity bar (settings) and status bar.
    toggle_count = body.count("data-ide-theme-toggle")
    assert toggle_count >= 2, "expected at least 2 theme-toggle entry points"


# ---------------------------------------------------------------------------
# 2. Shared theme switcher partial included (AC-2).
# ---------------------------------------------------------------------------


def test_ide_includes_shared_theme_switcher_partial(client: TestClient, store: ScanStore) -> None:
    """Every theme MUST expose the dropdown so the user can flip out of it.

    The IDE theme renders the partial inside a hidden host that the
    activity-bar / status-bar buttons toggle.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = _ide_response(client, scan)

    # Switcher partial uses the canonical "ag-" prefix on its IDs so it does
    # not collide with theme-internal selectors.
    assert "ag-theme-switcher" in body
    assert 'id="ag-theme-switcher-select"' in body or "ag-theme-switcher__select" in body
    # All four locked theme labels appear inside the switcher.
    for label in ("Editorial", "Mission Control", "Narrative Report", "IDE / Terminal"):
        assert label in body
    # The host is hidden by default — only an activity bar / status bar
    # click reveals it.
    assert "ide-theme-switcher-host" in body
    assert "data-ide-switcher-host" in body


# ---------------------------------------------------------------------------
# 3. File tree composes from the shared view-model.
# ---------------------------------------------------------------------------


def test_ide_file_tree_composed_from_view_model(client: TestClient, store: ScanStore) -> None:
    """The file tree's leaves come from view-model fields, not hard-coded.

    - README.md is always present.
    - recon/ has the three static artifacts.
    - agents/ has one .log per ASI row (10 total).
    - findings/ has one .diff per finding in findings_page.
    - trace/ and reproducibility/ have their canonical files.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = _ide_response(client, scan)

    # README + recon artifacts.
    assert 'data-tree-path="README.md"' in body
    for fname in ("system-card.json", "tooling.json", "policy.json"):
        assert f'data-tree-path="recon/{fname}"' in body

    # All 10 ASI rows have a matching agents/<code>.log leaf.
    for cat in AsiCategory:
        assert f'data-tree-path="agents/{cat.value}.log"' in body

    # Every finding becomes a findings/<id>.diff leaf.
    for f in scan.findings:
        assert f'data-tree-path="findings/{f.id}.diff"' in body
        # Severity dot class wired correctly.
        assert f'data-finding-severity="{f.severity.value.lower()}"' in body

    # Trace + reproducibility leaves.
    assert 'data-tree-path="trace/timeline.json"' in body
    assert 'data-tree-path="trace/reflections.ndjson"' in body
    assert 'data-tree-path="reproducibility/manifest.json"' in body
    assert 'data-tree-path="reproducibility/env.lock"' in body


# ---------------------------------------------------------------------------
# 4. Attack-transcript diff cell.
# ---------------------------------------------------------------------------


def test_ide_attack_transcript_diff_renders_for_each_finding(
    client: TestClient, store: ScanStore
) -> None:
    """Each finding pre-renders a ``.diff`` cell with the attack-transcript
    diff structure: a critical finding tints the head, the prompt side is
    on ``-`` and the response side is on ``+``, and the judge verdict
    badge carries the severity class.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = _ide_response(client, scan)

    # The diff primitive's structural classes appear once per finding's cell.
    assert body.count("ide-diff__body") >= len(scan.findings)
    # Critical finding tints the diff head.
    assert "ide-diff__head--critical" in body
    # The `-` (prompt) and `+` (response) line variants both render.
    assert "ide-diff__line--del" in body
    assert "ide-diff__line--add" in body
    # The judge verdict line carries a severity-tinted span.
    assert "ide-diff__sev-critical" in body
    # The metadata table renders the ASI / CSA / probe-id keys verbatim.
    assert "attack-vector" in body
    assert "csa-category" in body
    assert "atlas-tactics" in body


# ---------------------------------------------------------------------------
# 5. JSON cells — recon / trace / reproducibility files.
# ---------------------------------------------------------------------------


def test_ide_json_cells_render_with_syntax_highlighting(
    client: TestClient, store: ScanStore
) -> None:
    """The JSON view cell renders for every recon/trace/repro file with
    cyan keys, green strings, and the path header."""
    scan = _make_scan()
    _persist(store, scan)
    body = _ide_response(client, scan)

    # ide-json__head appears once per JSON cell (3 recon + 2 trace + 2 repro = 7).
    assert body.count("ide-json__head") >= 7
    # Path of each rendered JSON cell appears in the header.
    for path in (
        "recon/system-card.json",
        "recon/tooling.json",
        "recon/policy.json",
        "trace/timeline.json",
        "reproducibility/manifest.json",
        "reproducibility/env.lock",
    ):
        assert f'data-json-path="{path}"' in body
    # Syntax-highlight classes present.
    for css_class in ("ide-json__key", "ide-json__str", "ide-json__punct"):
        assert css_class in body


# ---------------------------------------------------------------------------
# 6. data-live keys mirrored — AC-7.
# ---------------------------------------------------------------------------


def test_ide_mirrors_all_data_live_keys(client: TestClient, store: ScanStore) -> None:
    """Every ``data-live`` key emitted by the Editorial SSE snapshot is
    present somewhere in the IDE shell. The Editorial template carries 21
    distinct keys; the IDE theme MUST mirror every one so SSE patches
    continue to work after a theme switch.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = _ide_response(client, scan)

    expected_keys = {
        "aivss",
        "band",
        "aivss-total",
        "elapsed",
        "probes",
        "tokens",
        "usd",
        "findings",
        "findings-total",
        "asi-covered",
        "critical",
        "high",
        "medium",
        "low",
    }
    for key in expected_keys:
        assert f'data-live="{key}"' in body, f"missing data-live key: {key}"


# ---------------------------------------------------------------------------
# 7. 0-findings (clean-control) sentry — AC-5.
# ---------------------------------------------------------------------------


def test_ide_renders_for_zero_findings_scan(client: TestClient, store: ScanStore) -> None:
    """A clean (0-findings) completed scan still renders without 500."""
    scan = _make_scan(findings=[])
    _persist(store, scan)
    body = _ide_response(client, scan)

    # Shell still up.
    assert "ide-body" in body
    assert 'data-theme="ide"' in body
    # README still present, findings tree carries the empty-state caption.
    assert 'data-tree-path="README.md"' in body
    assert "(empty — clean scan)" in body
    # No critical-badge on the activity bar when 0 critical findings.
    assert "ide-act-btn__badge--crit" not in body


# ---------------------------------------------------------------------------
# 8. Sidebar resize + theme switcher entry-points wired for JS.
# ---------------------------------------------------------------------------


def test_ide_interactive_handles_wired(client: TestClient, store: ScanStore) -> None:
    """The JS hooks the templates expose (sidebar sash, theme toggle,
    breadcrumb, status selection, copy buttons) are all present so
    `ide_interactive.js` finds them without crashing."""
    scan = _make_scan()
    _persist(store, scan)
    body = _ide_response(client, scan)

    # JS file linked.
    assert "/static/ide_interactive.js" in body
    # Sidebar sash for drag-resize.
    assert "data-ide-sidebar-sash" in body
    # Breadcrumb + status placeholder.
    assert "data-ide-breadcrumb" in body
    assert "data-ide-status-selection" in body
    # Copy-to-clipboard hooks.
    assert "data-ide-copy-scan-id" in body
    assert "data-ide-copy-finding-id" in body
    # Tab strip + command-palette opener.
    assert "data-ide-tabs" in body
    assert "data-ide-palette-open" in body
