"""Slice: reproducibility-per-tab.

Verify that the reproducibility receipt has been moved out of the layout-level
footer into per-tab includes.

Timeline:
* QA-029 sub-ask 3 restricted the receipt to Overview + Probes (Findings
  and Logs already omit it; the Agents tab itself was deleted in QA-030).
* BUG-2 (2026-06-02) — the Probes-tab include was removed because
  surfacing the same scan-level receipt twice was the bug operators
  flagged. Per-probe reproduction now lives in the drawer's "Reproduce"
  CLI button (QA-049). Only the Overview tab carries the canonical
  receipt today.
"""

from __future__ import annotations

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
# Fixtures (kept independent of test_theme_executive_rendering helpers so the
# synthesis phase can shuffle files without breaking this test).
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _make_finding(fid: str, severity: Severity) -> Finding:
    return Finding(
        id=fid,
        probe_id=f"probe-{fid}",
        asi=AsiCategory.ASI01,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=severity,
        attempt_count=2,
        success=True,
        confidence=0.91,
        summary=f"finding {fid}: prompt injection observed",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
    )


def _make_scan(scan_id: str = "cli-repro-per-tab-001") -> Scan:
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
        findings=[_make_finding("f-crit-1", Severity.CRITICAL)],
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


# ---------------------------------------------------------------------------
# Per-tabpanel slicing helper.
# ---------------------------------------------------------------------------


def _slice_tabpanel(html: str, tab_id: str) -> str:
    """Return the substring of ``html`` belonging to the named tabpanel.

    Tabpanels are sibling ``<section role="tabpanel">`` blocks. We slice from
    the opening ``id="tabpanel-<tab_id>"`` marker until the next
    ``id="tabpanel-..."`` marker (or the closing ``</main>``).
    """

    start = html.find(f'id="tabpanel-{tab_id}"')
    assert start != -1, f"tabpanel-{tab_id} not present in rendered HTML"
    # Move back to the opening "<section" so we capture the full element.
    section_open = html.rfind("<section", 0, start)
    if section_open == -1:
        section_open = start

    # Find the next tabpanel id after this one (search after the opener).
    next_panel = re.search(
        r'id="tabpanel-(?!' + re.escape(tab_id) + r'")[a-z]+"',
        html[start + 1 :],
    )
    if next_panel:
        end = start + 1 + next_panel.start()
        # Walk back to the "<section" that owns the next panel.
        next_open = html.rfind("<section", 0, end)
        end = next_open if next_open != -1 else end
    else:
        # No further tabpanels: cut at </main>.
        end = html.find("</main>", start)
        if end == -1:
            end = len(html)

    return html[section_open:end]


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


REPRO_MARKER = 'data-component="reproducibility"'


def test_reproducibility_receipt_is_gone_from_every_tab(
    client: TestClient, store: ScanStore
) -> None:
    """The reproducibility receipt was retired from the dashboard.

    QA-029 narrowed the include to Overview + Probes; BUG-2 (2026-06-02)
    removed the Probes include; the Overview cleanup then dropped the
    receipt's copy-block entirely (its "Scan identity" companion card was
    replaced by the CLI-style "Scan plan" panel). The receipt must not
    appear in any tabpanel anymore.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200

    for tab in ("overview", "findings", "probes", "logs"):
        pane = _slice_tabpanel(body, tab)
        assert REPRO_MARKER not in pane, (
            f"reproducibility receipt unexpectedly present in tabpanel-{tab} "
            f"after the Overview cleanup retired it"
        )


def test_reproducibility_no_longer_a_layout_level_footer(
    client: TestClient, store: ScanStore
) -> None:
    """Layout-footer position is retired: nothing between </main>'s last
    tabpanel and the closing </main> may contain the receipt as a sibling."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert resp.status_code == 200

    # Walk from the LAST tabpanel's closing </section> to </main> — that
    # tail region used to host the receipt and now must not.
    main_close = body.find("</main>")
    assert main_close != -1
    # Identify the last tabpanel's section close just before </main>.
    last_section_close = body.rfind("</section>", 0, main_close)
    assert last_section_close != -1
    tail = body[last_section_close + len("</section>") : main_close]
    assert REPRO_MARKER not in tail, (
        "reproducibility receipt must not appear as a layout-level sibling of <main>"
    )
