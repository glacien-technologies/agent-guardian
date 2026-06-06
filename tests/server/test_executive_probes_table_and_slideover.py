"""QA-032 / QA-049 / BUG-1 / BUG-2 — Probes tab compact table + slide-over.

Replaces the per-row card list (``exec-probes-list`` / ``exec-probe``) with
a 5-column scannable table. Each row carries the locked ``data-probe-id`` +
``data-action="probe-row-click"`` + ``data-source="probe"`` + ``tabindex="0"``
+ ``role="button"`` set so the shared slide-over JS can mount click +
keyboard handlers without doing any per-row markup discovery.

Covers:

* Card list is gone; 5-column table is rendered with the locked headers.
* Each row carries the locked data attributes + ARIA + tabindex.
* The slide-over component is mounted exactly once in the Probes tabpanel.
* Per-row ``data-probe-payload`` JSON attribute parses to the locked
  probe shape (BUG-1 — replaces the legacy ``#exec-probes-payload``
  JSON-island wall).
* Verdict pill vocabulary (``EXPLOITED`` / ``DEFENDED`` / ``INCONCLUSIVE``
  / ``PENDING``) renders correctly for the four verdict values.
* The clean-control empty state is preserved verbatim.
* The reproducibility receipt is REMOVED from the Probes tab (BUG-2 —
  the canonical receipt now lives only on the Overview tab; per-probe
  replay is covered by the drawer's "Reproduce" CLI button).
* The compact table keeps rendered HTML length bounded for a 100-probe
  payload (scroll-budget proxy).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_guardian import __version__
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
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


def _make_scan(scan_id: str = "cli-probes-032") -> Scan:
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
        findings=[],
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


def _seed_memory_jsonl(
    scan_dir: Path,
    *,
    count: int = 4,
    verdicts: list[str] | None = None,
) -> list[dict[str, object]]:
    """Write ``count`` reflection records with cycling verdicts.

    Returns the inner turn dicts.
    """
    if verdicts is None:
        verdicts = ["fail", "pass", "inconclusive", ""]
    turns: list[dict[str, object]] = []
    lines: list[str] = []
    for i in range(count):
        verdict = verdicts[i % len(verdicts)]
        turn = {
            "agent": f"agent-{i}",
            "asi_category": "ASI01",
            "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
            "turn": i + 1,
            "strategy": "direct_injection",
            "prompt": f"verbatim attacker prompt {i}",
            "target_response": f"target response text {i}",
            "verdict": verdict,
            "confidence": 0.85,
            "reasoning": f"judge reasoning sample {i}",
            "seed_id": f"PROBE-{i:03d}",
            "attacker_refused": False,
        }
        record = {
            "timestamp": f"2026-05-27T12:{30 + (i % 30):02d}:{(i % 60):02d}+00:00",
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


def _probes_pane(body: str) -> str:
    """Slice the body to just the ``#tabpanel-probes`` section.

    QA-030 deleted the Agents tab; the Probes tab is now followed by the
    Logs tab. Use ``tabpanel-logs`` as the end marker.
    """
    start = body.find('id="tabpanel-probes"')
    assert start >= 0
    end = body.find('id="tabpanel-logs"', start)
    assert end >= 0
    return body[start:end]


# ---------------------------------------------------------------------------
# 1. Card list is replaced by the compact table
# ---------------------------------------------------------------------------


def test_executive_probes_renders_table_not_card_list(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=4)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    assert resp.status_code == 200
    pane = _probes_pane(resp.text)
    assert 'class="exec-probes-table"' in pane
    # Legacy markup is gone (within the probes pane).
    assert '<ol class="exec-probes-list"' not in pane
    assert 'class="exec-probe"' not in pane


# ---------------------------------------------------------------------------
# 2. Five-column header
# ---------------------------------------------------------------------------


def test_executive_probes_table_has_3_columns(client: TestClient, store: ScanStore) -> None:
    # 2026-06-06 rev2: 3 columns — AGENT·ASI·RUNS | VERDICT | SUMMARY. The turn
    # count moved next to the ASI badge, EVIDENCE folded into the AI SUMMARY,
    # and LAST ACTIVITY was dropped.
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=2)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    for header in ("AGENT", "VERDICT", "SUMMARY"):
        assert header in pane, f"missing header {header!r}"
    # Dropped / renamed headers are gone.
    for absent in ("PROBE ID", "LAST ACTIVITY", "EVIDENCE", "WHAT WE LEARNED"):
        assert absent not in pane, f"header {absent!r} should be gone"


def test_executive_probes_table_columns_use_locked_widths(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=1)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    for cls in (
        "exec-probes-table__col--agent",
        "exec-probes-table__col--verdict",
        "exec-probes-table__col--summary",
    ):
        assert cls in pane, f"missing column class {cls!r}"
    # The dropped columns' classes are gone.
    for absent in (
        "exec-probes-table__col--time",
        "exec-probes-table__col--evidence",
        "exec-probes-table__col--turn",
    ):
        assert absent not in pane, f"column class {absent!r} should be gone"


# ---------------------------------------------------------------------------
# 3. Row data attributes + ARIA + tabindex
# ---------------------------------------------------------------------------


def test_executive_probes_row_carries_probe_id_and_tabindex(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turns = _seed_memory_jsonl(scan_dir, count=3)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    for turn in turns:
        probe_id = str(turn["seed_id"])
        marker = f'data-probe-id="{probe_id}"'
        assert marker in pane, f"missing row attribute {marker!r}"
    # Each row carries the locked role + tabindex + data-source.
    assert pane.count('data-source="probe"') == len(turns)
    assert pane.count('tabindex="0"') >= len(turns)
    assert pane.count('role="button"') >= len(turns)


# ---------------------------------------------------------------------------
# 4. Slide-over partial mounted exactly once per tab
# ---------------------------------------------------------------------------


def test_executive_probes_slideover_partial_mounted_once_per_tab(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=2)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    assert pane.count('id="exec-finding-slideover"') == 1
    assert pane.count('id="exec-finding-slideover-root"') == 1
    # Carries the kind marker so the shared JS can branch.
    assert 'data-slideover-kind="probe"' in pane


# ---------------------------------------------------------------------------
# 5. BUG-1 — initial HTML carries NO per-probe payload; rows fetch on click
# ---------------------------------------------------------------------------


def test_executive_probes_no_initial_payload_leak(client: TestClient, store: ScanStore) -> None:
    """BUG-1 (2026-06-02) — the initial Probes-tab HTML carries no
    prompt / target-response / judge-reasoning text. Each row references
    a server endpoint via ``data-probe-href``; the drawer JS
    ``fetch()``-es it on click. The legacy ``#exec-probes-payload``
    JSON-island wall (one giant blob of every probe's prompt + target
    response + reasoning) and the intermediate per-row
    ``data-probe-payload`` attribute are both gone.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turns = _seed_memory_jsonl(scan_dir, count=3)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)

    # The legacy script-tag wall must not be in the rendered HTML.
    assert '<script type="application/json" id="exec-probes-payload">' not in pane, (
        "legacy JSON-island wall leaked back into the rendered Probes pane"
    )
    # The intermediate per-row JSON attribute is gone too.
    assert "data-probe-payload" not in pane, (
        "per-row data-probe-payload attribute leaked the probe blob"
    )
    # The verbatim attacker prompt + target response never appear in the
    # initial Probes pane — those big payloads stay lazy-loaded via the drawer.
    for turn in turns:
        assert turn["prompt"] not in pane, (
            f"prompt {turn['prompt']!r} leaked into initial Probes HTML"
        )
        assert turn["target_response"] not in pane, (
            "target_response leaked into initial Probes HTML"
        )

    # 2026-06-06: judge reasoning IS now intentionally surfaced — but only as a
    # CAPPED one-line "WHAT WE LEARNED" gloss (``_one_line_summary``, ≤180
    # chars). A long reasoning must be truncated, never dumped verbatim.
    long_scan = _make_scan()
    long_dir = _persist(store, long_scan)
    long_turn = {
        "agent": "long-agent",
        "asi_category": "ASI01",
        "turn": 1,
        "prompt": "p",
        "target_response": "r",
        "verdict": "fail",
        "reasoning": "LEAKHEAD " + ("x" * 400) + " LEAKTAIL",
        "seed_id": "PROBE-LONG",
    }
    (long_dir / "memory.jsonl").write_text(
        json.dumps({"record_type": "reflection", "payload": {"content": json.dumps(long_turn)}})
        + "\n",
        encoding="utf-8",
    )
    long_pane = _probes_pane(client.get(f"/scan/{long_scan.id}?theme=executive").text)
    assert "LEAKHEAD" in long_pane, "the capped summary should surface the reasoning head"
    assert "LEAKTAIL" not in long_pane, "full reasoning must be truncated, not dumped verbatim"
    assert "…" in long_pane, "a truncated summary should carry the ellipsis"


def test_executive_probes_row_has_drawer_href(client: TestClient, store: ScanStore) -> None:
    """BUG-1 / QA-049 — each row carries a ``data-probe-href`` pointing at
    the server-rendered probe-detail-sheet endpoint.

    Per-agent grouping (2026-06-03) — the href now keys on the agent
    (``?group=<agent>``) so the modal renders that agent's whole
    conversation. The fixture seeds a distinct agent per turn, so each turn
    becomes its own one-row group.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=3)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    for idx in range(3):
        marker = f'data-probe-href="/scan/{scan.id}/probe?group=agent-{idx}"'
        assert marker in pane, f"row {idx} missing drawer href {marker!r}"


def test_executive_probes_row_has_action_contract(client: TestClient, store: ScanStore) -> None:
    """QA-049 — every probe row carries ``data-action="probe-row-click"``
    so the shared slide-over JS wires click + Enter/Space directly.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=4)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    # One ``data-action="probe-row-click"`` per row.
    assert pane.count('data-action="probe-row-click"') == 4


# ---------------------------------------------------------------------------
# 5b. Probe-drawer route — server-rendered fragment carries the locked data
# ---------------------------------------------------------------------------


def test_probe_drawer_route_renders_locked_fields(client: TestClient, store: ScanStore) -> None:
    """The on-demand probe-drawer fragment surfaces the locked QA-049
    sections: probe metadata, run context, exact prompt, target
    response, judge verdict / reasoning, evidence chain, reproduce
    command.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turns = _seed_memory_jsonl(scan_dir, count=2)
    resp = client.get(f"/scan/{scan.id}/probe?index=0")
    assert resp.status_code == 200
    body = resp.text
    # QA-061 — the probe endpoint now renders the SHARED ``_slideover.html``
    # modal body (``exec-slideover-sheet``) so probes get the same large
    # modal + chat conversation as findings.
    assert 'class="exec-slideover-sheet"' in body
    # Section labels for the seven QA-049 panels.
    for label in (
        "Probe metadata",
        "Run context",
        "Exact prompt sent",
        "Target response",
        "Judge verdict",
        "Judge reasoning",
        "Evidence chain",
    ):
        assert label in body, f"drawer missing section {label!r}"
    # Reproduce CLI block was removed from the detail view (operator request).
    assert "Reproduce" not in body
    # The verbatim prompt + response + reasoning text only appears here
    # (never in the initial page HTML).
    assert turns[0]["prompt"] in body
    assert turns[0]["target_response"] in body
    assert turns[0]["reasoning"] in body


def test_probe_drawer_route_supports_id_lookup(client: TestClient, store: ScanStore) -> None:
    """``?id=<probe_id>`` fallback is honoured when the deep link
    carries a probe id instead of an index (matches the
    ``?tab=probes&probe=<id>`` deep-link UX).
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turns = _seed_memory_jsonl(scan_dir, count=3)
    target_id = str(turns[1]["seed_id"])
    resp = client.get(f"/scan/{scan.id}/probe?id={target_id}")
    assert resp.status_code == 200
    body = resp.text
    assert target_id in body
    # The matched probe's prompt — not the first row's — is in the body.
    assert turns[1]["prompt"] in body


def test_probe_drawer_route_renders_empty_on_unknown_id(
    client: TestClient, store: ScanStore
) -> None:
    """Looking up a missing probe returns an HTML fragment with the
    structural class + an empty-state message, not a 404.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=1)
    resp = client.get(f"/scan/{scan.id}/probe?id=DOES-NOT-EXIST")
    assert resp.status_code == 200
    body = resp.text
    assert 'class="exec-slideover-sheet"' in body
    assert "Probe not found" in body


# ---------------------------------------------------------------------------
# 5c. Per-agent grouping (operator feedback 2026-06-03) — recon's many turns
#     collapse into ONE conversational row; the modal renders all turns.
# ---------------------------------------------------------------------------


def _seed_single_agent_multi_turn(
    scan_dir: Path,
    *,
    agent: str = "recon",
    turns: int = 17,
    verdicts: list[str] | None = None,
) -> list[dict[str, object]]:
    """Write ``turns`` reflection records that all belong to ONE agent.

    Mirrors the real recon case: one agent, no per-turn ``seed_id`` (recon
    writes turns without a probe seed), many turns in chronological order.
    """
    out: list[dict[str, object]] = []
    lines: list[str] = []
    for i in range(turns):
        verdict = (verdicts[i % len(verdicts)]) if verdicts else "pass"
        turn = {
            "agent": agent,
            "asi_category": "ASI01",
            "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
            "turn": i + 1,
            "strategy": "recon_probe",
            "prompt": f"recon prompt turn {i + 1}",
            "target_response": f"recon response turn {i + 1}",
            "verdict": verdict,
            "confidence": 0.7,
            "reasoning": f"recon reasoning turn {i + 1}",
            "seed_id": "",
            "attacker_refused": False,
        }
        record = {
            "timestamp": f"2026-05-27T12:{30 + i:02d}:00+00:00",
            "record_type": "reflection",
            "payload": {"agent": agent, "content": json.dumps(turn)},
        }
        out.append(turn)
        lines.append(json.dumps(record))
    (scan_dir / "memory.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def test_executive_probes_groups_one_row_per_agent(client: TestClient, store: ScanStore) -> None:
    """17 recon turns under one agent collapse into a SINGLE table row."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_single_agent_multi_turn(scan_dir, agent="recon", turns=17)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    # Exactly one data row (the live-append <template> skeleton is NOT
    # counted — it carries no ``data-action`` token).
    assert pane.count('data-action="probe-row-click"') == 1
    # The single row shows the rolled-up run count (next to the ASI badge),
    # not "turn 1".
    assert "17 runs" in pane
    # Row href targets the per-agent group endpoint.
    assert f'data-probe-href="/scan/{scan.id}/probe?group=recon"' in pane


def test_executive_probes_group_verdict_is_worst_case(client: TestClient, store: ScanStore) -> None:
    """A thread with one exploited turn rolls up to EXPLOITED, not DEFENDED."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_single_agent_multi_turn(
        scan_dir, agent="recon", turns=3, verdicts=["pass", "fail", "pass"]
    )
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    assert pane.count('data-action="probe-row-click"') == 1
    assert "EXPLOITED" in pane
    assert 'data-verdict="fail"' in pane


def test_probe_drawer_group_renders_full_conversation(client: TestClient, store: ScanStore) -> None:
    """``?group=<agent>`` renders every turn of the agent as a chat thread."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turns = _seed_single_agent_multi_turn(scan_dir, agent="recon", turns=4)
    resp = client.get(f"/scan/{scan.id}/probe?group=recon")
    assert resp.status_code == 200
    body = resp.text
    assert 'class="exec-slideover-sheet"' in body
    # Every turn's verbatim prompt + response appears (the full conversation),
    # not just the representative turn.
    for t in turns:
        assert t["prompt"] in body, f"missing prompt for {t['turn']}"
        assert t["target_response"] in body, f"missing response for {t['turn']}"


def test_recon_agent_slideover_renders_recon_not_pending(
    client: TestClient, store: ScanStore
) -> None:
    """The recon-agent group slide-over shows a RECON pill, not PENDING.

    Recon has no graded verdict (no probe_id / ASI), so the rollup is empty.
    The ctx builder must surface the neutral ``recon`` sentinel so the header
    pill reads RECON — matching the table row — instead of falling through the
    empty-string path to PENDING.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_single_agent_multi_turn(scan_dir, agent="recon-agent", turns=4)
    resp = client.get(f"/scan/{scan.id}/probe?group=recon-agent")
    assert resp.status_code == 200
    body = resp.text
    assert 'data-verdict="recon"' in body
    assert 'data-verdict-label="RECON"' in body
    assert 'data-verdict-label="PENDING"' not in body


def test_recon_agent_slideover_suppresses_turn_chip(client: TestClient, store: ScanStore) -> None:
    """Recon groups carry no single turn, so the header ``data-turn`` is "—".

    The JS suppresses the "turn N" chip for an em-dash turn; the template must
    emit the em-dash placeholder (not a real turn number) for recon so that
    suppression fires.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_single_agent_multi_turn(scan_dir, agent="recon-agent", turns=4)
    resp = client.get(f"/scan/{scan.id}/probe?group=recon-agent")
    assert resp.status_code == 200
    assert 'data-turn="—"' in resp.text


def test_probe_drawer_group_unknown_agent_renders_empty(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_single_agent_multi_turn(scan_dir, agent="recon", turns=2)
    resp = client.get(f"/scan/{scan.id}/probe?group=does-not-exist")
    assert resp.status_code == 200
    body = resp.text
    assert 'class="exec-slideover-sheet"' in body
    assert "Probe not found" in body


# ---------------------------------------------------------------------------
# 6. Verdict pill vocabulary
# ---------------------------------------------------------------------------


def test_executive_probes_table_renders_verdict_pill_vocab(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(
        scan_dir,
        count=4,
        verdicts=["fail", "pass", "inconclusive", ""],
    )
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    # Labels — one of each in the table cells.
    assert "EXPLOITED" in pane
    assert "DEFENDED" in pane
    assert "INCONCLUSIVE" in pane
    assert "PENDING" in pane
    # Matching modifier classes — single source of truth.
    assert "exec-verdict-pill--fail" in pane
    assert "exec-verdict-pill--pass" in pane
    assert "exec-verdict-pill--inconclusive" in pane
    assert "exec-verdict-pill--unknown" in pane


# ---------------------------------------------------------------------------
# 7. Empty-state preserved
# ---------------------------------------------------------------------------


def test_executive_probes_clean_control_empty_state_preserved(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    _persist(store, scan)
    # No memory.jsonl seeded → probes_list is empty.
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    # The empty placeholder copy renders inside the always-present table.
    assert "No probe attempts recorded yet — they appear here as the swarm runs." in pane
    # The table scaffold + slide-over now ALWAYS render (live-append target),
    # even with zero probe groups.
    assert 'class="exec-probes-table"' in pane
    assert 'id="exec-finding-slideover"' in pane
    # But the empty render still carries ZERO clickable agent rows — the
    # placeholder row is not a probe-row-click target.
    assert pane.count('data-action="probe-row-click"') == 0


# ---------------------------------------------------------------------------
# 8. Reproducibility receipt removed from Probes tab (BUG-2 — 2026-06-02)
# ---------------------------------------------------------------------------


def test_executive_probes_reproducibility_no_longer_included(
    client: TestClient, store: ScanStore
) -> None:
    """BUG-2 (2026-06-02) removed the Probes-tab reproducibility include;
    the later Overview cleanup retired the receipt entirely. The Probes
    drawer's "Reproduce" CLI button still covers per-probe replay.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=1)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    # The reproducibility component must NOT render inside the Probes
    # tabpanel any more.
    assert 'data-component="reproducibility"' not in pane
    # Cross-check: the receipt is gone from the Overview tab too.
    overview_start = resp.text.find('id="tabpanel-overview"')
    overview_end = resp.text.find('id="tabpanel-findings"', overview_start)
    overview_pane = resp.text[overview_start:overview_end]
    assert 'data-component="reproducibility"' not in overview_pane


# ---------------------------------------------------------------------------
# 9. Scroll-budget proxy — table layout is dramatically shorter than the
#    legacy card layout for the same payload.
# ---------------------------------------------------------------------------


def test_executive_probes_table_scroll_budget(client: TestClient, store: ScanStore) -> None:
    """100 probes → the rendered probes-pane HTML stays small.

    The OLD card layout emitted the verbatim prompt + target_response +
    reasoning text INLINE for every probe (inside each ``<pre>`` /
    ``<blockquote>``). For our seed-of-100 fixture each turn carries
    ~140 chars of body text (prompt + response + reasoning combined) plus
    ~600 chars of card markup, so the card layout would have weighed
    ~74 kB of inline text + structural markup.

    BUG-1 (2026-06-02) retired the centralised JSON-island wall AND the
    intermediate per-row ``data-probe-payload`` attribute — the initial
    Probes-tab HTML now only carries 5 short cells per row plus a
    ``data-probe-href`` pointer to the drawer fragment. The full
    payload weight is lazy-loaded on click. This drops the pane to
    well under the card-layout baseline.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=100)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)

    # End-to-end ceiling: 100 probes x ~1.1 kB row markup ~= 110 kB
    # (each row carries 5 short cells + a ``data-probe-href`` pointer
    # at the drawer endpoint). Lock at 150 kB to leave headroom for
    # future cell additions without flapping. The dominant compaction
    # signal is that NO verbatim probe body text appears in the
    # initial render.
    assert len(pane) < 150_000, f"probes pane HTML too large: {len(pane)} bytes for 100 probes"

    # Cross-check: legacy card markup is absent and the big verbatim payloads
    # (attacker prompt + target response) still never leak into the initial
    # render. (2026-06-06: a CAPPED judge-reasoning one-liner is intentionally
    # surfaced in the WHAT WE LEARNED column — bounded by ``_SUMMARY_CAP``, so
    # the size budget above still holds.)
    assert '<ol class="exec-probes-list"' not in pane
    assert 'class="exec-probe"' not in pane
    assert "verbatim attacker prompt 0" not in pane
    assert "target response text 0" not in pane


# ---------------------------------------------------------------------------
# 10. JS asset reachable (boot script + marker)
# ---------------------------------------------------------------------------


def test_executive_findings_slideover_js_loaded(client: TestClient) -> None:
    resp = client.get("/static/executive_findings.js")
    assert resp.status_code == 200
    body = resp.text
    assert "ag.dashboard.executive.findings.slideover" in body
    # BUG-1: the legacy ``#exec-probes-payload`` JSON-island lookup was
    # replaced with an on-demand ``fetch()`` to the row's
    # ``data-probe-href``; no inline payload + no JSON island.
    assert "data-probe-href" in body
    assert "exec-slideover-root" in body
    # QA-049: row activation contract.
    assert "probe-row-click" in body


# ---------------------------------------------------------------------------
# 11. Topbar "Download" button — direct zip, no detour through /export
# ---------------------------------------------------------------------------


def test_executive_topbar_download_button_targets_bundle_zip(
    client: TestClient, store: ScanStore
) -> None:
    """The scan-page topbar button downloads the zip directly.

    Operator feedback (2026-06-06): clicking the button should pull the whole
    evidence pack straight down, not navigate to the Export / Files listing
    first. So the topbar anchor points at ``/export/bundle.zip`` and carries a
    ``download`` attribute (the route's Content-Disposition forces the save
    either way, but the hint keeps the current tab put).
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert f'href="/scan/{scan.id}/export/bundle.zip"' in body
    # The anchor advertises a download (not a navigation).
    start = body.find(f'href="/scan/{scan.id}/export/bundle.zip"')
    anchor = body[body.rfind("<a", 0, start) : body.find("</a>", start)]
    assert "download" in anchor


# ---------------------------------------------------------------------------
# 12. Topbar scan-lifecycle status pill (in-progress spinner / completed)
# ---------------------------------------------------------------------------


def test_topbar_scan_status_shows_completed_when_terminal(
    client: TestClient, store: ScanStore
) -> None:
    """A finished scan shows a 'Completed' status pill in the topbar.

    The freshness dot only reports SSE stream health (LIVE/STALE), not whether
    the scan itself is done — so a terminal scan needs its own lifecycle pill.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    assert 'data-scan-status="done"' in body
    assert "Completed" in body


def test_topbar_scan_status_shows_in_progress_when_running(
    client: TestClient, store: ScanStore
) -> None:
    """A running scan shows an 'In progress' status pill with a spinner."""

    class FakeSwarm:
        observer = None

    scan = _make_scan()
    _persist(store, scan)
    store.register(scan.id, FakeSwarm())  # type: ignore[arg-type]
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    assert 'data-scan-status="running"' in body
    assert "In progress" in body
    assert "exec-scan-status__spinner" in body


def test_topbar_scan_status_pending_when_started_but_not_terminal(
    client: TestClient, store: ScanStore
) -> None:
    """A scan that started but never produced a terminal scan.json shows Pending.

    Regression: an interrupted scan (scan_dir exists, partial artifacts, no
    scan.json, not registered as running) was wrongly labelled 'Completed'
    because the pill only checked is_running. It must read neither 'In progress'
    nor 'Completed'.
    """
    scan_id = "cli-interrupted"
    sd = store.scan_dir(scan_id)
    sd.mkdir(parents=True, exist_ok=True)
    # Partial artifact, but NO terminal scan.json and NOT registered running.
    (sd / "events.jsonl").write_text('{"kind":"recon_start"}\n', encoding="utf-8")
    body = client.get(f"/scan/{scan_id}?theme=executive").text
    assert 'data-scan-status="pending"' in body
    assert 'data-scan-status="done"' not in body
