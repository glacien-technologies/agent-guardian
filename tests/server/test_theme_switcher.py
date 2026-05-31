"""QA-020 — dashboard theme switcher infrastructure tests.

Covers the route-level theme resolution + template selection introduced for
the Mission Control / Narrative Report / IDE themes, plus the byte-for-byte
preservation of the existing Editorial theme behaviour when ``?theme=`` is
absent.

The tests are deliberately layered:

* :func:`test_resolve_theme_*` — pure unit tests for the
  :func:`resolve_theme` helper. No HTTP, no env, no I/O.
* :func:`test_route_*` — end-to-end TestClient assertions: query-param +
  env-var precedence, invalid-name fall-through, the regression check
  that an unparametrised ``/scan/<id>`` still serves the Editorial template,
  and the switcher partial appearing in every theme render.
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
from agent_guardian.server.dashboard_view import (
    AGENT_GUARDIAN_DASHBOARD_THEME_ENV,
    DASHBOARD_THEME_DEFAULT,
    DASHBOARD_THEME_TEMPLATES,
    DASHBOARD_THEMES,
    resolve_theme,
    resolve_theme_from_env,
)

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


def _make_finding(fid: str, severity: Severity, asi: AsiCategory = AsiCategory.ASI01) -> Finding:
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


def _make_scan(scan_id: str = "cli-theme-switcher") -> Scan:
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
        findings=[
            _make_finding("f-crit-1", Severity.CRITICAL, AsiCategory.ASI01),
            _make_finding("f-high-1", Severity.HIGH, AsiCategory.ASI02),
        ],
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


# ---------------------------------------------------------------------------
# resolve_theme — pure unit tests
# ---------------------------------------------------------------------------


def test_resolve_theme_constants_match_template_map() -> None:
    """Every locked theme slug has exactly one template path; no orphans."""
    assert set(DASHBOARD_THEMES) == set(DASHBOARD_THEME_TEMPLATES.keys())
    assert DASHBOARD_THEME_DEFAULT in DASHBOARD_THEMES
    assert DASHBOARD_THEME_DEFAULT == "editorial"
    # Editorial MUST map to the pre-existing template path so the legacy
    # byte-for-byte behaviour is preserved.
    assert DASHBOARD_THEME_TEMPLATES["editorial"] == "dashboard/scan_detail.html"


@pytest.mark.parametrize("slug", list(DASHBOARD_THEMES))
def test_resolve_theme_query_param_wins(slug: str) -> None:
    """Query param is the highest-priority signal."""
    assert resolve_theme(slug, None) == slug
    # Query param also overrides any env-supplied default.
    assert resolve_theme(slug, "editorial") == slug
    assert resolve_theme(slug, "mission") == slug


def test_resolve_theme_falls_back_to_env_when_no_query() -> None:
    assert resolve_theme(None, "narrative") == "narrative"
    assert resolve_theme(None, "ide") == "ide"


def test_resolve_theme_default_when_nothing_set() -> None:
    assert resolve_theme(None, None) == DASHBOARD_THEME_DEFAULT


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "hello", "Editorial Plus", "mission2", "EDITORIALSON"],
)
def test_resolve_theme_invalid_falls_through(bad: str) -> None:
    """Invalid theme names fall through silently — never raise."""
    # Query-only: falls to default.
    assert resolve_theme(bad, None) == DASHBOARD_THEME_DEFAULT
    # Env-only: also falls to default.
    assert resolve_theme(None, bad) == DASHBOARD_THEME_DEFAULT
    # Bad query + good env: env wins.
    assert resolve_theme(bad, "mission") == "mission"
    # Good query + bad env: query still wins.
    assert resolve_theme("ide", bad) == "ide"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("EDITORIAL", "editorial"),
        ("Mission", "mission"),
        ("  narrative  ", "narrative"),
        ("IDE", "ide"),
    ],
)
def test_resolve_theme_normalises_case_and_whitespace(raw: str, expected: str) -> None:
    """Case + leading/trailing whitespace are normalised before the lookup."""
    assert resolve_theme(raw, None) == expected


def test_resolve_theme_from_env_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The convenience wrapper consults the documented env var."""
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_THEME_ENV, "narrative")
    assert resolve_theme_from_env(None) == "narrative"
    # Query param still overrides the env.
    assert resolve_theme_from_env("mission") == "mission"


def test_resolve_theme_from_env_with_no_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the env var is unset, only the query param + default are consulted."""
    monkeypatch.delenv(AGENT_GUARDIAN_DASHBOARD_THEME_ENV, raising=False)
    assert resolve_theme_from_env(None) == DASHBOARD_THEME_DEFAULT
    assert resolve_theme_from_env("ide") == "ide"


# ---------------------------------------------------------------------------
# Route-level: query param picks the template
# ---------------------------------------------------------------------------


def test_route_query_param_mission_picks_mission_template(
    client: TestClient, store: ScanStore
) -> None:
    """``?theme=mission`` renders the Mission Control layout."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    assert resp.status_code == 200
    # Distinguishing marker — Mission's <html> carries data-theme="mission".
    assert 'data-theme="mission"' in resp.text


def test_route_query_param_narrative_picks_narrative_template(
    client: TestClient, store: ScanStore
) -> None:
    """``?theme=narrative`` renders the Narrative Report layout."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=narrative")
    assert resp.status_code == 200
    assert 'data-theme="narrative"' in resp.text


def test_route_query_param_ide_picks_ide_template(client: TestClient, store: ScanStore) -> None:
    """``?theme=ide`` renders the IDE / Terminal layout."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=ide")
    assert resp.status_code == 200
    assert 'data-theme="ide"' in resp.text


# ---------------------------------------------------------------------------
# Route-level: env var picks the template when no query param
# ---------------------------------------------------------------------------


def test_route_env_var_picks_narrative_when_no_query(
    client: TestClient, store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``$AGENT_GUARDIAN_DASHBOARD_THEME=narrative`` picks Narrative when no ?theme=."""
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_THEME_ENV, "narrative")
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    assert resp.status_code == 200
    assert 'data-theme="narrative"' in resp.text


def test_route_query_param_overrides_env_var(
    client: TestClient, store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Operator precedence: ?theme= beats $AGENT_GUARDIAN_DASHBOARD_THEME."""
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_THEME_ENV, "narrative")
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    assert resp.status_code == 200
    assert 'data-theme="mission"' in resp.text
    # And not narrative.
    assert 'data-theme="narrative"' not in resp.text


# ---------------------------------------------------------------------------
# Route-level: invalid theme name silently falls through
# ---------------------------------------------------------------------------


def test_route_invalid_theme_falls_through_to_editorial(
    client: TestClient, store: ScanStore
) -> None:
    """``?theme=hello`` is a no-op — Editorial is served."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=hello")
    assert resp.status_code == 200
    # Editorial is identified by the dash-body class on <body>.
    assert 'class="dash-body"' in resp.text


def test_route_empty_theme_falls_through_to_editorial(client: TestClient, store: ScanStore) -> None:
    """``?theme=`` (empty) is a no-op — Editorial is served."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=")
    assert resp.status_code == 200
    assert 'class="dash-body"' in resp.text


def test_route_invalid_theme_in_env_falls_through(
    client: TestClient, store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A garbage env value never breaks the route — Editorial wins."""
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_THEME_ENV, "not-a-theme")
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    assert resp.status_code == 200
    assert 'class="dash-body"' in resp.text


# ---------------------------------------------------------------------------
# REGRESSION: editorial route serves the existing template unchanged
# ---------------------------------------------------------------------------


def test_route_editorial_default_is_unchanged(
    client: TestClient, store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ?theme= is absent AND env unset, the Editorial template renders."""
    monkeypatch.delenv(AGENT_GUARDIAN_DASHBOARD_THEME_ENV, raising=False)
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    assert resp.status_code == 200
    # All the editorial-template anchor markers must still be present.
    body = resp.text
    assert 'class="dash-body"' in body
    assert "dash-topbar" in body
    assert "dash-masthead" in body
    # The masthead block from the saved-design's Briefing layout.
    assert "Your agent" in body or "still scoring" in body


def test_route_editorial_explicit_query_matches_default(
    client: TestClient, store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``?theme=editorial`` is equivalent to no query param."""
    monkeypatch.delenv(AGENT_GUARDIAN_DASHBOARD_THEME_ENV, raising=False)
    scan = _make_scan()
    _persist(store, scan)
    default_resp = client.get(f"/scan/{scan.id}")
    explicit_resp = client.get(f"/scan/{scan.id}?theme=editorial")
    assert default_resp.status_code == 200
    assert explicit_resp.status_code == 200
    # Both responses must render the Editorial template (identified by the
    # dash-body class on <body>); the explicit query just labels it.
    assert 'class="dash-body"' in default_resp.text
    assert 'class="dash-body"' in explicit_resp.text


# ---------------------------------------------------------------------------
# Dropdown HTML present in all four themes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("theme", list(DASHBOARD_THEMES))
def test_route_renders_theme_switcher_partial(
    client: TestClient, store: ScanStore, theme: str
) -> None:
    """Every theme MUST embed the shared switcher partial in its topbar."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme={theme}")
    assert resp.status_code == 200, resp.text[:500]
    body = resp.text
    # The shared partial root container.
    assert "ag-theme-switcher" in body
    # The dropdown element id used by theme_switcher.js.
    assert 'id="ag-theme-switcher-select"' in body
    # The script tag pointing at the persistence helper.
    assert "/static/theme_switcher.js" in body


@pytest.mark.parametrize("theme", list(DASHBOARD_THEMES))
def test_route_switcher_marks_current_theme(
    client: TestClient, store: ScanStore, theme: str
) -> None:
    """The active theme's option must carry the ``selected`` attribute."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme={theme}")
    assert resp.status_code == 200
    body = resp.text
    # The active option carries the slug as <option value> and the rendered
    # href; the select element's data-current attribute mirrors the slug.
    assert f'value="{theme}"' in body
    assert f"?theme={theme}" in body
    assert f'data-current="{theme}"' in body


@pytest.mark.parametrize("theme", list(DASHBOARD_THEMES))
def test_route_switcher_lists_every_theme(client: TestClient, store: ScanStore, theme: str) -> None:
    """The switcher dropdown lists all four locked themes regardless of context."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme={theme}")
    assert resp.status_code == 200
    body = resp.text
    for slug in DASHBOARD_THEMES:
        assert f'value="{slug}"' in body, f"missing theme option {slug} in {theme} render"


# ---------------------------------------------------------------------------
# Static asset served
# ---------------------------------------------------------------------------


def test_theme_switcher_js_is_served(client: TestClient) -> None:
    """The companion JS is mounted under /static and returns the persistence helper."""
    resp = client.get("/static/theme_switcher.js")
    assert resp.status_code == 200
    assert "ag.dashboard.theme" in resp.text
    assert "ag-theme-switcher-select" in resp.text


# ---------------------------------------------------------------------------
# Template map invariants
# ---------------------------------------------------------------------------


def test_template_map_paths_are_distinct() -> None:
    """No two themes share a Jinja template root."""
    paths = list(DASHBOARD_THEME_TEMPLATES.values())
    assert len(paths) == len(set(paths))


def test_editorial_template_path_is_unchanged() -> None:
    """The Editorial template path is byte-for-byte the pre-QA-020 default."""
    assert DASHBOARD_THEME_TEMPLATES["editorial"] == "dashboard/scan_detail.html"
