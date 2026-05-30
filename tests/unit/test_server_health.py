"""Tests for /healthz, /readyz, /metrics + the metrics registry.

These verify the operational surface every container orchestrator expects:
liveness, readiness, and a Prometheus-text exposition. The exposition is
hand-rolled (no ``prometheus_client`` dep) so we also assert the format is
parseable in the shape Prometheus scrapers require.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from agent_guardian import __version__
from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.routes.health import (
    MetricsRegistry,
    _label_value,
    _le_label,
    get_metrics_registry,
)


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


# ---------------------------------------------------------------------------
# /healthz — liveness
# ---------------------------------------------------------------------------


def test_healthz_returns_ok_with_version(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_healthz_does_not_touch_disk(client: TestClient, tmp_path: Path) -> None:
    """Liveness must succeed even if the scan store root vanishes."""
    # We can't actually unmount the fs, but we can blow away the root and
    # confirm liveness still reports ok — the readiness probe should be the
    # only check that flips to 503 in this state.
    app = client.app
    store = app.state.scan_store  # type: ignore[union-attr]
    # Remove the root directory the fixture set up.
    if store.root.exists():
        for child in store.root.iterdir():
            if child.is_file():
                child.unlink()
        store.root.rmdir()
    resp = client.get("/healthz")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /readyz — readiness
# ---------------------------------------------------------------------------


def test_readyz_ok_when_root_is_writable(client: TestClient, store: ScanStore) -> None:
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["scan_store_root"] == str(store.root)


def test_readyz_503_when_root_missing(client: TestClient, store: ScanStore) -> None:
    if store.root.exists():
        for child in store.root.iterdir():
            if child.is_file():
                child.unlink()
        store.root.rmdir()
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "unavailable"
    assert "does not exist" in body["reason"]


def test_readyz_503_when_root_not_a_directory(
    tmp_path: Path,
) -> None:
    # Point the store at a regular file rather than a directory.
    fake_root = tmp_path / "not-a-dir"
    fake_root.write_text("x", encoding="utf-8")
    store = ScanStore(root_dir=fake_root)
    app = create_app(scan_store=store)
    client = TestClient(app)
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert "not a directory" in body["reason"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX chmod semantics required")
def test_readyz_503_when_root_not_writable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "ro-root"
    root.mkdir()
    # 0o555: r-x for owner, no write.
    root.chmod(stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)
    try:
        store = ScanStore(root_dir=root)
        app = create_app(scan_store=store)
        client = TestClient(app)
        resp = client.get("/readyz")
        # CI runs as root in some setups; root can write to anything. Skip in
        # that case rather than asserting a false negative.
        if resp.status_code == 200:
            pytest.skip("running as root: writable check inapplicable")
        assert resp.status_code == 503
        assert "not writable" in resp.json()["reason"]
    finally:
        root.chmod(stat.S_IRWXU)


# ---------------------------------------------------------------------------
# /metrics — Prometheus exposition format
# ---------------------------------------------------------------------------


def test_metrics_exposes_prometheus_content_type(client: TestClient) -> None:
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "version=0.0.4" in resp.headers["content-type"]


def test_metrics_exposition_has_required_series(client: TestClient) -> None:
    resp = client.get("/metrics")
    body = resp.text
    for name in (
        "agentguardian_scans_total",
        "agentguardian_scans_running",
        "agentguardian_scan_duration_seconds_bucket",
        "agentguardian_scan_duration_seconds_sum",
        "agentguardian_scan_duration_seconds_count",
        "agentguardian_findings_total",
        "agentguardian_llm_calls_total",
        "agentguardian_llm_errors_total",
    ):
        assert name in body, f"missing series: {name}"
    # Every metric has both # HELP and # TYPE lines (Prometheus convention).
    assert body.count("# HELP ") == body.count("# TYPE ")


def test_metrics_includes_plus_inf_bucket(client: TestClient) -> None:
    resp = client.get("/metrics")
    assert 'agentguardian_scan_duration_seconds_bucket{le="+Inf"}' in resp.text


def test_metrics_reflect_registry_state(client: TestClient) -> None:
    """An observed scan-complete bumps both the counter and histogram."""
    registry = client.app.state.metrics  # type: ignore[union-attr]
    assert isinstance(registry, MetricsRegistry)
    registry.observe_scan_complete(1.5)
    registry.observe_scan_complete(60.0)
    registry.observe_finding("HIGH")
    registry.observe_finding("high")  # case-insensitive
    registry.observe_llm_call("openai")
    registry.observe_llm_error("openai")

    body = client.get("/metrics").text
    assert "agentguardian_scans_total 2" in body
    # 1.5 + 60 = 61.5 (rendered as a float)
    sum_match = re.search(r"agentguardian_scan_duration_seconds_sum (\S+)", body)
    assert sum_match is not None
    assert float(sum_match.group(1)) == pytest.approx(61.5)
    assert "agentguardian_scan_duration_seconds_count 2" in body
    # Both findings landed in the "high" bucket (the helper lower-cases).
    assert 'agentguardian_findings_total{severity="high"} 2' in body
    assert 'agentguardian_llm_calls_total{provider="openai"} 1' in body
    assert 'agentguardian_llm_errors_total{provider="openai"} 1' in body


def test_metrics_reflects_running_scan_lifecycle(client: TestClient, store: ScanStore) -> None:
    """register/scan_done flip the scans_running gauge + bump scans_total."""

    class FakeSwarm:
        observer = None

    # Initial state.
    body = client.get("/metrics").text
    assert "agentguardian_scans_running 0" in body

    fake = FakeSwarm()
    store.register("scan-metrics", fake)  # type: ignore[arg-type]
    body = client.get("/metrics").text
    assert "agentguardian_scans_running 1" in body
    assert "agentguardian_scans_total 0" in body

    # Drive the observer through to scan_done — register rewired observer
    # onto the fake instance, and that closure decrements the gauge and
    # bumps the histogram.
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    from agent_guardian.core.swarm import SwarmEvent

    assert fake.observer is not None
    fake.observer(
        SwarmEvent(
            kind="scan_done",  # type: ignore[arg-type]
            timestamp=_dt(2026, 5, 30, 12, 0, 0, tzinfo=_tz.utc),
        )
    )
    body = client.get("/metrics").text
    assert "agentguardian_scans_running 0" in body
    assert "agentguardian_scans_total 1" in body


def test_metrics_observe_scan_complete_clamps_negative_duration() -> None:
    registry = MetricsRegistry()
    registry.observe_scan_complete(-5.0)
    body = registry.render()
    assert "agentguardian_scans_total 1" in body
    # Negative duration is clamped to 0.
    assert "agentguardian_scan_duration_seconds_sum 0.0" in body


def test_metrics_label_value_sanitises_quotes_and_newlines() -> None:
    assert _label_value('a"b') == 'a\\"b'
    assert _label_value("a\\b") == "a\\\\b"
    assert _label_value("a\nb") == "a b"
    assert _label_value(None) == "unknown"
    assert _label_value("") == "unknown"


def test_metrics_le_label_renders_int_when_possible() -> None:
    assert _le_label(1.0) == "1"
    assert _le_label(60.0) == "60"
    assert _le_label(0.5) == repr(0.5)


def test_get_metrics_registry_idempotent() -> None:
    """Calling the dependency twice returns the same registry."""
    fake_app = SimpleNamespace(state=SimpleNamespace())
    fake_request = SimpleNamespace(app=fake_app)
    r1 = get_metrics_registry(fake_request)  # type: ignore[arg-type]
    r2 = get_metrics_registry(fake_request)  # type: ignore[arg-type]
    assert r1 is r2


# ---------------------------------------------------------------------------
# Metrics — empty state still emits valid Prometheus 0.0.4 lines
# ---------------------------------------------------------------------------


def test_metrics_empty_findings_emits_zero_series(client: TestClient) -> None:
    body = client.get("/metrics").text
    # An entirely empty findings map still emits one labelled line so
    # scrapers don't get a series-missing surprise on a fresh restart.
    assert 'agentguardian_findings_total{severity="none"} 0' in body
    assert 'agentguardian_llm_calls_total{provider="none"} 0' in body
    assert 'agentguardian_llm_errors_total{provider="none"} 0' in body
