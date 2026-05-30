"""Operational endpoints: ``/healthz``, ``/readyz``, ``/metrics``.

These three URLs are the bare-minimum surface every container orchestrator
expects. We hand-roll all three rather than pulling in ``prometheus_client``
so the dashboard's base install stays narrow (no extra dependency, no
binary wheel) and so the exposition is fully under our control — the
Prometheus text format is intentionally simple.

Endpoints
---------

* ``GET /healthz`` — liveness. Returns ``200 {"status":"ok","version":...}``
  whenever the process is responsive. Never touches disk. Kubernetes
  ``livenessProbe`` should point here.
* ``GET /readyz`` — readiness. Verifies that the scan store's root directory
  exists and is writable. Returns ``200`` when ready, ``503`` with a
  ``{"status":"unavailable","reason":...}`` body otherwise so the orchestrator
  can mark the pod NotReady without restarting it. Kubernetes
  ``readinessProbe`` should point here.
* ``GET /metrics`` — Prometheus exposition (``text/plain; version=0.0.4``).
  Six metrics:
      - ``agentguardian_scans_total`` (counter)
      - ``agentguardian_scans_running`` (gauge)
      - ``agentguardian_scan_duration_seconds`` (histogram, one bucketed series)
      - ``agentguardian_findings_total{severity}`` (counter, labelled)
      - ``agentguardian_llm_calls_total{provider}`` (counter, labelled)
      - ``agentguardian_llm_errors_total{provider}`` (counter, labelled)

  The counters are process-local and reset on restart — sufficient for the
  single-worker dashboard deployment that M12 ships. Multi-worker setups
  should aggregate in their LB or move to a Pushgateway.

The metrics registry exposed by :func:`get_metrics_registry` is the single
source of truth other server modules can publish to. The scan store
:meth:`ScanStore.register` increments ``scans_running``; the scan-done
observer decrements it and bumps ``scans_total`` + the duration histogram.
LLM clients can call :meth:`MetricsRegistry.observe_llm_call` /
:meth:`observe_llm_error` to publish provider-labelled counts.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from agent_guardian._version import __version__
from agent_guardian.server.routes._deps import get_scan_store

__all__ = ["MetricsRegistry", "get_metrics_registry", "router"]

_LOG = logging.getLogger(__name__)

router = APIRouter()


# Default histogram buckets (seconds). Chosen for adversarial-swarm scans
# that range from a fast unit-stub scan (~1s) to a multi-hour deep PoV
# (4h ceiling). The ``+Inf`` bucket is implicit per Prometheus convention.
_DEFAULT_DURATION_BUCKETS: tuple[float, ...] = (
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
    120.0,
    300.0,
    600.0,
    1800.0,
    3600.0,
    14400.0,
)


@dataclass
class MetricsRegistry:
    """Process-local Prometheus-compatible metrics aggregator.

    Thread-safe (uses a single :class:`threading.Lock` for all mutating
    operations) since FastAPI/uvicorn may schedule observers across worker
    threads. The mutations are tiny (dict increment, list compare) so a
    single lock has negligible contention compared with the cost of each
    metric event itself.
    """

    duration_buckets: tuple[float, ...] = field(default_factory=lambda: _DEFAULT_DURATION_BUCKETS)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _scans_total: int = 0
    _scans_running: int = 0
    _duration_bucket_counts: list[int] = field(init=False)
    _duration_sum: float = 0.0
    _duration_count: int = 0
    _findings_total: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _llm_calls_total: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _llm_errors_total: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def __post_init__(self) -> None:
        # One bucket counter per bucket + an implicit +Inf (handled in render).
        self._duration_bucket_counts = [0] * len(self.duration_buckets)

    # -- observers -----------------------------------------------------------

    def inc_scans_running(self) -> None:
        with self._lock:
            self._scans_running += 1

    def dec_scans_running(self) -> None:
        with self._lock:
            if self._scans_running > 0:
                self._scans_running -= 1

    def observe_scan_complete(self, duration_seconds: float) -> None:
        """Record one finished scan + its wall-clock duration."""
        if duration_seconds < 0.0:
            duration_seconds = 0.0
        with self._lock:
            self._scans_total += 1
            self._duration_sum += duration_seconds
            self._duration_count += 1
            for i, edge in enumerate(self.duration_buckets):
                if duration_seconds <= edge:
                    self._duration_bucket_counts[i] += 1

    def observe_finding(self, severity: str) -> None:
        normalised = _label_value(severity).lower()
        with self._lock:
            self._findings_total[normalised] += 1

    def observe_llm_call(self, provider: str) -> None:
        with self._lock:
            self._llm_calls_total[_label_value(provider)] += 1

    def observe_llm_error(self, provider: str) -> None:
        with self._lock:
            self._llm_errors_total[_label_value(provider)] += 1

    # -- exposition ----------------------------------------------------------

    def render(self) -> str:
        """Return a Prometheus 0.0.4 text-format exposition snapshot."""
        with self._lock:
            scans_total = self._scans_total
            scans_running = self._scans_running
            duration_sum = self._duration_sum
            duration_count = self._duration_count
            buckets = list(zip(self.duration_buckets, self._duration_bucket_counts, strict=True))
            findings = dict(self._findings_total)
            llm_calls = dict(self._llm_calls_total)
            llm_errors = dict(self._llm_errors_total)

        lines: list[str] = []
        lines.append("# HELP agentguardian_scans_total Completed scans observed by the dashboard.")
        lines.append("# TYPE agentguardian_scans_total counter")
        lines.append(f"agentguardian_scans_total {scans_total}")

        lines.append("# HELP agentguardian_scans_running Currently running scans registered.")
        lines.append("# TYPE agentguardian_scans_running gauge")
        lines.append(f"agentguardian_scans_running {scans_running}")

        lines.append("# HELP agentguardian_scan_duration_seconds Scan wall-clock duration.")
        lines.append("# TYPE agentguardian_scan_duration_seconds histogram")
        cumulative = 0
        for edge, count in buckets:
            cumulative += count
            lines.append(
                f'agentguardian_scan_duration_seconds_bucket{{le="{_le_label(edge)}"}} {count}'
            )
        # The "+Inf" bucket equals the total count by Prometheus convention.
        lines.append(f'agentguardian_scan_duration_seconds_bucket{{le="+Inf"}} {duration_count}')
        lines.append(f"agentguardian_scan_duration_seconds_sum {duration_sum}")
        lines.append(f"agentguardian_scan_duration_seconds_count {duration_count}")

        lines.append("# HELP agentguardian_findings_total Findings observed, labelled by severity.")
        lines.append("# TYPE agentguardian_findings_total counter")
        if findings:
            for severity, count in sorted(findings.items()):
                lines.append(f'agentguardian_findings_total{{severity="{severity}"}} {count}')
        else:
            lines.append('agentguardian_findings_total{severity="none"} 0')

        lines.append("# HELP agentguardian_llm_calls_total LLM calls, labelled by provider.")
        lines.append("# TYPE agentguardian_llm_calls_total counter")
        if llm_calls:
            for provider, count in sorted(llm_calls.items()):
                lines.append(f'agentguardian_llm_calls_total{{provider="{provider}"}} {count}')
        else:
            lines.append('agentguardian_llm_calls_total{provider="none"} 0')

        lines.append("# HELP agentguardian_llm_errors_total LLM errors, labelled by provider.")
        lines.append("# TYPE agentguardian_llm_errors_total counter")
        if llm_errors:
            for provider, count in sorted(llm_errors.items()):
                lines.append(f'agentguardian_llm_errors_total{{provider="{provider}"}} {count}')
        else:
            lines.append('agentguardian_llm_errors_total{provider="none"} 0')

        return "\n".join(lines) + "\n"


def _label_value(raw: str | None) -> str:
    """Sanitise a Prometheus label value (no quotes, backslashes, newlines)."""
    if raw is None:
        return "unknown"
    s = str(raw).strip() or "unknown"
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ")


def _le_label(edge: float) -> str:
    # Render integer-valued buckets without trailing ".0" so the exposition
    # matches the Prometheus convention seen in client_python.
    if edge.is_integer():
        return str(int(edge))
    return repr(edge)


def get_metrics_registry(request: Request) -> MetricsRegistry:
    """Return (or lazily create) the app-scoped :class:`MetricsRegistry`.

    Stashed on ``app.state.metrics`` so a single process shares one
    registry across requests.
    """
    existing = getattr(request.app.state, "metrics", None)
    if isinstance(existing, MetricsRegistry):
        return existing
    registry = MetricsRegistry()
    request.app.state.metrics = registry
    return registry


# ---------------------------------------------------------------------------
# /healthz
# ---------------------------------------------------------------------------


@router.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    """Liveness probe. Always cheap; never touches disk."""
    return JSONResponse({"status": "ok", "version": __version__})


# ---------------------------------------------------------------------------
# /readyz
# ---------------------------------------------------------------------------


@router.get("/readyz", include_in_schema=False)
async def readyz(request: Request) -> JSONResponse:
    """Readiness probe. Verifies the scan store root is usable.

    Returns ``503`` when the root directory is missing, not a directory, or
    not writable so the orchestrator can flag the pod NotReady without
    restarting it (the writable-FS condition is recoverable once a volume
    re-attaches).
    """
    store = get_scan_store(request)
    root = store.root
    if not root.exists():
        return JSONResponse(
            {
                "status": "unavailable",
                "reason": f"scan store root does not exist: {root}",
            },
            status_code=503,
        )
    if not root.is_dir():
        return JSONResponse(
            {
                "status": "unavailable",
                "reason": f"scan store root is not a directory: {root}",
            },
            status_code=503,
        )
    if not os.access(root, os.W_OK):
        return JSONResponse(
            {
                "status": "unavailable",
                "reason": f"scan store root is not writable: {root}",
            },
            status_code=503,
        )
    return JSONResponse(
        {
            "status": "ok",
            "version": __version__,
            "scan_store_root": str(root),
        }
    )


# ---------------------------------------------------------------------------
# /metrics
# ---------------------------------------------------------------------------


# Prometheus 0.0.4 text exposition media type — pinned in the response so
# scrapers without content negotiation still parse correctly.
_PROM_CONTENT_TYPE: str = "text/plain; version=0.0.4; charset=utf-8"


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> PlainTextResponse:
    """Prometheus exposition."""
    registry = get_metrics_registry(request)
    # Touch the wall clock so cardinality-free scrape latency tracking is
    # possible from the scraper's own histograms. The exposition itself is
    # synchronous so we measure the assembly cost only.
    _t0 = time.monotonic()
    body = registry.render()
    _LOG.debug("metrics exposition assembled in %.3fms", (time.monotonic() - _t0) * 1000)
    return PlainTextResponse(body, media_type=_PROM_CONTENT_TYPE)
