"""The recon probe corpus must actually EXECUTE at runtime.

``load_recon_probes()`` + the bundled ``recon/time-channel-fingerprint.yaml``
(RECON-TC-001) were schema-validated and unit-tested, but never called during a
real capability audit — so the time-channel inference-family fingerprint was
dead infrastructure. These tests pin that the audit now runs the latency-variance
recon probe (issues its stable question N times, measures per-call latency) and
records an inference-latency profile.
"""

from __future__ import annotations

import asyncio

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.core.capability_audit import (
    CapabilityAuditResult,
    _run_time_channel_probe,
    run_capability_audit,
)
from agent_guardian.llm.stub import StubLLM


class _RecordingTarget(TargetAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.prompts: list[str] = []

    def fingerprint(self) -> TargetFingerprint:
        return TargetFingerprint(mode="code", ref="x")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        self.prompts.append(prompt)
        return "The chemical symbol for water is H2O."

    async def aclose(self) -> None:
        return None


async def test_time_channel_probe_executes_and_records_profile() -> None:
    target = _RecordingTarget()
    result = CapabilityAuditResult()
    await _run_time_channel_probe(target, result, cancel_event=None, on_probe=None)

    # The probe's stable question was issued the corpus-mandated >=5 times.
    assert len(target.prompts) >= 5
    assert all("chemical symbol for water" in p for p in target.prompts)
    # A latency profile was recorded from those samples.
    prof = result.inference_latency_profile
    assert prof.get("samples", 0) >= 5
    assert prof.get("mean_ms", -1) >= 0.0
    assert prof.get("stdev_ms", -1) >= 0.0
    assert result.time_channel_signal in {"tight-cluster", "wide-variance"}


async def test_capability_audit_executes_recon_corpus() -> None:
    """End-to-end: a full capability audit now populates the inference-latency
    profile — the recon corpus is no longer dead at runtime."""
    target = _RecordingTarget()
    result = await run_capability_audit(
        target,
        llm=StubLLM(default="I am a banking assistant."),
        model="stub",
        max_deepen_rounds=1,
    )
    assert result.inference_latency_profile.get("samples", 0) >= 5


async def test_time_channel_probe_respects_cancel() -> None:
    target = _RecordingTarget()
    result = CapabilityAuditResult()
    ev = asyncio.Event()
    ev.set()  # pre-cancelled
    await _run_time_channel_probe(target, result, cancel_event=ev, on_probe=None)
    # Cancelled before any call — no samples, no profile.
    assert target.prompts == []
    assert result.inference_latency_profile == {}
