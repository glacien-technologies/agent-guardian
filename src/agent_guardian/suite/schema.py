"""Pydantic schema for the suite YAML — a strict, orchestration-only contract.

Every workload field maps 1:1 onto a real ``agent-guardian scan`` flag (see
``argv.py``) or is an orchestration-only knob (``env`` / ``timeout_seconds`` /
``workdir`` / ``formats``) consumed by the runner itself. ``extra="forbid"``
everywhere so a typo'd flag fails loudly at load time instead of being silently
dropped into a scan that then behaves unexpectedly.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# The report formats the scan / report commands accept. Kept in lockstep with
# cli.py ``_ALL_FORMATS`` — validated here so a bad format fails at suite-load,
# not three minutes into a scan when the report writer rejects it.
ALL_FORMATS: frozenset[str] = frozenset({"json", "sarif", "junit", "md", "gitlab", "pdf"})


def _check_formats(value: list[str] | None) -> list[str] | None:
    if value is None:
        return None
    bad = [f for f in value if f not in ALL_FORMATS]
    if bad:
        raise ValueError(f"unknown report format(s) {bad}; choose from {sorted(ALL_FORMATS)}")
    return value


class WorkloadFields(BaseModel):
    """All scan knobs (optional) plus orchestration-only fields.

    Used for BOTH ``defaults`` (nothing required) and each ``workloads[]`` entry
    (``name`` + exactly one target mode required *after* defaults are merged in —
    that post-merge check lives in ``resolve.py``, not here, because defaults can
    legitimately supply part of the picture).
    """

    model_config = ConfigDict(extra="forbid")

    # identity
    name: str | None = None

    # target modes — exactly one required post-merge (resolve.py enforces)
    target: str | None = None
    endpoint: str | None = None
    system_prompt: str | None = None
    framework: str | None = None
    framework_ref: str | None = None
    contract: str | None = None

    # models
    model: str | None = None
    commander_model: str | None = None
    attacker_model: str | None = None
    evaluator_model: str | None = None

    # thoroughness / shaping
    mode: str | None = None
    tier: str | None = None
    goal: str | None = None
    seed: int | None = None
    max_turns: int | None = None
    no_owasp_llm: bool | None = None
    no_preflight: bool | None = None
    pov_gate: bool | None = None
    critic: bool | None = None
    pretext: bool | None = None
    indirect: bool | None = None
    log_agent_io: bool | None = None
    otel_endpoint: str | None = None

    # budgets
    budget_usd: float | None = None
    budget_seconds: float | None = None
    recon_budget_seconds: float | None = None

    # gates (each can flip the child's exit code)
    fail_under: int | None = None
    max_critical: int | None = None
    max_high: int | None = None
    max_medium: int | None = None
    max_low: int | None = None

    # deliverables (orchestration-only)
    formats: list[str] | None = None

    # orchestration-only (NOT scan flags)
    env: dict[str, str] | None = None
    timeout_seconds: float | None = None
    workdir: str | None = None

    @field_validator("formats")
    @classmethod
    def _formats_ok(cls, value: list[str] | None) -> list[str] | None:
        return _check_formats(value)


class SuiteConfig(BaseModel):
    """Suite-level orchestration settings (not a scan)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    concurrency: int | None = Field(
        default=None, gt=0, description="max scans in flight; default min(N, cpu_count)"
    )
    isolate_home: bool = True
    fail_fast: bool = False
    out_dir: str = "./suite-out"
    reports_dir: str | None = None  # default: <out_dir>/reports
    formats: list[str] = Field(default_factory=lambda: ["json"])
    register_scans: bool = True
    serve: bool = False
    budget_usd_total: float | None = Field(default=None, gt=0)
    exit_code: Literal["any-gate-fail", "all-pass", "always-zero"] = "any-gate-fail"

    @field_validator("formats")
    @classmethod
    def _formats_ok(cls, value: list[str]) -> list[str]:
        return _check_formats(value) or []


class SuiteFile(BaseModel):
    """Top-level suite document."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    suite: SuiteConfig
    defaults: WorkloadFields = Field(default_factory=WorkloadFields)
    workloads: list[WorkloadFields] = Field(min_length=1)

    @model_validator(mode="after")
    def _names_present_and_unique(self) -> SuiteFile:
        names: list[str] = []
        for i, wl in enumerate(self.workloads):
            if not wl.name:
                raise ValueError(f"workloads[{i}] is missing a 'name'")
            names.append(wl.name)
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"duplicate workload names: {dupes}")
        return self
