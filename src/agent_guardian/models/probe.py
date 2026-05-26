"""Probe model and YAML loader.

A probe defines a single, self-contained attack template. The schema matches
PRD §5.2. The :func:`load_probe` loader enforces the triple-framework gate
required by the PRD: ``asi``, ``mitre_atlas`` (non-empty), and ``csa_category``
are mandatory; missing or empty values raise :class:`ProbeValidationError`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.mitre import MitreTechnique
from agent_guardian.models.severity import Severity
from agent_guardian.models.tier import Tier

__all__ = ["Probe", "ProbeValidationError", "load_probe", "load_probes_from_dir"]


class ProbeValidationError(ValueError):
    """Raised when a probe YAML fails schema validation.

    The string representation includes the failing field path(s) where possible.
    """


class Probe(BaseModel):
    """Single attack probe definition (PRD §5.2)."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    asi: AsiCategory
    mitre_atlas: list[MitreTechnique] = Field(min_length=1)
    csa_category: CsaCategory
    severity: Severity
    tier_floor: Tier
    seeds: list[str] = Field(min_length=1)
    description: str = Field(min_length=1)
    expected_evidence: str = Field(min_length=1)
    remediation_ref: str = Field(min_length=1)
    references: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True, extra="forbid")


def _format_pydantic_errors(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(item) for item in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)


def _coerce_probe(raw: Any, *, source: str) -> Probe:
    if not isinstance(raw, dict):
        raise ProbeValidationError(
            f"Probe in {source}: expected a YAML mapping at top level, got {type(raw).__name__}"
        )

    # Triple-framework gate: explicit, deterministic checks before pydantic.
    for required in ("asi", "csa_category"):
        if required not in raw or raw[required] in (None, ""):
            raise ProbeValidationError(f"Probe in {source}: missing required field {required!r}")
    mitre_value = raw.get("mitre_atlas")
    if mitre_value is None or (isinstance(mitre_value, list) and len(mitre_value) == 0):
        raise ProbeValidationError(f"Probe in {source}: mitre_atlas must be a non-empty list")

    try:
        return Probe.model_validate(raw)
    except ValidationError as exc:
        raise ProbeValidationError(f"Probe in {source}: {_format_pydantic_errors(exc)}") from exc


def load_probe(path: Path) -> Probe:
    """Load and validate a single probe YAML file.

    Raises:
        ProbeValidationError: if the file isn't valid YAML or fails schema validation.
        FileNotFoundError: if the path does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Probe file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProbeValidationError(f"Probe in {path}: YAML parse error: {exc}") from exc
    if raw is None:
        raise ProbeValidationError(f"Probe in {path}: file is empty")
    return _coerce_probe(raw, source=str(path))


def load_probes_from_dir(directory: Path) -> list[Probe]:
    """Recursively load every ``*.yaml`` and ``*.yml`` probe under ``directory``.

    Probes are sorted by ``id`` for deterministic ordering.

    Raises:
        FileNotFoundError: if ``directory`` does not exist.
        ProbeValidationError: if any probe fails validation.
    """
    if not directory.exists():
        raise FileNotFoundError(f"Probe directory not found: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    candidates = sorted([*directory.rglob("*.yaml"), *directory.rglob("*.yml")])
    probes = [load_probe(path) for path in candidates]
    probes.sort(key=lambda p: p.id)
    return probes
