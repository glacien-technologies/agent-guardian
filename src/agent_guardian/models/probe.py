"""Probe model and YAML loader.

A probe defines a single, self-contained attack template. The schema matches
PRD §5.2. The :func:`load_probe` loader enforces the triple-framework gate
required by the PRD: ``asi``, ``mitre_atlas`` (non-empty), and ``csa_category``
are mandatory; missing or empty values raise :class:`ProbeValidationError`.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.mitre import MitreTechnique
from agent_guardian.models.multimodal import ProbeAttachment
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
    # OWASP-2026 scenario citation (CC-4). Optional for backward compat with
    # legacy probes; Phase B probes are required to populate this.
    owasp_scenario: str | None = None
    # Phase C.C4a — multimodal attachments riding alongside the seed text.
    # Tuple default keeps the model frozen+hashable; empty default preserves
    # existing canonical-JSON / signed-bundle hashes for all current probes.
    attachments: tuple[ProbeAttachment, ...] = ()

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)


def _format_pydantic_errors(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(item) for item in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)


def _build_attachment_from_dict(
    item: dict[str, Any],
    *,
    base_dir: Path | None,
    source: str,
    idx: int,
) -> ProbeAttachment:
    """Construct a ProbeAttachment from a YAML mapping.

    Accepts two payload modes:
      - inline ``b64_payload`` + ``size_bytes`` (already-encoded bytes), OR
      - ``path``: a relative path to a sibling binary asset, resolved
        against ``base_dir`` (the probe YAML's parent). When ``path`` is
        used the loader reads the file, base64-encodes it, and computes
        ``size_bytes`` automatically.

    ``mime_type`` and ``alt_text`` are required either way. Mixing ``path``
    with ``b64_payload`` is rejected as ambiguous.
    """
    mime_type = item.get("mime_type")
    alt_text = item.get("alt_text")
    path_value = item.get("path")
    b64_value = item.get("b64_payload")

    if path_value is not None and b64_value is not None:
        raise ProbeValidationError(
            f"Probe in {source}: attachments[{idx}] cannot set both 'path' and "
            "'b64_payload' — pick exactly one payload source"
        )

    if path_value is not None:
        # Sibling-file mode: read + b64-encode at load time.
        if base_dir is None:
            raise ProbeValidationError(
                f"Probe in {source}: attachments[{idx}] uses 'path' but probe "
                "has no on-disk parent (loaded inline?) — switch to 'b64_payload'"
            )
        asset_path = (base_dir / str(path_value)).resolve()
        try:
            base_resolved = base_dir.resolve()
            asset_path.relative_to(base_resolved)
        except ValueError as exc:
            # WHY: refuse to walk outside the probe's directory.
            raise ProbeValidationError(
                f"Probe in {source}: attachments[{idx}] path {path_value!r} "
                "escapes the probe directory — refusing to load"
            ) from exc
        if not asset_path.is_file():
            raise ProbeValidationError(
                f"Probe in {source}: attachments[{idx}] sibling asset not found: {asset_path}"
            )
        raw_bytes = asset_path.read_bytes()
        try:
            return ProbeAttachment(
                mime_type=str(mime_type) if mime_type is not None else "",
                b64_payload=base64.b64encode(raw_bytes).decode("ascii"),
                alt_text=str(alt_text) if alt_text is not None else "",
                size_bytes=len(raw_bytes),
            )
        except (TypeError, ValueError) as exc:
            raise ProbeValidationError(
                f"Probe in {source}: attachments[{idx}] invalid: {exc}"
            ) from exc

    # Inline-b64 mode: pass through directly. size_bytes must be supplied.
    try:
        return ProbeAttachment(**item)
    except (TypeError, ValueError) as exc:
        raise ProbeValidationError(f"Probe in {source}: attachments[{idx}] invalid: {exc}") from exc


def _coerce_attachments(
    raw: Any, *, source: str, base_dir: Path | None
) -> tuple[ProbeAttachment, ...] | None:
    """Convert dict-shaped attachments into ProbeAttachment instances.

    Returns None when no attachments key is present (caller leaves the field
    at its default empty tuple). YAML loads attachments as a list-of-mappings;
    pydantic with arbitrary_types_allowed=True will NOT auto-build the
    dataclass, so we do the conversion here before model_validate. Raises a
    ProbeValidationError on malformed shapes — bubbles up through load_probe.

    ``base_dir`` resolves sibling-file ``path`` entries when present; pass
    None when loading from an in-memory dict (no on-disk context).
    """
    if "attachments" not in raw:
        return None
    items = raw["attachments"]
    if items is None or items == []:
        return ()
    if not isinstance(items, list):
        raise ProbeValidationError(
            f"Probe in {source}: attachments must be a list, got {type(items).__name__}"
        )
    out: list[ProbeAttachment] = []
    for idx, item in enumerate(items):
        if isinstance(item, ProbeAttachment):
            out.append(item)
            continue
        if not isinstance(item, dict):
            raise ProbeValidationError(
                f"Probe in {source}: attachments[{idx}] must be a mapping, "
                f"got {type(item).__name__}"
            )
        out.append(_build_attachment_from_dict(item, base_dir=base_dir, source=source, idx=idx))
    return tuple(out)


def _coerce_probe(raw: Any, *, source: str, base_dir: Path | None = None) -> Probe:
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

    # WHY: pydantic with arbitrary_types_allowed won't build the dataclass for us.
    coerced = _coerce_attachments(raw, source=source, base_dir=base_dir)
    if coerced is not None:
        raw = {**raw, "attachments": coerced}

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
    return _coerce_probe(raw, source=str(path), base_dir=path.parent)


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
