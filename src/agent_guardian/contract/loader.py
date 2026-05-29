"""Contract loading + discovery (Stage 1A).

The loader is the single entry point for turning an on-disk contract document
into a validated :class:`~agent_guardian.contract.schema.Contract`.

Order of operations (the *version gate comes first*):

1. Read the YAML into a mapping (mirrors :func:`config._read_yaml`).
2. Inspect the declared ``version`` *before* building the model:
   * unknown / far-future version → :class:`UnsupportedContractVersion`;
   * known-older version → :class:`MigrationNeeded` (migration is a later stage).
3. Validate the mapping into a :class:`Contract`; wrap any Pydantic error in
   :class:`ContractValidationError`.

Discovery is deliberately narrow for Stage 1A: only ``./agentguardian.yaml`` in
the current working directory. (Note the *no-dot* filename — distinct from the
CLI's ``.agentguardian.yaml`` config file.)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_guardian.contract.errors import (
    ContractValidationError,
    MigrationNeeded,
    UnsupportedContractVersion,
)
from agent_guardian.contract.schema import (
    CURRENT_CONTRACT_VERSION,
    MAX_KNOWN_CONTRACT_VERSION,
    Contract,
)

__all__ = [
    "CONTRACT_FILENAME",
    "discover_contract_path",
    "load_contract",
    "load_contract_file",
    "parse_contract",
]

_LOG = logging.getLogger(__name__)

CONTRACT_FILENAME = "agentguardian.yaml"


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read a YAML file into a top-level mapping.

    Mirrors :func:`agent_guardian.config._read_yaml`: empty file → ``{}``,
    ``None`` document → ``{}``, non-mapping top level → ``ValueError``.
    """
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) if text.strip() else {}
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"contract file {path} must contain a YAML mapping at the top level")
    return data


def _gate_version(version: Any) -> None:
    """Reject unsupported versions *before* model validation.

    * Non-int / version 0 or below → :class:`UnsupportedContractVersion`.
    * The current version → accepted (no raise).
    * A *known* version that isn't current (``!= CURRENT`` but within
      ``[1, MAX_KNOWN]``) → :class:`MigrationNeeded`.
    * A version beyond :data:`MAX_KNOWN_CONTRACT_VERSION` → hard
      :class:`UnsupportedContractVersion` ("upgrade your build").
    """
    if not isinstance(version, int) or isinstance(version, bool):
        raise UnsupportedContractVersion(
            f"contract 'version' must be an integer (got {version!r})",
            found=None,
            supported=CURRENT_CONTRACT_VERSION,
        )
    if version < 1:
        raise UnsupportedContractVersion(
            f"contract version {version} is not a valid version",
            found=version,
            supported=CURRENT_CONTRACT_VERSION,
        )
    if version == CURRENT_CONTRACT_VERSION:
        return
    if version > MAX_KNOWN_CONTRACT_VERSION:
        raise UnsupportedContractVersion(
            f"contract version {version} is beyond the maximum version this build "
            f"recognises ({MAX_KNOWN_CONTRACT_VERSION}); upgrade AgentGuardian",
            found=version,
            supported=CURRENT_CONTRACT_VERSION,
        )
    # Known, non-current version → migration required (Stage 1A ships only the
    # skeleton, so this is currently always a loud signal).
    raise MigrationNeeded(
        f"contract version {version} requires migration to the current version "
        f"{CURRENT_CONTRACT_VERSION}",
        found=version,
        target=CURRENT_CONTRACT_VERSION,
    )


def parse_contract(data: dict[str, Any]) -> Contract:
    """Validate an already-parsed mapping into a :class:`Contract`.

    Runs the version gate first, then Pydantic validation. Any validation
    failure is re-raised as :class:`ContractValidationError`.
    """
    _gate_version(data.get("version", CURRENT_CONTRACT_VERSION))
    try:
        return Contract.model_validate(data)
    except ValidationError as exc:
        _LOG.debug("contract: model validation failed (%s)", exc)
        raise ContractValidationError(f"contract failed validation:\n{exc}") from exc


def load_contract_file(path: Path) -> Contract:
    """Load + validate a contract from an explicit file path."""
    if not path.is_file():
        raise ContractValidationError(f"contract file not found: {path}")
    try:
        data = _read_yaml(path)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        _LOG.debug("contract: could not read %s (%s)", path, exc)
        raise ContractValidationError(f"could not read contract file {path}: {exc}") from exc
    return parse_contract(data)


def discover_contract_path(explicit: Path | None = None) -> Path | None:
    """Resolve which contract file to load.

    Stage 1A discovery is narrow: the explicit path if given, otherwise
    ``./agentguardian.yaml`` in the current working directory (only).
    """
    if explicit is not None:
        return explicit
    candidate = Path.cwd() / CONTRACT_FILENAME
    if candidate.is_file():
        return candidate
    return None


def load_contract(path: Path | None = None) -> Contract:
    """Load a contract from ``path`` or via cwd discovery.

    Raises:
        ContractValidationError: no contract file was found, or it failed
            to read / validate.
        UnsupportedContractVersion / MigrationNeeded: version gate tripped.
    """
    resolved = discover_contract_path(path)
    if resolved is None:
        raise ContractValidationError(
            f"no contract found: expected ./{CONTRACT_FILENAME} or an explicit path"
        )
    return load_contract_file(resolved)
