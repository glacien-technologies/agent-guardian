"""Load + validate a suite YAML, expanding ``${ENV}`` references in scalars."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_guardian.suite.errors import SuiteConfigError
from agent_guardian.suite.schema import SuiteFile


def _expand(value: Any) -> Any:
    """Recursively expand ``${VAR}`` / ``$VAR`` in every string scalar.

    Unknown variables are left verbatim (``os.path.expandvars`` semantics) so a
    missing key surfaces as an obvious literal rather than a silent empty string.
    """
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def load_suite_file(path: str | Path) -> SuiteFile:
    """Parse ``path`` into a validated :class:`SuiteFile`."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SuiteConfigError(f"cannot read suite file {p}: {exc}") from exc

    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise SuiteConfigError(f"invalid YAML in {p}: {exc}") from exc

    if not isinstance(doc, dict):
        raise SuiteConfigError(f"suite file {p} must be a YAML mapping at the top level")

    try:
        return SuiteFile.model_validate(_expand(doc))
    except ValidationError as exc:
        raise SuiteConfigError(f"invalid suite config in {p}:\n{exc}") from exc
