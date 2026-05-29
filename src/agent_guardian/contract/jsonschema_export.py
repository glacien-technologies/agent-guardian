"""JSON Schema export for the contract (Stage 1A).

Editors and CI can validate a contract document against a published JSON
Schema. We generate it from the Pydantic model so the schema can never drift
from the code, and stamp a stable ``$id`` so the schema is self-identifying.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_guardian.contract.schema import CURRENT_CONTRACT_VERSION, Contract

__all__ = ["CONTRACT_SCHEMA_ID", "contract_json_schema", "write_contract_json_schema"]

CONTRACT_SCHEMA_ID = (
    f"https://schemas.glacien.ai/agent-guardian/contract/v{CURRENT_CONTRACT_VERSION}.json"
)


def contract_json_schema() -> dict[str, Any]:
    """Return the JSON Schema for :class:`Contract`, stamped with a ``$id``."""
    schema = Contract.model_json_schema()
    schema["$id"] = CONTRACT_SCHEMA_ID
    schema.setdefault("$schema", "https://json-schema.org/draft/2020-12/schema")
    schema.setdefault("title", "AgentGuardian Contract")
    return schema


def write_contract_json_schema(path: Path, *, indent: int = 2) -> Path:
    """Write the contract JSON Schema to ``path`` (pretty-printed) and return it."""
    schema = contract_json_schema()
    path.write_text(json.dumps(schema, indent=indent, sort_keys=True) + "\n", encoding="utf-8")
    return path
