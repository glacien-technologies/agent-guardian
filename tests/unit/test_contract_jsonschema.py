"""Unit tests for contract JSON-Schema export (Stage 1)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from agent_guardian.contract.jsonschema_export import (
    CONTRACT_SCHEMA_ID,
    contract_json_schema,
    write_contract_json_schema,
)


def test_schema_generates_dict() -> None:
    schema = contract_json_schema()
    assert isinstance(schema, dict)
    assert "properties" in schema


def test_schema_has_id() -> None:
    schema = contract_json_schema()
    assert schema["$id"] == CONTRACT_SCHEMA_ID
    assert schema["$id"].startswith("https://")


def test_schema_declares_dialect_and_title() -> None:
    schema = contract_json_schema()
    assert urlparse(schema["$schema"]).hostname == "json-schema.org"
    assert schema["title"]


def test_schema_describes_top_level_properties() -> None:
    schema = contract_json_schema()
    props = schema["properties"]
    for field in ("version", "target", "roe", "observability", "extensions"):
        assert field in props


def test_schema_includes_nested_definitions() -> None:
    schema = contract_json_schema()
    defs = schema.get("$defs", {})
    # The full tree's models must surface in $defs.
    for model in ("Target", "HttpTransport", "RoE", "Response", "ApiKeyAuth", "HmacAuth"):
        assert model in defs


def test_write_schema_round_trips(tmp_path: Path) -> None:
    out = tmp_path / "contract.schema.json"
    returned = write_contract_json_schema(out)
    assert returned == out
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["$id"] == CONTRACT_SCHEMA_ID
    # Pretty-printed + trailing newline.
    assert out.read_text(encoding="utf-8").endswith("}\n")
