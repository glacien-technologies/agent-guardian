"""Unit tests for the canonical JSON encoder used by the signature pipeline.

The encoder is the byte-stable bridge between the in-memory Pydantic models
and the M13 HMAC + Ed25519 signing inputs. Anything subtle here breaks
reproducibility of signed reports across machines, so we exercise every
``_default`` branch.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

import pytest
from pydantic import BaseModel

from agent_guardian.reports.canonical import from_canonical_json, to_canonical_json


class _Color(Enum):
    RED = "red"
    GREEN = "green"


class _Toy(BaseModel):
    name: str
    score: int


def test_basic_round_trip_is_stable() -> None:
    payload = {"b": 2, "a": 1, "nested": {"y": [3, 1, 2], "x": "hi"}}
    encoded_once = to_canonical_json(payload)
    encoded_twice = to_canonical_json(payload)
    assert encoded_once == encoded_twice
    assert from_canonical_json(encoded_once) == payload
    # Keys are sorted; the "a" key precedes "b" in the byte stream.
    assert encoded_once.find(b'"a":1') < encoded_once.find(b'"b":2')


def test_aware_datetime_normalised_to_utc_zulu() -> None:
    dt = datetime(2026, 5, 27, 12, 0, tzinfo=UTC)
    encoded = to_canonical_json({"ts": dt})
    assert b'"ts":"2026-05-27T12:00:00Z"' in encoded


def test_naive_datetime_assumed_utc() -> None:
    dt = datetime(2026, 5, 27, 12, 0)  # No tzinfo.
    encoded = to_canonical_json({"ts": dt})
    assert b'"ts":"2026-05-27T12:00:00Z"' in encoded


def test_enum_reduced_to_value() -> None:
    encoded = to_canonical_json({"colour": _Color.RED})
    assert b'"colour":"red"' in encoded


def test_pydantic_model_reduced_via_model_dump() -> None:
    encoded = to_canonical_json({"toy": _Toy(name="alpha", score=9)})
    assert b'"name":"alpha"' in encoded
    assert b'"score":9' in encoded


def test_purepath_reduced_to_string() -> None:
    encoded = to_canonical_json({"p": Path("/tmp/some/where")})
    assert b'"p":"/tmp/some/where"' in encoded


def test_bytes_base64_encoded() -> None:
    raw = b"hello world"
    encoded = to_canonical_json({"blob": raw})
    expected = base64.b64encode(raw).decode("ascii")
    assert expected.encode("ascii") in encoded


def test_bytearray_base64_encoded() -> None:
    raw = bytearray(b"data")
    encoded = to_canonical_json({"blob": raw})
    expected = base64.b64encode(bytes(raw)).decode("ascii")
    assert expected.encode("ascii") in encoded


def test_set_sorted_by_string() -> None:
    encoded = to_canonical_json({"tags": {"z", "a", "m"}})
    # Sorted ascending by string representation.
    assert encoded.index(b'"a"') < encoded.index(b'"m"') < encoded.index(b'"z"')


def test_frozenset_sorted_by_string() -> None:
    encoded = to_canonical_json({"tags": frozenset({"z", "a"})})
    assert encoded.index(b'"a"') < encoded.index(b'"z"')


def test_unknown_type_raises_typeerror() -> None:
    class _NotEncodable:
        pass

    with pytest.raises(TypeError, match="not canonical-JSON serialisable"):
        to_canonical_json({"bad": _NotEncodable()})
