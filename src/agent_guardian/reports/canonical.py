"""Canonical JSON serialisation (PRD §11.2, M13).

The signature flow requires a *stable* byte representation of a payload so
HMAC-SHA256 / Ed25519 signatures verify reproducibly across machines and
Python versions. The rules below are an RFC 8785-flavour subset that's
sufficient for AgentGuardian payloads:

* keys sorted lexicographically;
* no whitespace between tokens;
* UTF-8 with ASCII-safe escaping disabled (``ensure_ascii=False``);
* :class:`datetime` is normalised to UTC and rendered as ``YYYY-MM-DDTHH:MM:SS[.ffffff]Z``;
* :class:`enum.Enum` is reduced to its ``.value``;
* :class:`pydantic.BaseModel` is reduced via ``.model_dump(mode="json")``;
* :class:`pathlib.PurePath` is reduced to ``str(path)``;
* :class:`bytes` is base64-encoded (we don't expect raw bytes inside report
  payloads, but the encoder accepts them defensively).

Anything else raises :class:`TypeError` — explicit failure beats silent
inconsistency.
"""

from __future__ import annotations

import base64
import dataclasses
import json
from datetime import UTC, datetime
from enum import Enum
from pathlib import PurePath
from typing import Any

from pydantic import BaseModel

__all__ = ["from_canonical_json", "to_canonical_json"]


def _default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        # Always render as UTC; if naive, assume UTC.
        dt = obj.replace(tzinfo=UTC) if obj.tzinfo is None else obj.astimezone(UTC)
        return dt.isoformat().replace("+00:00", "Z")
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    # WHY: ProbeAttachment is a frozen dataclass that may ride through a Probe.
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, PurePath):
        return str(obj)
    if isinstance(obj, bytes | bytearray):
        return base64.b64encode(bytes(obj)).decode("ascii")
    if isinstance(obj, set | frozenset):
        return sorted(obj, key=str)
    raise TypeError(f"Object of type {type(obj).__name__} is not canonical-JSON serialisable")


def to_canonical_json(obj: Any) -> bytes:
    """Serialise ``obj`` to canonical JSON bytes.

    The output is sorted-key, whitespace-free, UTF-8 — the same bytes from any
    process given the same logical input, suitable for HMAC / signature input.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_default,
        allow_nan=False,
    ).encode("utf-8")


def from_canonical_json(data: bytes) -> Any:
    """Inverse of :func:`to_canonical_json` for round-trip parsing."""
    return json.loads(data.decode("utf-8"))
