"""HTTP shape registry — provider-shaped request/response templates (PRD §7).

Each registered :class:`HttpShape` is a pair of pure functions:

* ``build_request(prompt, *, model, session, extra)`` → JSON-serialisable
  body dict.
* ``extract_response_text(response_json)`` → assistant text string.

The functions are kept pure so they can be unit-tested without network
access; the actual HTTP transport (request signing, retry, timeouts) lives
in :class:`agent_guardian.adapters.http.HttpAdapter` and is finished in M9.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = [
    "HttpShape",
    "RequestBuilder",
    "ResponseExtractor",
    "get_shape",
    "list_shapes",
    "register_shape",
]

RequestBuilder = Callable[..., dict[str, Any]]
ResponseExtractor = Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class HttpShape:
    """Provider-specific HTTP request/response shape."""

    name: str
    build_request: RequestBuilder
    extract_response_text: ResponseExtractor
    auth_header_name: str | None = None
    auth_header_format: str | None = None


_SHAPES: dict[str, HttpShape] = {}


def register_shape(shape: HttpShape) -> None:
    """Register a shape under its ``name``. Re-registration is an error."""
    if shape.name in _SHAPES:
        raise ValueError(f"HTTP shape already registered: {shape.name!r}")
    _SHAPES[shape.name] = shape


def get_shape(name: str) -> HttpShape:
    """Look up a registered shape by name. Raises :class:`KeyError` if missing."""
    try:
        return _SHAPES[name]
    except KeyError as exc:
        available = ", ".join(sorted(_SHAPES)) or "<none>"
        raise KeyError(f"Unknown HTTP shape: {name!r}. Registered: {available}.") from exc


def list_shapes() -> list[str]:
    """Return the sorted names of all registered shapes."""
    return sorted(_SHAPES)
