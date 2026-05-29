"""Transport-kind registry (Stage 1A).

A tiny name → :class:`Transport` factory registry so callers can construct a
transport by string kind (``"http"``) without importing the concrete class.
Mirrors the pattern used by :mod:`agent_guardian.adapters.http_shapes.base`.

The registry intentionally maps to *factories* (callables returning a
:class:`Transport`) rather than classes, so future kinds with different
construction signatures can be wired in without changing the lookup surface.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from agent_guardian.transports.base import Transport
from agent_guardian.transports.http import HttpTransport

__all__ = [
    "TransportFactory",
    "build_transport",
    "get_transport_factory",
    "list_transport_kinds",
    "register_transport",
]

_LOG = logging.getLogger(__name__)

TransportFactory = Callable[..., Transport]

_REGISTRY: dict[str, TransportFactory] = {}


def register_transport(kind: str, factory: TransportFactory) -> None:
    """Register a transport ``factory`` under ``kind``. Re-registration errors."""
    if kind in _REGISTRY:
        raise ValueError(f"transport kind already registered: {kind!r}")
    _REGISTRY[kind] = factory


def get_transport_factory(kind: str) -> TransportFactory:
    """Look up a registered factory by kind. Raises :class:`KeyError` if missing."""
    try:
        return _REGISTRY[kind]
    except KeyError as exc:
        available = ", ".join(sorted(_REGISTRY)) or "<none>"
        _LOG.debug("transport: unknown kind %r requested (registered: %s)", kind, available)
        raise KeyError(f"Unknown transport kind: {kind!r}. Registered: {available}.") from exc


def build_transport(kind: str, **kwargs: Any) -> Transport:
    """Construct a transport of ``kind`` with the given keyword arguments."""
    return get_transport_factory(kind)(**kwargs)


def list_transport_kinds() -> list[str]:
    """Return the sorted names of all registered transport kinds."""
    return sorted(_REGISTRY)


register_transport("http", HttpTransport)
