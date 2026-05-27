"""HTTP shape registry and built-in provider shapes."""

from __future__ import annotations

import logging

from agent_guardian.adapters.http_shapes import (
    agentcore_shape,
    anthropic_shape,
    bedrock_shape,
    generic_shape,
    openai_shape,
    vertex_shape,
)
from agent_guardian.adapters.http_shapes.base import (
    HttpShape,
    RequestBuilder,
    ResponseExtractor,
    get_shape,
    list_shapes,
    register_shape,
)

__all__ = [
    "HttpShape",
    "RequestBuilder",
    "ResponseExtractor",
    "get_shape",
    "list_shapes",
    "register_shape",
]

_LOG = logging.getLogger(__name__)


def _register_builtins() -> None:
    for shape in (
        openai_shape.SHAPE,
        anthropic_shape.SHAPE,
        bedrock_shape.SHAPE,
        vertex_shape.SHAPE,
        agentcore_shape.SHAPE,
        generic_shape.SHAPE,
    ):
        # Already-registered is fine for test re-imports — log at DEBUG so
        # the trace shows it without raising about a benign re-registration.
        try:
            register_shape(shape)
        except ValueError as exc:
            _LOG.debug(
                "http_shapes: shape %s already registered (%s) — skipping",
                shape.name,
                exc,
            )


_register_builtins()
