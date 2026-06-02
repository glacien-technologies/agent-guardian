"""Request-body templating for HTTP transports (Stage 1A).

Operators describe a target's request body as a Jinja2 template that renders to
a JSON document. We expose three variables to the template:

* ``prompt`` — the current user turn, **already JSON-escaped** (no surrounding
  quotes) so ``{"input": "{{ prompt }}"}`` is valid even when the prompt
  contains quotes, backslashes, or newlines.
* ``session`` — the opaque session token (escaped the same way; empty string
  when ``None``).
* ``conversation`` — a ready-to-embed JSON array literal of
  ``{"role": ..., "content": ...}`` objects for prior turns, so a template can
  splice multi-turn history with ``"messages": {{ conversation }}``.

A ``json`` filter is also registered for advanced templates that want to embed
an arbitrary value safely (``{{ value | json }}``).

The rendered string is parsed with :func:`json.loads`; a non-object result or a
JSON syntax error raises :class:`agent_guardian.llm.errors.LLMPermanentError`
(it is a configuration bug, not a transport fault). Templates run with autoescape
**off** — we are producing JSON, not HTML — but every interpolated value is
pre-escaped via :func:`json.dumps`, which is the correct escaping for the JSON
context.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any

import jinja2

from agent_guardian.llm.errors import LLMPermanentError
from agent_guardian.transports.base import Message

__all__ = ["json_escape", "render_body"]

_LOG = logging.getLogger(__name__)


def json_escape(value: str) -> str:
    """JSON-encode ``value`` and strip the surrounding quotes.

    The result is safe to drop *between* quotes inside a JSON template, e.g.
    ``"input": "{{ prompt }}"``. Quotes, backslashes and control characters are
    escaped per the JSON spec.
    """
    return json.dumps(value)[1:-1]


def _conversation_json(conversation: Sequence[Message]) -> str:
    """Render prior turns as a compact JSON array literal."""
    return json.dumps(
        [{"role": m.role, "content": m.content} for m in conversation],
        ensure_ascii=False,
    )


def render_body(
    template: str,
    *,
    prompt: str,
    session: str | None = None,
    conversation: Sequence[Message] = (),
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Render a Jinja2 JSON ``template`` to a request-body dict.

    Args:
      template: Jinja2 source that renders to a JSON object.
      prompt: current user turn (exposed pre-escaped as ``prompt``).
      session: opaque session token (exposed pre-escaped as ``session``).
      conversation: prior turns (exposed as a JSON array literal ``conversation``).
      extra: additional template variables (merged last; raw, not pre-escaped —
        use the ``json`` filter for these).

    Returns:
      The parsed JSON object as a ``dict``.

    Raises:
      LLMPermanentError: the template is invalid, or renders to invalid JSON,
        or to a non-object. These are configuration errors, not transport faults.
    """
    # Output is JSON, never HTML — every interpolated value is JSON-escaped via
    # the ``json`` filter or ``json_escape()`` upstream. Enabling HTML autoescape
    # would corrupt the JSON (e.g. turn ``"`` into ``&quot;`` mid-string).
    # Output is application/json sent to upstream LLM HTTP APIs (NOT a
    # browser). HTML autoescape would corrupt JSON (e.g. `"` -> `&quot;`
    # mid-string). All user-controlled values are JSON-escaped via the
    # `json` filter or json_escape() helper before interpolation, which is
    # the correct escaping for JSON context. StrictUndefined ensures
    # missing vars fail loud.
    env = jinja2.Environment(  # nosec B701 — JSON output, values pre-escaped via json filter
        autoescape=False,  # nosemgrep: python.jinja2.security.audit.autoescape-disabled-false.incorrect-autoescape-disabled — see comment above; JSON output, not browser
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=False,
    )
    env.filters["json"] = lambda value: json.dumps(value, ensure_ascii=False)

    context: dict[str, Any] = {
        "prompt": json_escape(prompt),
        "session": json_escape(session if session is not None else ""),
        "conversation": _conversation_json(conversation),
    }
    if extra:
        context.update(extra)

    try:
        rendered = env.from_string(template).render(**context)
    except jinja2.TemplateError as exc:
        _LOG.debug("transport: request template render error (%s)", exc)
        raise LLMPermanentError(f"transport: request template error: {exc}") from exc

    try:
        body = json.loads(rendered)
    except json.JSONDecodeError as exc:
        _LOG.debug("transport: rendered template is not valid JSON (%s)", exc)
        raise LLMPermanentError(
            f"transport: request template is not valid JSON after rendering: {exc}"
        ) from exc

    if not isinstance(body, dict):
        raise LLMPermanentError("transport: request template must render to a JSON object")
    return body
