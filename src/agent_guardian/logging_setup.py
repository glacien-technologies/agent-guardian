"""Centralized logging configuration for AgentGuardian.

Honors ``AGENT_GUARDIAN_LOG_LEVEL`` env var (per PRD §8.3). The CLI calls
:func:`configure_logging` at the top of every command; the runner harness
calls it as well. Library callers can invoke directly.

Default: ``INFO``. Set ``AGENT_GUARDIAN_LOG_LEVEL=DEBUG`` for the full
review trace — every per-turn strategy decision, per-probe recon signal,
per-LLM-call payload size, per-memory-write record. ``WARNING`` and above
quiets the per-turn detail but keeps phase transitions and fallback
notifications.

Design notes
------------

* **Single source of truth.** Modules across the package use
  ``logging.getLogger(__name__)`` — they pick up whatever this module
  configures. Library users who do not call :func:`configure_logging`
  see no output by default (Python's logging "no-handler" default).
* **Idempotent.** Repeat calls without ``force=True`` are no-ops. The
  CLI calls this on every sub-command; the runner calls it on import;
  tests that want a different level pass ``force=True``.
* **Noisy-dep gating.** ``httpx``, ``httpcore``, ``urllib3`` and the
  Gemini SDK emit DEBUG lines for every HTTP byte by default. We pin
  them to ``max(level, INFO)`` unless the operator explicitly asked
  for DEBUG (in which case the noise is intentional and useful).
"""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import IO

_CONFIGURED = False
_DEFAULT_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-5s %(name)-48s %(message)s"
_DEFAULT_DATEFMT = "%H:%M:%S"

ENV_VAR = "AGENT_GUARDIAN_LOG_LEVEL"

_REDACTED = "***REDACTED***"

# Secrets that must never reach the logs. httpx logs request URLs at INFO, and
# Gemini/Google pass the API key in the query string (``?key=...``) -- so
# without this every scan wrote the user's key to stderr. We cover three shapes:
#   1. sensitive query params (key/api_key/access_token/token/sig/signature)
#   2. ``Authorization: Bearer <token>`` headers
#   3. bare provider key shapes anywhere in the line (Google AIza..., OpenAI/
#      Anthropic sk-...), as defence-in-depth for any path we didn't anticipate.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)([?&](?:key|api[_-]?key|access_token|token|sig|signature)=)[^&\s\"']+"),
        r"\1" + _REDACTED,
    ),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)\S+"), r"\1" + _REDACTED),
    (re.compile(r"AIza[0-9A-Za-z_\-]{10,}"), _REDACTED),
    (re.compile(r"sk-(?:ant-)?[A-Za-z0-9_\-]{12,}"), _REDACTED),
)


def redact_secrets(text: str) -> str:
    """Mask API keys / bearer tokens in a log line, preserving the surrounding
    text (e.g. ``?key=AIza...`` -> ``?key=***REDACTED***``)."""
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


class _RedactingFilter(logging.Filter):
    """Scrubs secrets from every record before it is formatted/emitted.

    Operates on the fully-rendered message (``record.getMessage()``) so it
    catches secrets passed as ``%s`` args -- which is exactly how httpx logs
    request URLs -- then collapses the record to a redacted literal.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover -- malformed record; let it through
            return True
        redacted = redact_secrets(rendered)
        if redacted != rendered:
            record.msg = redacted
            record.args = ()
        return True


def _resolve_level(level: str | int | None) -> int:
    """Resolve a level spec (env var, str, int, or None) to a logging int."""
    if level is None:
        level = os.environ.get(ENV_VAR, "INFO").upper()
    if isinstance(level, str):
        # Tolerate "info"/"INFO"/"Info" + numeric strings ("20").
        upper = level.upper()
        attr = getattr(logging, upper, None)
        if isinstance(attr, int):
            return attr
        try:
            return int(level)
        except ValueError:
            return logging.INFO
    return int(level)


def configure_logging(
    level: str | int | None = None,
    *,
    stream: IO[str] | None = None,
    force: bool = False,
) -> None:
    """Configure root logging once per process.

    Args:
      level: log level (str like ``"DEBUG"``/``"INFO"`` or int). If None,
        reads ``AGENT_GUARDIAN_LOG_LEVEL`` env var; falls back to ``"INFO"``.
      stream: where to write logs (default: ``sys.stderr``).
      force: reconfigure even if already configured (useful in tests).
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    resolved = _resolve_level(level)
    logging.basicConfig(
        level=resolved,
        stream=stream or sys.stderr,
        format=_DEFAULT_FORMAT,
        datefmt=_DEFAULT_DATEFMT,
        force=True,
    )
    # Scrub secrets (API keys / bearer tokens) from every record. Attached to
    # the root handlers so it covers our own logs AND chatty deps like httpx
    # that log request URLs containing ``?key=...``.
    redactor = _RedactingFilter()
    for handler in logging.getLogger().handlers:
        handler.addFilter(redactor)
    # Quiet down chatty deps unless the operator explicitly asked for DEBUG.
    if resolved > logging.DEBUG:
        for noisy in ("httpx", "httpcore", "urllib3", "google_genai.models"):
            logging.getLogger(noisy).setLevel(max(resolved, logging.INFO))
    _CONFIGURED = True


def is_configured() -> bool:
    """Return True if :func:`configure_logging` has run in this process."""
    return _CONFIGURED


def _reset_for_tests() -> None:
    """Drop the configured flag so the next call reconfigures. Test-only."""
    global _CONFIGURED
    _CONFIGURED = False
