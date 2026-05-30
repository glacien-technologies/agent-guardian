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
from typing import IO, Any

_LOG = logging.getLogger(__name__)

_CONFIGURED = False
# Trace-correlation fields are stamped onto every LogRecord by the factory
# installed in ``_install_trace_correlation_factory``. When no OTel span is
# active they're empty strings so the formatter renders ``[trace=]`` rather
# than crashing on a missing attribute.
_DEFAULT_FORMAT = (
    "%(asctime)s.%(msecs)03d %(levelname)-5s %(name)-48s [trace=%(trace_id)s] %(message)s"
)
_DEFAULT_DATEFMT = "%H:%M:%S"

ENV_VAR = "AGENT_GUARDIAN_LOG_LEVEL"
JSON_ENV_VAR = "AGENT_GUARDIAN_LOG_JSON"

# Truthy tokens for the JSON-logging env var. Anything else (including unset,
# empty, "false", "0") leaves the stdlib formatter path in place.
_JSON_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on"})

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


def _json_logging_enabled() -> bool:
    """True iff ``AGENT_GUARDIAN_LOG_JSON`` is set to a truthy token."""
    raw = os.environ.get(JSON_ENV_VAR, "").strip().lower()
    return raw in _JSON_TRUTHY


def _install_trace_correlation_factory() -> None:
    """Stamp ``trace_id`` / ``span_id`` / ``trace_flags`` on every LogRecord.

    Wraps the current :func:`logging.getLogRecordFactory` so every record
    carries the W3C-formatted trace ID (32 hex chars), span ID (16 hex chars),
    and trace flags (2 hex chars) of the OTel span active *at the moment the
    log is written*. When no span is active — or the OTel SDK is absent — all
    three default to the empty string so the formatter never KeyErrors.

    Idempotent: calling this twice does not stack a second wrapper. The marker
    is set on the wrapper function itself so we can detect "we already wrapped"
    even across module reloads.
    """
    existing = logging.getLogRecordFactory()
    if getattr(existing, "_agent_guardian_trace_wrapped", False):
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = existing(*args, **kwargs)
        trace_id, span_id, flags = _current_trace_context()
        record.trace_id = trace_id
        record.span_id = span_id
        record.trace_flags = flags
        return record

    factory._agent_guardian_trace_wrapped = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(factory)


def _current_trace_context() -> tuple[str, str, str]:
    """Return ``(trace_id, span_id, trace_flags)`` for the active OTel span.

    Each value is an empty string when no span is active or the SDK is absent
    — we NEVER raise from the log factory, because a sick tracer must never
    break logging (and an exception in the factory would break every log line
    in the process).
    """
    try:
        from opentelemetry import trace
    except ImportError:
        return ("", "", "")
    try:
        span = trace.get_current_span()
        ctx = span.get_span_context()
    except Exception:
        # ``get_current_span`` itself shouldn't raise, but a third-party
        # provider could ship a buggy span; degrade to empty rather than break
        # every subsequent log line.
        _LOG.debug("otel trace-context fetch failed; logs will have no trace_id", exc_info=True)
        return ("", "", "")
    if not getattr(ctx, "is_valid", False):
        return ("", "", "")
    # Format per W3C trace-context: trace-id is 32 hex chars, span-id 16,
    # trace-flags 2. ``ctx`` carries them as ints from the SDK.
    trace_id = format(ctx.trace_id, "032x")
    span_id = format(ctx.span_id, "016x")
    flags = format(int(ctx.trace_flags), "02x")
    return (trace_id, span_id, flags)


def _configure_structlog_json(level: int, stream: IO[str]) -> None:
    """Configure structlog + stdlib to emit one JSON object per log line.

    Bridges stdlib records through a structlog ``ProcessorFormatter`` on the
    root handler so logs from libraries (httpx, OTel, our own modules using
    ``logging.getLogger``) flow through the same JSON pipeline as structlog
    calls. NEVER raises: if structlog is not importable, falls back silently
    to the stdlib path (the caller stays default-on).

    Processors (in order):

    #. ``merge_contextvars`` — pull thread-/task-local contextvars into the
       event dict (so request-scoped fields show up without re-binding).
    #. ``add_log_level`` — flatten ``logger.info(...)`` -> ``level=info``.
    #. ``add_logger_name`` — stamp the logger name (``__name__``).
    #. ``TimeStamper(iso, utc)`` — ISO-8601 UTC timestamp.
    #. trace correlation — stamp the W3C trace_id / span_id from the active
       span so JSON logs correlate with OTel exports.
    #. redaction — scrub API keys / bearer tokens (same patterns as the
       stdlib path) before they ever hit a renderer.
    #. ``JSONRenderer`` — one JSON object per line.
    """
    try:
        import structlog
    except ImportError:
        _LOG.debug("structlog unavailable; falling back to stdlib JSON path")
        return

    def _add_trace_context(
        _logger: object, _method_name: str, event_dict: dict[str, Any]
    ) -> dict[str, Any]:
        trace_id, span_id, flags = _current_trace_context()
        if trace_id:
            event_dict["trace_id"] = trace_id
            event_dict["span_id"] = span_id
            event_dict["trace_flags"] = flags
        return event_dict

    def _redact_processor(
        _logger: object, _method_name: str, event_dict: dict[str, Any]
    ) -> dict[str, Any]:
        event = event_dict.get("event")
        if isinstance(event, str):
            event_dict["event"] = redact_secrets(event)
        # Also scrub any string values in the event dict — provider keys often
        # ride along as ``api_key=...`` kwargs to ``logger.info(...)``.
        for key, value in list(event_dict.items()):
            if isinstance(value, str) and key != "event":
                event_dict[key] = redact_secrets(value)
        return event_dict

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_trace_context,
        _redact_processor,
    ]

    # structlog's PrintLoggerFactory expects a ``TextIO``; ``IO[str]`` is the
    # broader stdlib alias the rest of this module uses for ``stream``. The
    # cast is safe at runtime — structlog only ever calls ``write`` / ``flush``,
    # both of which are on ``IO[str]``.
    from typing import TextIO, cast

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=cast(TextIO, stream)),
        cache_logger_on_first_use=True,
    )

    # Bridge stdlib -> structlog so library logs (httpx, opentelemetry, etc.)
    # land in the same JSON pipeline. ``ProcessorFormatter`` renders each
    # stdlib record through the same processor chain and a JSON renderer.
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )
    root = logging.getLogger()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    # Replace any existing handlers so we don't double-emit (one JSON line +
    # one human line per record).
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)


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
    effective_stream = stream or sys.stderr
    # Install the trace-correlation factory BEFORE basicConfig — once it's in
    # place, every subsequent LogRecord (including the one basicConfig itself
    # may emit) carries trace_id/span_id/trace_flags. The factory is idempotent
    # so repeat configure_logging calls (e.g. force=True in tests) don't stack.
    _install_trace_correlation_factory()
    if _json_logging_enabled():
        # Replace stdlib formatting with structlog JSON. Operators set this in
        # production / container deployments where a JSON log shipper is the
        # log sink; the stdlib human-readable path stays the default for local
        # development.
        _configure_structlog_json(resolved, effective_stream)
    else:
        logging.basicConfig(
            level=resolved,
            stream=effective_stream,
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
