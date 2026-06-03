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
  Gemini SDK emit an INFO line for every HTTP request (and DEBUG
  lines for every byte). At INFO that drowns the swarm-board signal
  (QA-019). We pin them to ``max(level, WARNING)`` so the default
  INFO scan is quiet; the operator can opt in to the network-level
  trace via ``AGENT_GUARDIAN_LOG_LEVEL=DEBUG`` (root falls to DEBUG
  and the pin is lifted) or by calling
  ``logging.getLogger("httpx").setLevel(logging.INFO)`` after
  ``configure_logging`` returns.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from typing import IO, Any

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

_LOG = logging.getLogger(__name__)

_CONFIGURED = False
# Process-singleton Console (QA-002 F-1). Constructed lazily on first
# ``get_console()`` call. ALL Rich rendering — the Live region, the URL
# emitter, the reflection sink, and the RichHandler stdlib bridge — must
# route through this one instance so log lines and Live updates share
# the same stdout owner; without that, the smoking-gun border-tear
# regression from QA-002 reappears.
_CONSOLE: Console | None = None

# QA-002 design-lock palette. Keeps brand colour (deep violet #8B5CF6),
# status pills, severity bands, AIVSS bands, and the ten stable ASI
# tokens in one place so the CLI Live region, log lines, and the (future
# QA-005) reflection sink all paint with the same vocabulary.
_AG_THEME: Theme = Theme(
    {
        "brand": "#8B5CF6",
        "brand.dim": "#6366F1",
        "status.pending": "dim",
        "status.running": "cyan",
        "status.done": "green",
        "status.error": "red",
        "status.skipped": "yellow",
        "sev.critical": "bold red",
        "sev.high": "red",
        "sev.medium": "yellow",
        "sev.low": "dim",
        "verdict.pass": "green",
        "verdict.fail": "red",
        "verdict.inconclusive": "yellow",
        "aivss.low": "green",
        "aivss.med": "yellow",
        "aivss.high": "red",
        "aivss.none": "dim",
        "asi.ASI01": "magenta",
        "asi.ASI02": "cyan",
        "asi.ASI03": "yellow",
        "asi.ASI04": "blue",
        "asi.ASI05": "red",
        "asi.ASI06": "green",
        "asi.ASI07": "bright_magenta",
        "asi.ASI08": "bright_cyan",
        "asi.ASI09": "bright_yellow",
        "asi.ASI10": "bright_blue",
    }
)


def _stderr_is_tty() -> bool:
    """Return True iff ``sys.stderr`` looks like an interactive terminal.

    Used to decide whether to install :class:`RichHandler` (TTY) or fall
    back to the plain :class:`logging.StreamHandler` (CI, pipe, file).
    """
    try:
        return bool(sys.stderr.isatty())
    except Exception:  # pragma: no cover -- exotic stream
        return False


def _color_disabled() -> bool:
    """Honour ``NO_COLOR`` (https://no-color.org/) — any non-empty value disables colour."""
    return bool(os.environ.get("NO_COLOR"))


def get_console() -> Console:
    """Return the process-singleton CLI :class:`rich.console.Console`.

    First call constructs it with :data:`_AG_THEME`; subsequent calls
    return the same instance. Tests can override by assigning
    :data:`_CONSOLE` directly (then resetting in teardown).
    """
    global _CONSOLE
    if _CONSOLE is None:
        _CONSOLE = Console(
            theme=_AG_THEME,
            stderr=False,
            no_color=_color_disabled(),
        )
    return _CONSOLE


def _reset_console_for_tests() -> None:
    """Drop the cached Console so the next ``get_console()`` constructs fresh."""
    global _CONSOLE
    _CONSOLE = None


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


# CR/LF and other ASCII control characters must be stripped from any
# user-controlled value before it is rendered into a log line, otherwise an
# attacker can inject newlines to forge log entries (CWE-117).
_LOG_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_for_log(value: object, *, max_len: int = 256) -> str:
    """Return a log-safe representation of ``value``.

    Strips ASCII control characters (including CR/LF/TAB) which would let an
    attacker forge log entries, and clamps the result so a single user-supplied
    value can't blow out the log line. The result is also passed through the
    secret redactor for defence in depth.
    """
    text = value if isinstance(value, str) else repr(value)
    text = _LOG_CONTROL_RE.sub("?", text)
    if len(text) > max_len:
        text = text[:max_len] + "...[truncated]"
    return redact_secrets(text)


# Truncation cap for the full request/response bodies logged at DEBUG by the
# provider clients via :func:`log_model_exchange`. Generous on purpose: the
# operator-feedback complaint was that the old ``text[:80]`` truncation hid the
# actual prompt and response, so the cap has to be large enough to read a real
# system prompt + tool-call argument. Still bounded so a runaway response can't
# write megabytes per call into the log.
MODEL_EXCHANGE_LOG_CAP = 4000


def log_model_request(
    logger: logging.Logger,
    *,
    provider: str,
    model: str,
    n_messages: int,
    max_tokens: int | None,
    temperature: float | None = None,
    seed: int | None = None,
    request_body: object | None = None,
) -> None:
    """Log the start of one model call (the "request out" half), shared by all providers.

    Emits the single INFO narration line that feeds the operator's swarm-board
    — the ONLY place the provider + model name is stamped, so the paired
    :func:`log_model_response` line does not repeat it. At DEBUG it then dumps
    the full request that was actually sent (capped at
    :data:`MODEL_EXCHANGE_LOG_CAP` and run through :func:`sanitize_for_log` so
    API keys / control chars stay safe) — not the old ``[:80]`` truncation.

    Args:
      logger: the provider's module logger.
      provider: e.g. ``"gemini"`` / ``"openai"`` / ``"anthropic"``.
      model: the model name as requested.
      n_messages: number of messages in the request.
      max_tokens: requested completion cap, if any.
      temperature: sampling temperature, if known (DEBUG only).
      seed: deterministic-replay seed, if any (DEBUG only).
      request_body: the actual payload sent to the provider (dict / str).
    """
    logger.info("model call: %s-%s (msgs=%d, max_tok=%s)", provider, model, n_messages, max_tokens)
    if request_body is not None and logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "request out (temperature=%s seed=%s): %s",
            temperature,
            seed,
            sanitize_for_log(request_body, max_len=MODEL_EXCHANGE_LOG_CAP),
        )


def log_model_response(
    logger: logging.Logger,
    *,
    response_text: str | None = None,
    usage: object | None = None,
    finish_reason: str | None = None,
    error: BaseException | str | None = None,
) -> None:
    """Log the result of one model call (the "response in" half), shared by all providers.

    Pairs with :func:`log_model_request` and deliberately does NOT repeat the
    provider/model name. On success at DEBUG it logs the full response text
    (capped at :data:`MODEL_EXCHANGE_LOG_CAP`, sanitized) plus token usage and
    finish_reason — the usage + finish ARE useful, the ``[:80]`` truncation was
    not.

    Pass ``error`` (an exception or a string cause) to surface a failed call at
    WARNING with the cause spelled out instead of swallowing it. A
    ``finish_reason`` of ``content_filter`` is treated as a refusal / safety
    block and logged at WARNING with the (capped) returned text.

    Args:
      logger: the provider's module logger.
      response_text: the actual full text the provider returned.
      usage: an object exposing ``prompt_tokens`` / ``completion_tokens`` /
        ``total_tokens`` (our :class:`LLMUsage`).
      finish_reason: normalised finish reason.
      error: exception or cause string when the call failed.
    """
    if error is not None:
        cause = error if isinstance(error, str) else f"{type(error).__name__}: {error}"
        logger.warning(
            "model call failed: %s", sanitize_for_log(cause, max_len=MODEL_EXCHANGE_LOG_CAP)
        )
        return
    if finish_reason == "content_filter":
        # Refusal / safety block — surface it loudly with the full (capped)
        # text rather than folding it into the generic response line.
        logger.warning(
            "model call blocked: finish=%s text=%s",
            finish_reason,
            sanitize_for_log(response_text or "", max_len=MODEL_EXCHANGE_LOG_CAP),
        )
        return
    if logger.isEnabledFor(logging.DEBUG):
        prompt_tokens = getattr(usage, "prompt_tokens", 0)
        completion_tokens = getattr(usage, "completion_tokens", 0)
        total_tokens = getattr(usage, "total_tokens", 0)
        logger.debug(
            "response in: tokens={i:%s o:%s t:%s} finish=%s text=%s",
            prompt_tokens,
            completion_tokens,
            total_tokens,
            finish_reason,
            sanitize_for_log(response_text or "", max_len=MODEL_EXCHANGE_LOG_CAP),
        )


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


def _should_use_rich_handler(stream: IO[str]) -> bool:
    """Decide whether to install :class:`RichHandler` over the plain handler.

    True when (a) the operator has not disabled colour via ``NO_COLOR``,
    (b) the chosen stream is a TTY, and (c) the stream is ``sys.stderr``
    (we don't risk rewriting an operator-supplied buffer with ANSI).
    Tests override the singleton :data:`_CONSOLE` directly to exercise
    the Rich path with a recording console.
    """
    if _color_disabled():
        return False
    if stream is not sys.stderr:
        return False
    return _stderr_is_tty()


def _install_rich_handler(level: int) -> None:
    """Install one :class:`RichHandler` on the root logger.

    Idempotent: removes any prior handler installed by this function
    first, then installs exactly one. Bound to :func:`get_console` so
    log lines and the Live region share the same Console — that's the
    whole point of QA-002's "single source of truth" lock.
    """
    root = logging.getLogger()
    # Remove every existing handler (basicConfig may have added a stream
    # handler on a prior call, or a previous RichHandler may already be
    # attached). The redacting filter is reinstalled below by
    # ``configure_logging`` so we don't lose secret scrubbing.
    for existing in list(root.handlers):
        root.removeHandler(existing)
    handler = RichHandler(
        console=get_console(),
        rich_tracebacks=True,
        show_path=False,
        show_time=True,
        markup=False,
        log_time_format=_DEFAULT_DATEFMT,
    )
    handler.setLevel(level)
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
    elif _should_use_rich_handler(effective_stream):
        # QA-002 — when stderr is a real TTY and the operator hasn't disabled
        # colour, route stdlib logging through Rich so log lines (1) render
        # with theme tokens, and (2) share the same Console as the scan's
        # Live region. Sharing the Console is what guarantees log lines
        # serialize ABOVE the Live frame as scrollback instead of tearing
        # the panel border (the bug captured in the QA-002 reproducer).
        _install_rich_handler(resolved)
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
    # QA-019 + QA-068: pin chatty HTTP deps to WARNING UNCONDITIONALLY so the
    # swarm-board signal isn't drowned by one ``INFO HTTP Request: ... 200 OK``
    # per probe — and so ``send_request_headers`` / ``receive_response_body``
    # wire events stay quiet even when the operator runs at
    # ``AGENT_GUARDIAN_LOG_LEVEL=DEBUG``. Operators who genuinely want the
    # network-level trace can still opt back in by calling
    # ``logging.getLogger("httpx").setLevel(logging.DEBUG)`` after
    # :func:`configure_logging` returns (see
    # ``test_operator_can_opt_back_in_to_httpx_info_after_configure``).
    # The pin floor is ``max(resolved, WARNING)`` so ``resolved=ERROR`` still
    # escalates correctly while ``resolved=INFO|DEBUG`` clamps to WARNING.
    # Explicit pins for ``httpcore.http11`` / ``httpcore.connection`` are
    # defensive — parent-pin should cascade, but stating them prevents a future
    # logger from leaking wire events past the parent.
    _NOISY_DEPS = (
        "httpx",
        "httpcore",
        "httpcore.http11",
        "httpcore.connection",
        "urllib3",
        "google_genai.models",
    )
    for noisy in _NOISY_DEPS:
        logging.getLogger(noisy).setLevel(max(resolved, logging.WARNING))
    _CONFIGURED = True


def is_configured() -> bool:
    """Return True if :func:`configure_logging` has run in this process."""
    return _CONFIGURED


def _reset_for_tests() -> None:
    """Drop the configured flag so the next call reconfigures. Test-only.

    Also drops the cached Console so each test starts with a fresh
    Rich rendering pipeline (record buffers don't leak between tests).
    """
    global _CONFIGURED
    _CONFIGURED = False
    _reset_console_for_tests()
