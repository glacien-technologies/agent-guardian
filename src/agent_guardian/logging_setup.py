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

import contextlib
import hashlib
import logging
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path
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
# without this every scan wrote the user's key to stderr. Covered shapes include:
#   1. sensitive query params (key/api_key/access_token/token/sig/signature)
#   2. ``Authorization: Bearer <token>`` headers
#   3. AWS credential fields used by AgentGuardian, botocore, and SSO responses
#   4. AWS SigV4 authorization/security-token headers, including mapping reprs
#   5. bare AWS access-key IDs and provider key shapes (Google AIza..., OpenAI/
#      Anthropic sk-...), as defence-in-depth for any path we didn't anticipate.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)([?&](?:key|api[_-]?key|access_token|token|sig|signature)=)[^&\s\"']+"),
        r"\1" + _REDACTED,
    ),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)\S+"), r"\1" + _REDACTED),
    (
        re.compile(
            r"(?i)([\"']?(?:accessKeyId|secretAccessKey|sessionToken|"
            r"aws_access_key_id|aws_secret_access_key|aws_session_token|"
            r"access_key_id|secret_access_key|session_token|"
            r"access_key|secret_key|token)[\"']?"
            r"\s*[:=]\s*[\"']?)[^\"'\s,}]+"
        ),
        r"\1" + _REDACTED,
    ),
    (
        re.compile(r"(?i)(x-amz-security-token:\s*)\S+"),
        r"\1" + _REDACTED,
    ),
    (
        re.compile(
            r"(?i)([\"']?authorization[\"']?\s*:\s*[\"']?AWS4-HMAC-SHA256\s+)"
            r"[^\"'\r\n}]+"
        ),
        r"\1" + _REDACTED,
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), _REDACTED),
    (re.compile(r"AIza[0-9A-Za-z_\-]{10,}"), _REDACTED),
    (re.compile(r"sk-(?:ant-)?[A-Za-z0-9_\-]{12,}"), _REDACTED),
)


def redact_secrets(text: str) -> str:
    """Mask API keys, bearer tokens, AWS credentials, and SigV4 headers.

    Surrounding syntax is preserved (for example, ``?key=AIza...`` becomes
    ``?key=***REDACTED***``).
    """
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

# Per-call preview cap for the conversation half of "request out". Smaller than
# MODEL_EXCHANGE_LOG_CAP on purpose: stateless strategies (e.g. recon) resend the
# entire growing transcript every turn, so dumping the whole thing each call just
# repeats near-identical text. We show the TAIL — where the freshly-appended turn
# and the actual instruction live — instead.
MODEL_REQUEST_PREVIEW_CAP = 800

# System prompts are static but resent on every call. Track which ones we've
# already logged in full so they're shown once instead of dumped per call.
# Bounded so a long-lived `serve` process can't grow it without limit.
_LOGGED_SYSTEM_PROMPTS: set[str] = set()
_LOGGED_SYSTEM_PROMPTS_CAP = 512


def _model_log_full_prompts() -> bool:
    """Whether to dump the entire request payload per call (deep-debug opt-in).

    Off by default — the per-call view shows the system prompt once plus the
    newest conversation tail. Set ``AGENT_GUARDIAN_LOG_FULL_PROMPTS=1`` to get
    the full raw payload on every call instead.
    """
    return os.getenv("AGENT_GUARDIAN_LOG_FULL_PROMPTS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def full_agent_io_enabled() -> bool:
    """Whether to log full per-agent I/O to the run log for troubleshooting.

    Covers the attacker meta-prompt + the generated attack, and the judge's
    prompt + raw output + reasoning — the gaps the bounded per-turn preview and
    the provider request/response logs leave. Same opt-in as the full-prompt
    model dumps: ``AGENT_GUARDIAN_LOG_FULL_PROMPTS=1`` or the CLI
    ``--log-agent-io`` flag (which sets that env var).
    """
    return _model_log_full_prompts()


# Cap for the full agent-I/O troubleshooting lines: large enough to read a real
# attacker meta-prompt or judge prompt + reasoning, but bounded so a runaway
# response can't write megabytes per turn into the log.
AGENT_IO_LOG_CAP = 16000


# Issue #222 — summary-mode cap. When --log-agent-io-summary (or
# AGENT_GUARDIAN_LOG_AGENT_IO_SUMMARY=1) is set, the agent-io block is
# truncated to this many chars per side (input + output each) with a
# trailing "(+N chars)" marker. Empirically 200 is enough to read the
# shape of the call without burning a 10x run.log on a full-mode scan.
AGENT_IO_SUMMARY_CAP: int = 200


def _agent_io_summary_enabled() -> bool:
    """``True`` when the operator opted into --log-agent-io-summary."""
    return os.getenv("AGENT_GUARDIAN_LOG_AGENT_IO_SUMMARY", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _maybe_summarize(text: str) -> str:
    """Truncate ``text`` to :data:`AGENT_IO_SUMMARY_CAP` chars per side
    when summary mode is on; otherwise return unchanged."""
    if not _agent_io_summary_enabled():
        return text
    if len(text) <= AGENT_IO_SUMMARY_CAP:
        return text
    return f"{text[:AGENT_IO_SUMMARY_CAP]}…[+{len(text) - AGENT_IO_SUMMARY_CAP} chars]"


def log_agent_io(
    logger: logging.Logger,
    role: str,
    *,
    model: str | None = None,
    input_text: object = "",
    output_text: object = "",
    **fields: object,
) -> None:
    """Emit a role-tagged DEBUG line with one agent's full input + output.

    No-op unless :func:`full_agent_io_enabled`. The attacker path and the judge
    call this so an operator can grep ``agent-io [attacker]`` / ``agent-io
    [judge]`` in ``run.log`` and read the exact prompt, the generated attack /
    raw verdict, and the reasoning. Text is secret-redacted + control-stripped
    via :func:`sanitize_for_log` and capped at :data:`AGENT_IO_LOG_CAP`.

    Issue #222 — when ``--log-agent-io-summary`` is also set (env var
    ``AGENT_GUARDIAN_LOG_AGENT_IO_SUMMARY=1``), each of the input + output
    sides is further capped at :data:`AGENT_IO_SUMMARY_CAP` (200 chars)
    with a trailing ``…[+N chars]`` marker so the audit trail keeps the
    shape of the call without burning a 10x run.log on full-mode scans.
    """
    if not full_agent_io_enabled():
        return
    extra = " ".join(f"{k}={v}" for k, v in fields.items() if v is not None)
    sanitised_in = sanitize_for_log(input_text, max_len=AGENT_IO_LOG_CAP)
    sanitised_out = sanitize_for_log(output_text, max_len=AGENT_IO_LOG_CAP)
    logger.debug(
        "agent-io [%s]%s%s\n  --- input ---\n%s\n  --- output ---\n%s",
        role,
        f" model={model}" if model else "",
        f" {extra}" if extra else "",
        _maybe_summarize(sanitised_in),
        _maybe_summarize(sanitised_out),
    )


def _tail_preview(text: str, cap: int) -> str:
    """Return the last *cap* chars of *text* (where appended turns accrue).

    Prefixes an ``…[+N chars earlier]…`` marker when content was dropped so the
    reader knows the head was elided rather than the message being short.
    """
    if len(text) <= cap:
        return text
    return f"…[+{len(text) - cap} chars earlier]… {text[-cap:]}"


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
    messages: Sequence[Any] | None = None,
) -> None:
    """Log the start of one model call (the "request out" half), shared by all providers.

    Emits the single INFO narration line that feeds the operator's swarm-board
    — the ONLY place the provider + model name is stamped, so the paired
    :func:`log_model_response` line does not repeat it.

    At DEBUG it then shows the request *readably* rather than dumping the whole
    payload every call: the (static) system prompt is logged once by hash, and
    the conversation is shown as its newest tail (capped at
    :data:`MODEL_REQUEST_PREVIEW_CAP`). Stateless strategies resend the entire
    growing transcript each turn, so the full dump was near-identical noise on
    every call. Set ``AGENT_GUARDIAN_LOG_FULL_PROMPTS=1`` to restore the full
    per-call payload dump for deep debugging. Everything is run through
    :func:`sanitize_for_log` so API keys / control chars stay safe.

    Args:
      logger: the provider's module logger.
      provider: e.g. ``"gemini"`` / ``"openai"`` / ``"anthropic"``.
      model: the model name as requested.
      n_messages: number of messages in the request.
      max_tokens: requested completion cap, if any.
      temperature: sampling temperature, if known (DEBUG only).
      seed: deterministic-replay seed, if any (DEBUG only).
      request_body: the raw payload sent to the provider (dict / str); only
        dumped when ``AGENT_GUARDIAN_LOG_FULL_PROMPTS`` is set, or as a fallback
        when ``messages`` is not supplied.
      messages: the canonical request messages (each with ``role`` / ``content``)
        used to render the readable per-call preview.
    """
    logger.info("model call: %s-%s (msgs=%d, max_tok=%s)", provider, model, n_messages, max_tokens)
    if not logger.isEnabledFor(logging.DEBUG):
        return

    # Deep-debug escape hatch: dump the entire raw payload exactly as sent.
    if _model_log_full_prompts() and request_body is not None:
        logger.debug(
            "request out (full) (temperature=%s seed=%s): %s",
            temperature,
            seed,
            sanitize_for_log(request_body, max_len=MODEL_EXCHANGE_LOG_CAP),
        )
        return

    if messages:
        # Log each distinct system prompt once (it is static but resent every
        # call); show the conversation as its newest tail.
        system_text = "\n".join(
            m.content for m in messages if getattr(m, "role", "") == "system" and m.content
        )
        if system_text:
            digest = hashlib.sha256(system_text.encode("utf-8", "replace")).hexdigest()[:8]
            if digest not in _LOGGED_SYSTEM_PROMPTS:
                if len(_LOGGED_SYSTEM_PROMPTS) >= _LOGGED_SYSTEM_PROMPTS_CAP:
                    _LOGGED_SYSTEM_PROMPTS.clear()
                _LOGGED_SYSTEM_PROMPTS.add(digest)
                logger.debug(
                    "system prompt (sha=%s, %d chars): %s",
                    digest,
                    len(system_text),
                    sanitize_for_log(system_text, max_len=MODEL_EXCHANGE_LOG_CAP),
                )
        convo = [m for m in messages if getattr(m, "role", "") != "system"]
        if convo:
            newest = convo[-1].content or ""
            earlier = len(convo) - 1
            prefix = f"(+{earlier} earlier msg{'s' if earlier != 1 else ''}) " if earlier else ""
            logger.debug(
                "request out (temperature=%s seed=%s, %d chars): %s%s",
                temperature,
                seed,
                len(newest),
                prefix,
                sanitize_for_log(
                    _tail_preview(newest, MODEL_REQUEST_PREVIEW_CAP),
                    max_len=MODEL_EXCHANGE_LOG_CAP,
                ),
            )
        return

    # Fallback when no structured messages are supplied: a bounded preview of
    # the raw payload (still smaller than the old full dump).
    if request_body is not None:
        logger.debug(
            "request out (temperature=%s seed=%s): %s",
            temperature,
            seed,
            sanitize_for_log(request_body, max_len=MODEL_REQUEST_PREVIEW_CAP),
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
        logger.debug(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure — operator-requested DEBUG echo of the real model response; text passes through sanitize_for_log() (redact_secrets() masks API keys + control-char strip + length cap) and is scrubbed again by _RedactingFilter before emit
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


def structured_logging_enabled() -> bool:
    """True iff the structured/JSON log path is active (``--debug-format json``).

    QA-068 — call-site gate for the verbose, full-body DEBUG lines that are
    only useful to a machine consumer (the per-turn raw prompt + raw target
    response). Under the default human-readable DEBUG-text path those bodies
    drown the consolidated per-turn INFO narration, so the agent loop emits
    only the truncated previews there and reserves the full bodies for the
    structured path. The CLI maps ``--debug-format json`` onto
    ``AGENT_GUARDIAN_LOG_JSON``; setting that env var directly opts in too.
    """
    return _json_logging_enabled()


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
        "botocore",
        "botocore.parsers",
        "botocore.credentials",
    )
    for noisy in _NOISY_DEPS:
        logging.getLogger(noisy).setLevel(max(resolved, logging.WARNING))
    _CONFIGURED = True


def resolve_level(level: str | int | None) -> int:
    """Public wrapper over :func:`_resolve_level` for callers (the CLI) that
    need to turn a level spec (``"DEBUG"`` / ``"info"`` / ``20`` / ``None``)
    into a :mod:`logging` int without reaching into a private helper."""
    return _resolve_level(level)


def attach_run_log_file(
    path: str | os.PathLike[str],
    *,
    level: str | int | None = "DEBUG",
) -> logging.Handler:
    """Attach a :class:`logging.FileHandler` that captures the FULL log trace.

    QA-072 (2026-06-04) — the scan command routes the raw stdlib stream to a
    per-scan ``run.log`` so the terminal can stay quiet (board + compact attack
    feed) while every line is still recoverable on disk. The file always
    captures at ``level`` (default ``DEBUG``) regardless of how high the
    terminal handler filters — so we also lower the ROOT level to ``level`` when
    needed, otherwise the root would gate ``DEBUG`` records before any handler
    sees them.

    The handler carries the same plain formatter as the non-TTY console path
    (timestamp + level + logger + trace id) and the same secret-redacting
    filter, so API keys never land in the file. Returns the exact handler so
    the caller can retain it through final summaries, then detach it during
    the joint run/event forensic seal before hashing.
    """
    resolved = _resolve_level(level)
    root = logging.getLogger()
    # Root level gates BEFORE per-handler levels: if the root sits at WARNING, a
    # DEBUG record never reaches this file handler. We drop the root floor below
    # so the full trace flows — but any EXISTING handler that was relying on the
    # root level (``level == NOTSET``) would then silently start passing DEBUG
    # too (the console would un-quiet, the events bridge would balloon). Pin
    # those to the prior effective root level FIRST so lowering the root only
    # affects the new file sink; callers raise the console separately via
    # :func:`set_terminal_log_level`.
    prior_root_level = root.level if root.level != logging.NOTSET else logging.WARNING
    for existing in root.handlers:
        if existing.level == logging.NOTSET:
            existing.setLevel(prior_root_level)

    fpath = Path(path)
    fpath.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(fpath, mode="a", encoding="utf-8")
    handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT, datefmt=_DEFAULT_DATEFMT))
    handler.setLevel(resolved)
    handler.addFilter(_RedactingFilter())
    root.addHandler(handler)
    if root.level == logging.NOTSET or root.level > resolved:
        root.setLevel(resolved)
    return handler


def detach_run_log_file(handler: logging.Handler) -> None:
    """Flush, detach, and close one run-log handler without touching other sinks.

    The operation is idempotent so callers can safely seal the same handler
    during best-effort finalization more than once.
    """
    root = logging.getLogger()
    with contextlib.suppress(Exception):
        handler.flush()
    if handler in root.handlers:
        root.removeHandler(handler)
    with contextlib.suppress(Exception):
        handler.close()


def set_terminal_log_level(level: str | int) -> None:
    """Set the level on the TERMINAL handler(s) only — never the run.log file
    handler or the events.jsonl bridge.

    QA-072 — decouples what the operator sees on screen from what is captured.
    Targets the Rich/stream console handler (``RichHandler`` on a TTY, or the
    plain ``StreamHandler`` basicConfig installs) and explicitly skips
    :class:`logging.FileHandler` (the run.log) and any non-stream handler such
    as the ``JsonlLogHandler`` events bridge (a bare ``logging.Handler``).
    """
    resolved = _resolve_level(level)
    for handler in logging.getLogger().handlers:
        # FileHandler is a StreamHandler subclass — skip it FIRST so run.log
        # keeps its own (lower) level.
        if isinstance(handler, logging.FileHandler):
            continue
        if isinstance(handler, (RichHandler, logging.StreamHandler)):
            handler.setLevel(resolved)


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
