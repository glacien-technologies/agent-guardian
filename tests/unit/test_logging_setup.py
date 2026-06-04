"""Tests for the centralized logging setup (PRD §8.3)."""

from __future__ import annotations

import io
import logging

import pytest

from agent_guardian import logging_setup


@pytest.fixture(autouse=True)
def _reset_logging() -> None:
    """Ensure each test starts from a clean module-level state.

    ``configure_logging`` short-circuits on the second call without
    ``force=True``; tests assert behaviour by configuring fresh each time.

    Also resets structlog's default configuration when available — the JSON
    renderer caches its first logger binding (``cache_logger_on_first_use``),
    so without this reset a test that writes to a torn-down StringIO ends up
    writing into a stale buffer the next test never sees.
    """
    logging_setup._reset_for_tests()
    # Reset the noisy-dep loggers — configure_logging pins them on every
    # run (QA-068) which would otherwise leak across tests in this file.
    for noisy in (
        "httpx",
        "httpcore",
        "httpcore.http11",
        "httpcore.connection",
        "urllib3",
        "google_genai.models",
    ):
        logging.getLogger(noisy).setLevel(logging.NOTSET)
    # Also drop any handlers that a prior test installed so we don't double-print.
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    try:
        import structlog as _structlog

        _structlog.reset_defaults()
    except ImportError:  # pragma: no cover - structlog is a hard dep but stay resilient
        pass
    yield
    logging_setup._reset_for_tests()
    for noisy in (
        "httpx",
        "httpcore",
        "httpcore.http11",
        "httpcore.connection",
        "urllib3",
        "google_genai.models",
    ):
        logging.getLogger(noisy).setLevel(logging.NOTSET)
    try:
        import structlog as _structlog

        _structlog.reset_defaults()
    except ImportError:  # pragma: no cover
        pass


def test_default_level_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(logging_setup.ENV_VAR, raising=False)
    logging_setup.configure_logging(force=True)
    assert logging.getLogger().getEffectiveLevel() == logging.INFO
    assert logging_setup.is_configured() is True


def test_env_override_debug(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(logging_setup.ENV_VAR, "DEBUG")
    logging_setup.configure_logging(force=True)
    assert logging.getLogger().getEffectiveLevel() == logging.DEBUG


def test_env_override_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(logging_setup.ENV_VAR, "warning")  # lower-case OK
    logging_setup.configure_logging(force=True)
    assert logging.getLogger().getEffectiveLevel() == logging.WARNING


def test_explicit_level_str_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(logging_setup.ENV_VAR, "ERROR")
    logging_setup.configure_logging(level="DEBUG", force=True)
    assert logging.getLogger().getEffectiveLevel() == logging.DEBUG


def test_explicit_level_int_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(logging_setup.ENV_VAR, "ERROR")
    logging_setup.configure_logging(level=logging.DEBUG, force=True)
    assert logging.getLogger().getEffectiveLevel() == logging.DEBUG


def test_force_reconfigures(monkeypatch: pytest.MonkeyPatch) -> None:
    logging_setup.configure_logging(level="INFO", force=True)
    assert logging.getLogger().getEffectiveLevel() == logging.INFO
    logging_setup.configure_logging(level="DEBUG", force=True)
    assert logging.getLogger().getEffectiveLevel() == logging.DEBUG


def test_no_double_configuration_without_force(monkeypatch: pytest.MonkeyPatch) -> None:
    logging_setup.configure_logging(level="INFO", force=True)
    initial_level = logging.getLogger().getEffectiveLevel()
    # Second call without force MUST be a no-op even if level differs.
    logging_setup.configure_logging(level="ERROR")
    assert logging.getLogger().getEffectiveLevel() == initial_level


def test_unknown_level_string_falls_back_to_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(logging_setup.ENV_VAR, raising=False)
    logging_setup.configure_logging(level="NOT_A_LEVEL", force=True)
    assert logging.getLogger().getEffectiveLevel() == logging.INFO


def test_noisy_dependencies_pinned_at_warning_when_caller_runs_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # QA-019: at the default INFO level, httpx/httpcore/urllib3 must be
    # pinned to WARNING so the operator does NOT see one
    # ``INFO HTTP Request: METHOD url "HTTP/1.1 200 OK"`` per probe drown
    # the swarm board. WARNING (and above) is the contract — exactly
    # WARNING is the expected pin.
    logging_setup.configure_logging(level="INFO", force=True)
    assert logging.getLogger("httpx").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() == logging.WARNING
    # QA-068 — defensive child pins (parent already cascades, but state
    # the http11 + connection loggers explicitly so a future grandchild
    # cannot inherit DEBUG from root through a renamed parent).
    assert logging.getLogger("httpcore.http11").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("httpcore.connection").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("urllib3").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("google_genai.models").getEffectiveLevel() == logging.WARNING


def test_noisy_dependencies_pinned_at_warning_even_at_debug_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # QA-068: even at root=DEBUG the noisy deps must stay at WARNING so
    # ``send_request_headers`` / ``receive_response_body`` wire events from
    # httpcore.http11 don't drown the operator's swarm-board narration. The
    # only way back in is the explicit per-logger override documented in
    # ``test_operator_can_opt_back_in_to_httpx_info_after_configure`` —
    # which uses ``setLevel`` AFTER configure_logging returns.
    logging_setup.configure_logging(level="DEBUG", force=True)
    assert logging.getLogger("httpx").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("httpcore.http11").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("httpcore.connection").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("urllib3").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("google_genai.models").getEffectiveLevel() == logging.WARNING


def test_noisy_dependencies_escalate_above_warning_when_caller_runs_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # QA-019: the WARNING pin is a *floor*, not a ceiling. An operator
    # running at ERROR (e.g. a quiet CI job that only wants alerts) must
    # see the noisy deps clamped to ERROR, not relaxed back down to
    # WARNING. Locks the ``max(resolved, WARNING)`` direction.
    logging_setup.configure_logging(level="ERROR", force=True)
    assert logging.getLogger("httpx").getEffectiveLevel() == logging.ERROR
    assert logging.getLogger("httpcore").getEffectiveLevel() == logging.ERROR


def test_operator_can_opt_back_in_to_httpx_info_after_configure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # QA-019 acceptance: operators who want the network-level info can
    # opt in via ``logging.getLogger("httpx").setLevel(logging.INFO)``
    # AFTER configure_logging returns. The pin must not be reapplied on
    # subsequent calls without ``force=True``.
    logging_setup.configure_logging(level="INFO", force=True)
    logging.getLogger("httpx").setLevel(logging.INFO)
    # Second call without force is a no-op — must NOT re-pin to WARNING.
    logging_setup.configure_logging(level="INFO")
    assert logging.getLogger("httpx").getEffectiveLevel() == logging.INFO


def test_custom_stream_is_used() -> None:
    buf = io.StringIO()
    logging_setup.configure_logging(level="DEBUG", stream=buf, force=True)
    logging.getLogger(__name__).info("hello %s", "world")
    contents = buf.getvalue()
    assert "hello world" in contents


# ---------------------------------------------------------------------------
# Trace correlation (item: install LogRecordFactory for trace_id/span_id)
# ---------------------------------------------------------------------------
def test_log_record_has_trace_fields_when_no_span_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Default formatter now renders ``[trace=%(trace_id)s]``; ensure the field
    # is always set (empty string when no span is active) so the formatter
    # never KeyErrors. Use a fresh empty OTel context so any pollution from
    # earlier-in-suite tests (which may have left an observer span attached)
    # can't make this assertion flap.
    monkeypatch.delenv(logging_setup.JSON_ENV_VAR, raising=False)
    buf = io.StringIO()
    logging_setup.configure_logging(level="INFO", stream=buf, force=True)
    try:
        from opentelemetry import context as otel_context

        token = otel_context.attach(otel_context.Context())
    except ImportError:
        token = None
    try:
        logging.getLogger(__name__).info("no-span-line")
    finally:
        if token is not None:
            from opentelemetry import context as otel_context

            otel_context.detach(token)
    out = buf.getvalue()
    assert "no-span-line" in out
    assert "[trace=]" in out


def test_log_record_carries_active_trace_id(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("opentelemetry")
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", provider, raising=False)

    class _AlreadyDone:
        def do_once(self, func: object) -> bool:
            return False

    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", _AlreadyDone(), raising=False)

    monkeypatch.delenv(logging_setup.JSON_ENV_VAR, raising=False)
    buf = io.StringIO()
    logging_setup.configure_logging(level="INFO", stream=buf, force=True)

    tracer = trace.get_tracer("test")
    with tracer.start_as_current_span("scan") as span:
        ctx = span.get_span_context()
        expected_trace = format(ctx.trace_id, "032x")
        logging.getLogger(__name__).info("inside-span-line")

    out = buf.getvalue()
    assert "inside-span-line" in out
    # The 32-hex trace id must appear in the formatted output — that's the
    # whole point of the LogRecordFactory.
    assert expected_trace in out
    assert "[trace=]" not in out.split("inside-span-line")[0].splitlines()[-1]


def test_trace_correlation_factory_is_idempotent() -> None:
    # Repeat configure_logging (force=True) must NOT stack a new wrapper on
    # each call — otherwise every reconfiguration leaks a wrapper frame.
    logging_setup.configure_logging(force=True)
    factory1 = logging.getLogRecordFactory()
    logging_setup.configure_logging(force=True)
    factory2 = logging.getLogRecordFactory()
    assert factory1 is factory2


# ---------------------------------------------------------------------------
# structlog JSON renderer (item: AGENT_GUARDIAN_LOG_JSON=1)
# ---------------------------------------------------------------------------
def test_json_logging_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(logging_setup.JSON_ENV_VAR, raising=False)
    assert logging_setup._json_logging_enabled() is False


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on"])
def test_json_logging_enabled_by_truthy_token(monkeypatch: pytest.MonkeyPatch, truthy: str) -> None:
    monkeypatch.setenv(logging_setup.JSON_ENV_VAR, truthy)
    assert logging_setup._json_logging_enabled() is True


@pytest.mark.parametrize("falsy", ["0", "false", "no", "off", ""])
def test_json_logging_disabled_by_falsy_token(monkeypatch: pytest.MonkeyPatch, falsy: str) -> None:
    monkeypatch.setenv(logging_setup.JSON_ENV_VAR, falsy)
    assert logging_setup._json_logging_enabled() is False


def test_json_renderer_emits_json_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    # When AGENT_GUARDIAN_LOG_JSON=1 stdlib records flow through structlog's
    # ProcessorFormatter and end up as one JSON object per line — exactly what
    # a container log shipper expects.
    pytest.importorskip("structlog")
    import json

    monkeypatch.setenv(logging_setup.JSON_ENV_VAR, "1")
    buf = io.StringIO()
    logging_setup.configure_logging(level="INFO", stream=buf, force=True)
    logging.getLogger("test.json").info("structured-line")
    raw = buf.getvalue().strip()
    assert raw, "expected at least one log line"
    # Each line must parse as JSON.
    for line in raw.splitlines():
        parsed = json.loads(line)
        assert isinstance(parsed, dict)
    # The most recent line must carry the event message + a level field — the
    # canonical structlog contract.
    last = json.loads(raw.splitlines()[-1])
    assert last.get("event") == "structured-line"
    assert last.get("level", "").lower() == "info"


def test_json_renderer_redacts_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    # Defence-in-depth: the JSON path must apply the same secret-scrubbing as
    # the stdlib path. A Google API key in a log arg must never reach the
    # rendered output.
    pytest.importorskip("structlog")
    import json

    monkeypatch.setenv(logging_setup.JSON_ENV_VAR, "1")
    buf = io.StringIO()
    logging_setup.configure_logging(level="INFO", stream=buf, force=True)
    logging.getLogger("test.json").info("calling https://x?key=AIzaSyA1234567890ABCDEF")
    raw = buf.getvalue().strip().splitlines()[-1]
    parsed = json.loads(raw)
    assert "AIzaSyA1234567890ABCDEF" not in parsed["event"]
    assert "***REDACTED***" in parsed["event"]


def test_structured_logging_enabled_tracks_json_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # QA-068 — ``structured_logging_enabled()`` is the call-site gate the
    # agent loop uses to decide whether to emit full per-turn bodies. It is a
    # thin alias over the JSON/structured log path (``AGENT_GUARDIAN_LOG_JSON``,
    # which the CLI maps from ``--debug-format json``).
    monkeypatch.delenv(logging_setup.JSON_ENV_VAR, raising=False)
    assert logging_setup.structured_logging_enabled() is False
    monkeypatch.setenv(logging_setup.JSON_ENV_VAR, "1")
    assert logging_setup.structured_logging_enabled() is True
    monkeypatch.setenv(logging_setup.JSON_ENV_VAR, "false")
    assert logging_setup.structured_logging_enabled() is False


# ---------------------------------------------------------------------------
# QA-072 — run.log file sink + terminal-level decoupling
# ---------------------------------------------------------------------------


def test_attach_run_log_file_captures_debug_while_terminal_quiet(tmp_path) -> None:
    """The run.log file captures DEBUG even when the terminal handler is at
    WARNING — the whole point of the decoupling."""
    import io as _io

    stream = _io.StringIO()
    # Terminal handler starts at WARNING (the scan default).
    logging_setup.configure_logging(level="WARNING", stream=stream, force=True)
    run_log = tmp_path / "run.log"
    handler = logging_setup.attach_run_log_file(run_log, level="DEBUG")
    try:
        log = logging.getLogger("agent_guardian.test.qa072")
        log.debug("debug-only-line")
        log.warning("warning-line")
        for h in logging.getLogger().handlers:
            h.flush()
        file_text = run_log.read_text(encoding="utf-8")
        # File got BOTH the debug and the warning.
        assert "debug-only-line" in file_text
        assert "warning-line" in file_text
        # Terminal (WARNING) got the warning but NOT the debug line.
        term = stream.getvalue()
        assert "warning-line" in term
        assert "debug-only-line" not in term
    finally:
        logging.getLogger().removeHandler(handler)


def test_set_terminal_log_level_skips_file_and_jsonl_handlers(tmp_path) -> None:
    """``set_terminal_log_level`` raises the console handler only — never the
    run.log FileHandler nor a non-stream events bridge handler."""
    import io as _io

    stream = _io.StringIO()
    logging_setup.configure_logging(level="DEBUG", stream=stream, force=True)
    file_handler = logging_setup.attach_run_log_file(tmp_path / "run.log", level="DEBUG")
    # A bare logging.Handler stands in for the JsonlLogHandler events bridge.
    bridge = logging.Handler()
    bridge.setLevel(logging.NOTSET)
    logging.getLogger().addHandler(bridge)
    try:
        logging_setup.set_terminal_log_level("WARNING")
        # The file handler keeps DEBUG (full trace).
        assert file_handler.level == logging.DEBUG
        # The bare bridge handler is untouched (still NOTSET=0).
        assert bridge.level == logging.NOTSET
    finally:
        root = logging.getLogger()
        root.removeHandler(file_handler)
        root.removeHandler(bridge)


def test_resolve_level_public_wrapper() -> None:
    assert logging_setup.resolve_level("DEBUG") == logging.DEBUG
    assert logging_setup.resolve_level("warning") == logging.WARNING
    assert logging_setup.resolve_level(20) == logging.INFO
