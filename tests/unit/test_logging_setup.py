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
    """
    logging_setup._reset_for_tests()
    # Reset the noisy-dep loggers — configure_logging pins them on INFO+
    # runs which would otherwise leak across tests in this file.
    for noisy in ("httpx", "httpcore", "urllib3", "google_genai.models"):
        logging.getLogger(noisy).setLevel(logging.NOTSET)
    # Also drop any handlers that a prior test installed so we don't double-print.
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    yield
    logging_setup._reset_for_tests()
    for noisy in ("httpx", "httpcore", "urllib3", "google_genai.models"):
        logging.getLogger(noisy).setLevel(logging.NOTSET)


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


def test_noisy_dependencies_pinned_at_info_when_caller_runs_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logging_setup.configure_logging(level="INFO", force=True)
    # httpx, httpcore et al. must not fall below INFO when the operator
    # runs at INFO — otherwise a single HTTP call balloons the log.
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.INFO
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.INFO


def test_noisy_dependencies_not_pinned_when_caller_runs_debug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logging_setup.configure_logging(level="DEBUG", force=True)
    # At DEBUG the operator opted in to the noise — leave the chatty deps alone.
    # We assert they are NOT explicitly pinned to INFO+.
    httpx_logger = logging.getLogger("httpx")
    # Effective level inherits from root (DEBUG) when no explicit level is set.
    # If we pinned them, this assertion would fail.
    assert httpx_logger.getEffectiveLevel() == logging.DEBUG


def test_custom_stream_is_used() -> None:
    buf = io.StringIO()
    logging_setup.configure_logging(level="DEBUG", stream=buf, force=True)
    logging.getLogger(__name__).info("hello %s", "world")
    contents = buf.getvalue()
    assert "hello world" in contents
