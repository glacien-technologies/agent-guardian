"""Secrets must never reach the logs.

Regression guard for the Gemini ``?key=`` leak: httpx logs request URLs at
INFO, and Gemini passes the API key in the query string, so without redaction
every scan wrote the user's key to stderr.
"""

from __future__ import annotations

import io
import logging

from agent_guardian.logging_setup import (
    _RedactingFilter,
    _reset_for_tests,
    configure_logging,
    redact_secrets,
)


def test_redact_masks_google_key_query_param() -> None:
    url = (
        "HTTP Request: POST https://generativelanguage.googleapis.com/v1beta/"
        'models/gemini-2.5-flash:generateContent?key=AIzaSyD_TOPSECRET_123 "HTTP/1.1 200 OK"'
    )
    out = redact_secrets(url)
    assert "AIzaSyD_TOPSECRET_123" not in out
    assert "key=" in out  # the param name is kept; only the value is masked


def test_redact_masks_bearer_token() -> None:
    out = redact_secrets("Authorization: Bearer sk-abcdef1234567890ABCDEF")
    assert "sk-abcdef1234567890ABCDEF" not in out


def test_redact_masks_bare_provider_key_shapes() -> None:
    out = redact_secrets("key leaked: AIzaSyD_TOPSECRET_1234567 and sk-ant-aaaaaaaaaaaaaaaaaaaa")
    assert "AIzaSyD_TOPSECRET_1234567" not in out
    assert "sk-ant-aaaaaaaaaaaaaaaaaaaa" not in out


def test_redact_is_noop_on_clean_text() -> None:
    clean = "phase parallel: done (11 agents, duration=0.1s)"
    assert redact_secrets(clean) == clean


def test_filter_redacts_message_built_from_args() -> None:
    # httpx logs the URL as a %s arg, not in the format string.
    rec = logging.LogRecord(
        name="httpx",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="HTTP Request: %s",
        args=("https://x/v1?key=AIzaSyD_TOPSECRET_123",),
        exc_info=None,
    )
    assert _RedactingFilter().filter(rec) is True
    assert "AIzaSyD_TOPSECRET_123" not in rec.getMessage()


def test_configure_logging_redacts_emitted_output() -> None:
    buf = io.StringIO()
    _reset_for_tests()
    try:
        configure_logging(level="INFO", stream=buf, force=True)
        logging.getLogger("httpx").info(
            "HTTP Request: %s", "https://x/v1?key=AIzaSyD_TOPSECRET_123"
        )
        assert "AIzaSyD_TOPSECRET_123" not in buf.getvalue()
        assert "key=" in buf.getvalue()
    finally:
        _reset_for_tests()
