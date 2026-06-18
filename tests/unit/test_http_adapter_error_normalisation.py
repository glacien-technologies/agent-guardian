"""HttpAdapter normalises ``adapter_error:`` substrings before they reach
recon / the judge LLM context (rc38 P0-#4, sibling to PR #248).

The transport layer is the right altitude to strip provider-internal error
prose out of the assistant text — recon and the judge then see a stable
``[TARGET_UNAVAILABLE: <code>]`` sentinel instead of attacker-shaped JSON.
"""

from __future__ import annotations

from agent_guardian.adapters.http import _normalize_adapter_error_text


def test_normalize_leaves_benign_text_unchanged() -> None:
    """A normal assistant reply must pass through untouched."""
    text = "I can look up your balance and transfer money."
    assert _normalize_adapter_error_text(text) == text


def test_normalize_replaces_adapter_error_sentinel() -> None:
    """``[adapter_error: ...]`` substrings collapse to the public sentinel."""
    text = "[adapter_error: 429 RESOURCE_EXHAUSTED quota_metric=...]"
    out = _normalize_adapter_error_text(text)
    assert "adapter_error" not in out
    assert "[TARGET_UNAVAILABLE:" in out
    assert "429" in out  # the status code is preserved for diagnostics


def test_normalize_handles_embedded_adapter_error_inside_prose() -> None:
    """The sentinel can be embedded inside a longer string; the whole
    ``[adapter_error: ...]`` span must be replaced."""
    text = "model said: [adapter_error: 503 transient backend failure] -- retry later"
    out = _normalize_adapter_error_text(text)
    assert "adapter_error" not in out
    assert "[TARGET_UNAVAILABLE:" in out
    assert "503" in out


def test_normalize_empty_and_none_safe() -> None:
    """Edge cases: empty string and None pass through without error."""
    assert _normalize_adapter_error_text("") == ""
    assert _normalize_adapter_error_text(None) is None
