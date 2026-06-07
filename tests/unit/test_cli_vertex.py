"""CLI tests for the Vertex provider (M9 complete).

Vertex AI is now a fully-functional provider (OAuth2 ADC auth via the ``[gcp]``
extra). The CLI no longer refuses ``vertex:<model>`` with an M9-pending error.
What it DOES still do is fail fast with a clear ``BadParameter`` when no GCP
project can be resolved (neither ``+project=`` qualifier nor
``GOOGLE_CLOUD_PROJECT``), so an operator gets an actionable message before any
tokens are spent.
"""

from __future__ import annotations

import pytest
import typer

from agent_guardian.cli import build_llm


def _expect_bad_parameter(spec: str, role: str) -> str:
    """Invoke ``build_llm`` and return the raised :class:`typer.BadParameter`'s message."""
    try:
        build_llm(spec, role)
    except typer.BadParameter as exc:
        return str(exc)
    raise AssertionError(f"build_llm({spec!r}, {role!r}) did not raise BadParameter")


def test_vertex_without_project_raises_bad_parameter(monkeypatch: pytest.MonkeyPatch) -> None:
    """``vertex:<model>`` with no project resolvable → actionable BadParameter."""
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    msg = _expect_bad_parameter("vertex:gemini-2.5-flash", "attacker")
    lowered = msg.lower()
    assert "vertex" in lowered
    assert "project" in lowered
    # The old M9-pending wording must be gone — Vertex is functional now.
    assert "m9" not in lowered
    assert "unknown provider" not in lowered


def test_vertex_builds_with_project_qualifier(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``+project=`` qualifier (or env) lets the client construct cleanly."""
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    llm = build_llm("vertex:gemini-2.5-flash+project=my-proj+location=us-central1", "attacker")
    try:
        assert llm.provider == "vertex"
        assert llm.project == "my-proj"  # type: ignore[attr-defined]
        assert llm.location == "us-central1"  # type: ignore[attr-defined]
    finally:
        import asyncio

        asyncio.run(llm.aclose())


def test_vertex_builds_with_project_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "env-proj")
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    llm = build_llm("vertex:gemini-2.5-flash", "attacker")
    try:
        assert llm.project == "env-proj"  # type: ignore[attr-defined]
        assert llm.location == "us-central1"  # type: ignore[attr-defined]
    finally:
        import asyncio

        asyncio.run(llm.aclose())
