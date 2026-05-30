"""CLI tests for the Vertex provider gating (#15).

Until M9 lands OAuth2 service-account authentication, the Vertex provider
is request-builder-only. The CLI must refuse a ``vertex:<model>`` spec
with a clear M9-pending error rather than letting it fall through to the
generic ``Unknown provider`` message — and rather than letting the swarm
start and crash at first ``.complete()`` call.
"""

from __future__ import annotations

import typer

from agent_guardian.cli import build_llm


def _expect_bad_parameter(spec: str, role: str) -> str:
    """Invoke ``build_llm`` and return the raised :class:`typer.BadParameter`'s message.

    Raises :exc:`AssertionError` if the call does NOT raise BadParameter —
    the test suite would otherwise quietly pass on a regression that let the
    spec fall through.
    """
    try:
        build_llm(spec, role)
    except typer.BadParameter as exc:
        return str(exc)
    raise AssertionError(f"build_llm({spec!r}, {role!r}) did not raise BadParameter")


def test_vertex_provider_raises_m9_pending_bad_parameter() -> None:
    """``vertex:<model>`` is rejected with the M9-pending guidance string."""
    msg = _expect_bad_parameter("vertex:gemini-pro", "attacker")
    lowered = msg.lower()
    # The message must clearly call out that Vertex is M9-pending so the
    # operator doesn't think it's a typo / unsupported model -- it's a
    # known-unimplemented provider.
    assert "vertex" in lowered
    assert "m9" in lowered or "pending" in lowered
    # Don't leak the generic "Unknown provider" wording from the fall-through.
    assert "unknown provider" not in lowered
