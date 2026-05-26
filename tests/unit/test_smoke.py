"""Smoke test placeholder until M2 lands the domain-model tests."""

from agent_guardian import __version__


def test_version_is_set() -> None:
    """The package exposes a version string."""
    assert isinstance(__version__, str)
    assert len(__version__) > 0
