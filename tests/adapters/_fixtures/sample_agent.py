"""Sample sync + async target callables for CodeAdapter tests."""

from __future__ import annotations

# Module-level attributes the adapter's tier-hint heuristic should pick up.
tools = ["search", "calculator"]


def sync_agent(prompt: str) -> str:
    """Sync function that ignores session."""
    return f"sync:{prompt}"


def sync_with_session(prompt: str, session: str | None = None) -> str:
    return f"sync:{prompt}:{session}"


async def async_agent(prompt: str) -> str:
    return f"async:{prompt}"


async def async_with_session(prompt: str, session: str | None = None) -> str:
    return f"async:{prompt}:{session}"


def returns_int(_prompt: str) -> int:
    """Triggers the non-str coercion warning."""
    return 42


# Carries tool-hint attribute so CodeAdapter picks it up.
sync_agent.tools = ["search"]  # type: ignore[attr-defined]
