"""CrewAI demo target — multi-agent crew used to exercise CrewAIAdapter.

This module is **opt-in**. CrewAI is not a runtime dependency of
agent-guardian; install with ``uv sync --extra examples-crewai`` (or
``pip install crewai`` in your own environment).

Exposes a module-level :data:`research_crew` (Mode D handle for
``--framework crewai``) and an async :func:`run` callable (Mode B handle
for ``CodeAdapter``).
"""
