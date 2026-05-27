"""Demo target agents used to exercise AgentGuardian's framework adapters.

These modules are **opt-in** — they pull in LangGraph and the OpenAI Agents
SDK, which are not runtime dependencies of agent-guardian itself. Install
with ``uv sync --extra examples`` (typically alongside ``--extra dev``).

The directory is excluded from pytest collection (see
``[tool.pytest.ini_options].norecursedirs`` in ``pyproject.toml``) because
the smoke-test path makes real Gemini API calls and would cost money on
every CI run.
"""
