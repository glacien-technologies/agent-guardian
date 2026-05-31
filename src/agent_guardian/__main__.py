"""Allow ``python -m agent_guardian`` to invoke the Typer CLI.

This is the entry point QA-009's auto-serve manager uses to spawn a
child ``serve`` process; running the package via ``-m`` is portable
across virtualenvs and avoids depending on the ``agent-guardian``
console script being on ``PATH`` in the child process's environment.
"""

from __future__ import annotations

from agent_guardian.cli import app


def main() -> None:
    """Invoke the Typer ``app`` so ``python -m agent_guardian ...`` works."""
    app()


if __name__ == "__main__":
    main()
