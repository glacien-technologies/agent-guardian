"""AgentGuardian CLI entrypoint. Production commands land in M10."""

from __future__ import annotations

import typer

from agent_guardian._version import __version__

app = typer.Typer(
    name="agent-guardian",
    help="Adversarial swarm framework for agentic AI red-teaming.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the installed agent-guardian version and exit."""
    typer.echo(__version__)


@app.command()
def doctor() -> None:
    """Verify install and runtime prerequisites."""
    typer.echo(f"agent-guardian {__version__}")
    typer.echo("CLI: ok")
    typer.echo("(M10 will add LLM-provider and sandbox checks.)")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version_flag: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """AgentGuardian Open."""


if __name__ == "__main__":
    app()
