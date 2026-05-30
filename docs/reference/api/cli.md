# CLI module

**TL;DR** — `agent_guardian.cli` is the Typer app that backs the `agent-guardian` command. The same helpers (`build_llm`, `build_target_adapter`) are importable from Python, so anything the CLI does is reproducible from a script.

For the user-facing command reference (every flag of every sub-command), see [CLI Reference](../cli.md). This page is the module-level docstring + helpers, generated from source.

::: agent_guardian.cli
    options:
      members:
        - app
        - build_llm
        - build_target_adapter
      show_root_heading: false
      show_source: true
