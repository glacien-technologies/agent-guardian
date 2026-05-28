# CLI module

The `agent_guardian.cli` module is the Typer app plus the helpers that any Python consumer can reuse to build an LLM, resolve a target adapter, and render reports.

For the user-facing command reference, see [CLI Reference](../cli.md).

::: agent_guardian.cli
    options:
      members:
        - app
        - build_llm
        - build_target_adapter
      show_root_heading: false
      show_source: true
