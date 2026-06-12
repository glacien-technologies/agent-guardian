"""Issue #150 — ``agent-guardian models list`` subcommand.

Three sites in ``src/agent_guardian/llm/validation.py`` (the ``not_found``
branches at lines 504, 524, 924 as of rc20) tell the user to ``Run
`agent-guardian models list` to see all available ids.`` That suggestion
was a dead end before this fix: no such subcommand existed, so the
operator hit a brick wall after the CLI politely refused to scan with an
unknown model.

These tests lock the post-fix invariants:

1. ``agent-guardian models list`` is a real subcommand (exits 0).
2. Listing without filters prints every provider in
   :data:`agent_guardian.llm.validation.KNOWN_MODELS` plus its model
   ids — the same allow-list the validator uses for ``difflib`` "did you
   mean" hints. One source of truth, surfaced once.
3. The ``--provider`` filter narrows output to a single provider and
   raises a clean error on an unknown provider — no traceback leakage.
4. The dead-link in the validator's error message now points to an
   existing command (so the symptom #150 reported cannot recur).
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from agent_guardian.cli import app
from agent_guardian.llm.validation import KNOWN_MODELS


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# Issue #150 — the dead-link reproduction lock.
# ---------------------------------------------------------------------------


def test_models_list_is_a_real_subcommand(runner: CliRunner) -> None:
    """The bug: the error suggested ``agent-guardian models list`` and the
    command didn't exist. Lock that it now exists and exits 0."""
    result = runner.invoke(app, ["models", "list"])
    assert result.exit_code == 0, (
        f"`models list` must be a real subcommand (issue #150). Exit code "
        f"{result.exit_code}, stdout={result.stdout!r}"
    )


def test_models_list_prints_every_known_provider(runner: CliRunner) -> None:
    """The listing must surface every provider present in KNOWN_MODELS so
    operators steered here from the not-found error have a complete map."""
    result = runner.invoke(app, ["models", "list"])
    assert result.exit_code == 0
    for provider in KNOWN_MODELS:
        # Providers with an empty corpus (azure, openrouter, groq, ...) still
        # appear in the listing — knowing the gateway is supported is itself
        # useful, even when we ship no static id list for it.
        assert provider in result.stdout, (
            f"provider {provider!r} from KNOWN_MODELS must appear in `models "
            f"list` output, stdout=\n{result.stdout}"
        )


def test_models_list_prints_every_known_model_id(runner: CliRunner) -> None:
    """For every provider that ships a non-empty static allow-list, every
    one of its ids must appear in the output. This is the contract the
    error message refers to."""
    result = runner.invoke(app, ["models", "list"])
    assert result.exit_code == 0
    for provider, ids in KNOWN_MODELS.items():
        for model_id in ids:
            assert model_id in result.stdout, (
                f"model id {model_id!r} (provider {provider!r}) missing from `models list` output"
            )


# ---------------------------------------------------------------------------
# --provider filter — single-provider use case.
# ---------------------------------------------------------------------------


def test_models_list_provider_filter_narrows_output(runner: CliRunner) -> None:
    """``--provider openai`` should print openai ids and NOT print ids from
    other providers — narrowing is the whole point of the filter."""
    result = runner.invoke(app, ["models", "list", "--provider", "openai"])
    assert result.exit_code == 0
    for openai_id in KNOWN_MODELS["openai"]:
        assert openai_id in result.stdout
    # The exclusion check: an anthropic-only id must not appear.
    assert "claude-opus-4-5" not in result.stdout, (
        "filter must exclude ids from other providers, stdout=\n" + result.stdout
    )


def test_models_list_provider_filter_rejects_unknown_provider(runner: CliRunner) -> None:
    """An unknown provider gets a clean error (non-zero exit, no traceback),
    not a silent empty output that looks like a successful list."""
    result = runner.invoke(app, ["models", "list", "--provider", "definitely-not-a-real-provider"])
    assert result.exit_code != 0, (
        "unknown provider must exit non-zero so scripts can detect the typo"
    )
    # No raw traceback. The error must be a typer/click-style message.
    assert "Traceback" not in result.stdout
    assert "Traceback" not in (result.stderr or "")


# ---------------------------------------------------------------------------
# The validator-error-message contract: the suggestion must stay reachable.
# ---------------------------------------------------------------------------


def test_validator_error_suggestion_points_to_a_real_command() -> None:
    """Read the validator source and assert: every site that tells the user
    to ``Run `agent-guardian X`...`` must reference a subcommand that exists.

    This is the regression lock for issue #150. If a future contributor
    adds another not-found branch with a different (nonexistent) command
    suggestion, this test will catch it before it ships."""
    import re
    from pathlib import Path

    from agent_guardian import cli as cli_module
    from agent_guardian.llm import validation as validation_module

    # Every typer command name that the CLI actually registers.
    registered = {cmd.name for cmd in cli_module.app.registered_commands}
    # Sub-apps (e.g. ``models``) are registered as ``add_typer`` groups.
    registered_groups = {grp.name for grp in cli_module.app.registered_groups}
    allowed = registered | registered_groups

    source = Path(validation_module.__file__).read_text()
    # Match each ``Run `agent-guardian <word>...`` suggestion. The captured
    # group is the immediate next token — that's the subcommand or group.
    suggestions = re.findall(r"Run `agent-guardian ([\w-]+)", source)
    assert suggestions, "expected to find at least one suggestion line"
    for suggested in suggestions:
        assert suggested in allowed, (
            f"validation.py suggests `agent-guardian {suggested}` but no such "
            f"top-level CLI command or sub-app exists. Either add it, or "
            f"change the suggestion. (issue #150 regression check)"
        )
