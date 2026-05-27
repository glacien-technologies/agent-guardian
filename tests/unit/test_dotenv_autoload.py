"""Tests for the CLI's project-local ``.env`` auto-loading helper.

The helper is non-fatal: it is a silent no-op when python-dotenv is not
installed (production users) and when there is no ``.env`` file in the
cwd. When both conditions are met it populates ``os.environ`` *without*
overriding values the user already exported in their real shell.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_guardian.cli import _try_load_dotenv


@pytest.fixture(autouse=True)
def _isolated_cwd_and_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Pin cwd to a fresh temp dir and clear keys we touch in these tests."""
    monkeypatch.chdir(tmp_path)
    for var in (
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AGENT_GUARDIAN_GEMINI_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


def test_dotenv_loads_from_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A ``.env`` in the cwd populates os.environ when none was previously set."""
    (tmp_path / ".env").write_text("GEMINI_API_KEY=loaded-from-dotenv\n", encoding="utf-8")
    _try_load_dotenv()
    assert os.environ.get("GEMINI_API_KEY") == "loaded-from-dotenv"


def test_dotenv_does_not_override_existing_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A real shell export must always win over the on-disk ``.env``."""
    (tmp_path / ".env").write_text("GEMINI_API_KEY=from-dotenv\n", encoding="utf-8")
    monkeypatch.setenv("GEMINI_API_KEY", "real-env-wins")
    _try_load_dotenv()
    assert os.environ.get("GEMINI_API_KEY") == "real-env-wins"


def test_dotenv_silently_skips_when_no_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No ``.env`` in cwd → no environment mutations, no errors raised."""
    _try_load_dotenv()
    assert os.environ.get("GEMINI_API_KEY") is None


def test_dotenv_loads_env_local_too(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``.env.local`` is also checked (Next.js / Vite convention)."""
    (tmp_path / ".env.local").write_text("OPENAI_API_KEY=local-key\n", encoding="utf-8")
    _try_load_dotenv()
    assert os.environ.get("OPENAI_API_KEY") == "local-key"


def test_dotenv_env_takes_priority_over_env_local(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``.env`` is loaded first, then ``.env.local`` only fills in gaps
    (because we pass ``override=False`` to load_dotenv)."""
    (tmp_path / ".env").write_text("GEMINI_API_KEY=from-env\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text(
        "GEMINI_API_KEY=from-env-local\nANTHROPIC_API_KEY=local-only\n",
        encoding="utf-8",
    )
    _try_load_dotenv()
    # .env wins for the duplicated key; .env.local fills in the gap.
    assert os.environ.get("GEMINI_API_KEY") == "from-env"
    assert os.environ.get("ANTHROPIC_API_KEY") == "local-only"


def test_dotenv_missing_python_dotenv_is_non_fatal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If python-dotenv is not importable the helper is a silent no-op.

    We simulate the missing dependency by replacing the import machinery
    so ``from dotenv import load_dotenv`` raises ImportError, regardless
    of whether the package is actually installed in the test environment.
    """
    import builtins

    real_import = builtins.__import__

    def stub_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "dotenv":
            raise ImportError("simulated missing dotenv")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", stub_import)
    # Even with a .env present, no environment should be populated.
    (tmp_path / ".env").write_text("GEMINI_API_KEY=should-not-load\n", encoding="utf-8")
    _try_load_dotenv()  # must not raise
    assert os.environ.get("GEMINI_API_KEY") is None
