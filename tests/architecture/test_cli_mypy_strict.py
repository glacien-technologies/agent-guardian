"""QA-013 locking test: ``mypy --strict src/agent_guardian/cli.py`` returns 0 errors.

This pins the QA-013 acceptance criterion verbatim: the cli module must be
clean under ``mypy --strict`` so the strict gate can be flipped on for the
whole package without having to scope-exclude cli.py. The historical noise
was 5 errors on ``yaml.safe_load`` / ``yaml.safe_dump`` / ``yaml.YAMLError``
arising from the qualified-attribute access pattern (``import yaml`` then
``yaml.YAMLError``) -- fixed in cli.py by switching to named imports
(``from yaml import YAMLError, safe_dump, safe_load``).

If this test ever fails, the fix is either:
  (a) restore the named-import pattern at the offending call-site, or
  (b) reinstall ``types-pyyaml`` in the dev extra (`uv pip install -e
      '.[dev]'`).

Skipped automatically if ``mypy`` is not importable (e.g. in a runtime-only
install without the ``[dev]`` extra).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_CLI = _REPO_ROOT / "src" / "agent_guardian" / "cli.py"


def _have_mypy() -> bool:
    return shutil.which("mypy") is not None


@pytest.mark.skipif(not _have_mypy(), reason="mypy not installed; install [dev] extra")
def test_cli_module_passes_mypy_strict() -> None:
    """QA-013 acceptance: cli.py must report 0 errors under mypy --strict."""
    assert _CLI.is_file(), f"cli.py not found at {_CLI}"
    result = subprocess.run(
        ["mypy", "--strict", "--config-file", str(_REPO_ROOT / "pyproject.toml"), str(_CLI)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    # mypy exits 0 on success, 1 on any errors. The QA acceptance is "0 errors".
    assert result.returncode == 0, (
        f"mypy --strict on cli.py returned {result.returncode}.\n"
        f"--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}"
    )
    # Belt-and-braces: scan stdout for the 5 historical yaml-stub errors.
    forbidden_markers = [
        'untyped function "safe_load"',
        'untyped function "safe_dump"',
        'Module has no attribute "YAMLError"',
    ]
    for marker in forbidden_markers:
        assert marker not in result.stdout, (
            f"QA-013 regression: mypy reported the historical yaml-stub error "
            f"{marker!r} on cli.py. Restore the at-site `from yaml import ...` "
            f"pattern at lines around 1842 / 1894 in src/agent_guardian/cli.py."
        )


def test_cli_does_not_use_qualified_yaml_access() -> None:
    """QA-013 source-level guard: cli.py must use ``from yaml import ...``.

    This is a fast (no-subprocess) guard that prevents accidental regressions
    to the ``import yaml`` + ``yaml.XYZ`` pattern, which silently re-introduces
    the 5 mypy --strict errors whenever the types-pyyaml stubs are missing or
    incomplete in the dev venv.
    """
    body = _CLI.read_text(encoding="utf-8")
    # Top-level ``import yaml`` is allowed nowhere in cli.py today; nested
    # ``import yaml`` blocks inside the two functions are the historical
    # offenders. Either way, the qualified attribute access patterns below
    # are the symptoms we forbid.
    forbidden_patterns = ["yaml.safe_load", "yaml.safe_dump", "yaml.YAMLError"]
    offenders = [pat for pat in forbidden_patterns if pat in body]
    assert not offenders, (
        f"QA-013 regression: cli.py contains qualified yaml.* access {offenders!r}. "
        f"Use `from yaml import YAMLError, safe_dump, safe_load` at the call-site "
        f"so mypy --strict resolves the symbols against the types-pyyaml stubs."
    )
