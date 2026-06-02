"""Helper for normalising Rich/Click help output before substring assertions.

Pass-5 of the CLI-help test stabilisation.

Pass-4 set NO_COLOR=1 + TERM=dumb at the env-var layer, but Rich/Click
sometimes still emit ANSI escape sequences (and line-wrap flag names) in
the captured stdout under CI's narrow-terminal CliRunner. The conftest
shutil.get_terminal_size monkeypatch addresses width; this helper handles
the residual ANSI + whitespace normalisation at the assertion site so
substring asserts on flag names like ``--recon-budget-seconds`` are robust
against future Rich/Click version drift.
"""

from __future__ import annotations

import re

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(s: str) -> str:
    """Remove ANSI escape sequences from help-text output."""
    return _ANSI_ESCAPE_RE.sub("", s)


def normalise_help(s: str) -> str:
    """Strip ANSI then collapse whitespace runs (incl. wrap-breaks) to single spaces.

    Use this at every assertion site that does substring matching against
    Click/Rich help output. It guarantees the assertion is resilient to:
      - ANSI bold/colour escape sequences (`\\x1b[1m...\\x1b[0m`)
      - Soft line wraps in the middle of long flag names
      - Multi-space column padding from Rich tables
    """
    return re.sub(r"\s+", " ", strip_ansi(s))
