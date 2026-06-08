"""Output-engine fail-fast probes (QA-010 + QA-011 row source).

Single public entry point — :func:`validate_output_engine_available` — returns
an :class:`EngineCheck` the CLI consumes for two distinct closures:

1. **QA-010 fail-fast** at scan-startup so a missing PDF engine errors out
   *before* the swarm burns LLM budget. Previously the PDF dep check happened
   at write-time at the *end* of the scan; the operator paid for a 6-minute
   scan only to discover the writer couldn't emit anything.
2. **QA-011 plan-panel row source** for the OUTPUTS section of the
   "scan plan" panel — ✓/✗ per format, sourced from the same primitive so
   the two closures never drift.

Design contract:

* **Pure.** No network I/O. Only ``importlib.util.find_spec`` checks; the
  function is cheap enough to call repeatedly without caching at the
  caller side, though the caller may cache per format if it wants to.
* **Deterministic.** Same environment → same :class:`EngineCheck`.
* **Discrete states.** ``status`` is one of ``ok`` / ``missing`` /
  ``unknown_format`` (NOT an exception), so the plan-panel row builder
  can render the row uniformly without try/except plumbing.
* **No top-level import of** :mod:`agent_guardian.reports.pdf`.  The PDF
  dispatcher imports its native engine helpers lazily; mirroring that
  here keeps the probe trivially typecheckable even on systems with
  broken native PDF libs.

Per-format truth table:

==========  ====================================================
Format      Resolution
==========  ====================================================
``json``    Always ``ok`` (stdlib).
``sarif``   Always ``ok`` — ``jsonschema`` is in base deps.
``junit``   Always ``ok`` — hand-rolled XML via stdlib.
``md``      Always ``ok`` (stdlib).
``gitlab``  Always ``ok`` — GitLab SAST JSON via stdlib.
``pdf``     ``ok`` iff WeasyPrint native deps probe-render OK,
            OR ReportLab is importable. Otherwise ``missing``
            with ``install_hint='pip install agent-guardian[full]'``.
other       ``unknown_format``.
==========  ====================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

__all__ = [
    "ALL_FORMATS",
    "EngineCheck",
    "EngineStatus",
    "validate_output_engine_available",
]

#: Discrete outcomes of an engine probe. Kept as a ``Literal`` so static
#: checkers can prove the switch in :func:`validate_output_engine_available`
#: is exhaustive.
EngineStatus = Literal["ok", "missing", "unknown_format"]

#: Every format the CLI advertises via ``--output``. Used by the unknown-
#: format short-circuit and by the plan panel to enumerate rows.
ALL_FORMATS: Final[frozenset[str]] = frozenset({"json", "sarif", "junit", "md", "gitlab", "pdf"})


@dataclass(frozen=True)
class EngineCheck:
    """Result of probing one ``--output`` format's engine availability.

    Attributes:
        format: The lower-cased format string (``"pdf"``, ``"json"``, etc.).
        status: One of ``"ok"`` / ``"missing"`` / ``"unknown_format"``.
        engine: The resolved engine name when ``status == "ok"``. One of
            ``"stdlib"`` (for json / sarif / junit / md), ``"weasyprint"``,
            or ``"reportlab"``. Empty string otherwise.
        message: Operator-readable explanation. Always populated when
            ``status != "ok"``; empty for ``ok``.
        install_hint: ``pip install ...`` command that would fix a
            ``missing`` engine. Empty for ``ok`` and ``unknown_format``.
    """

    format: str
    status: EngineStatus
    engine: str = ""
    message: str = ""
    install_hint: str = ""

    @property
    def available(self) -> bool:
        """``True`` iff the engine for this format is importable."""
        return self.status == "ok"

    @property
    def missing_extra(self) -> str:
        """Alias for :attr:`install_hint` kept for the locked spec text.

        The design lock pins this property name so a downstream consumer
        can read either ``check.install_hint`` (descriptive) or
        ``check.missing_extra`` (semantic) without thinking about which
        the codebase happens to use today.
        """
        return self.install_hint


def validate_output_engine_available(format: str) -> EngineCheck:
    """Return engine-availability outcome for one ``--output`` format.

    See module docstring for the per-format truth table.

    Args:
        format: Format string as it would appear on the CLI (case-insensitive).

    Returns:
        :class:`EngineCheck` describing the outcome. Never raises.
    """
    fmt = format.lower()

    if fmt not in ALL_FORMATS:
        return EngineCheck(
            format=fmt,
            status="unknown_format",
            message=(f"unknown output format {format!r}; expected one of {sorted(ALL_FORMATS)}"),
        )

    if fmt in {"json", "sarif", "junit", "md", "gitlab"}:
        return EngineCheck(format=fmt, status="ok", engine="stdlib")

    # fmt == "pdf" — defer the import so this module type-checks cleanly even
    # on a box with a broken native PDF stack.
    from agent_guardian.reports.pdf import _has_reportlab, _has_weasyprint

    if _has_weasyprint():
        return EngineCheck(format=fmt, status="ok", engine="weasyprint")
    if _has_reportlab():
        return EngineCheck(format=fmt, status="ok", engine="reportlab")
    return EngineCheck(
        format=fmt,
        status="missing",
        message="no PDF engine importable",
        install_hint="pip install agent-guardian[full]",
    )
