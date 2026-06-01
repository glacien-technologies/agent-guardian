"""Calibration + Brier scoring for LLM judges — Phase C.C7.

The Brier score is the standard probabilistic-classifier evaluation metric:
the mean squared difference between the predicted probability and the actual
outcome (0 or 1). Range [0, 1]; **lower is better**; 0.0 = perfect, 0.25 =
chance for a binary classifier with calibrated predictions, 1.0 = always-wrong.

Why Brier and not accuracy:
  - Accuracy ignores confidence — a judge that's 100% confident and wrong
    looks the same as a judge that's 51% confident and wrong.
  - Brier punishes over-confidence harder than under-confidence (the squared
    error is asymmetric in expectation), which is the right inductive bias
    for security judges: an over-confident "pass" verdict that's actually a
    "fail" is the failure mode we want to surface.

The calibration set is a small hand-labelled fixture (initial seed: 10 items
across ASI categories; expand to 100 per the C7 spec as labels accumulate).
Each item carries a prompt, target response, ground-truth verdict, and the
ASI the verdict was authored under.

Why this is a runtime module (not a test fixture): the calibration set is
versioned with the package + invoked via ``agent-guardian calibrate`` so an
operator can re-run it against any judge they wire in, including private
judges that should not have to round-trip through pytest discovery.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from agent_guardian.models.asi import AsiCategory

_LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Data shape
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CalibrationItem:
    """One hand-labelled (prompt, response, verdict) triple for judge calibration."""

    prompt: str
    target_response: str
    expected_verdict: Literal["pass", "fail"]
    asi: AsiCategory
    # Optional human notes about why this is a clear-pass / clear-fail. Surfaced
    # in the report so an operator who disagrees with a label can find the rationale.
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.prompt:
            raise ValueError("CalibrationItem.prompt must be non-empty")
        if not self.target_response:
            raise ValueError("CalibrationItem.target_response must be non-empty")
        if self.expected_verdict not in ("pass", "fail"):
            raise ValueError(
                f"CalibrationItem.expected_verdict must be 'pass' or 'fail'; got {self.expected_verdict!r}"
            )


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    """Result of running a calibration set against one judge.

    ``brier_score``: lower-is-better metric in [0, 1].
    ``accuracy``: companion accuracy in [0, 1] for sanity-check.
    ``n_items``: number of items evaluated.
    ``judge_label``: free-text label identifying the judge (e.g. "panel-of-3",
        "gemini-3.5-flash"). Surfaces in reports + UI.
    """

    brier_score: float
    accuracy: float
    n_items: int
    judge_label: str


# --------------------------------------------------------------------------- #
# Brier score
# --------------------------------------------------------------------------- #


def brier_score(
    predictions: Sequence[tuple[Literal["pass", "fail"], float]],
    actual: Sequence[Literal["pass", "fail"]],
) -> float:
    """Standard Brier score for a binary classifier.

    Each prediction is ``(predicted_verdict, predicted_confidence)`` where
    confidence is the model's stated probability that the predicted verdict
    is correct. We convert to a probability-of-"fail" (the positive class
    convention for security judges: "fail" = "target was successfully
    attacked") so the formula is the standard binary Brier:

        Brier = mean((p_fail_i - y_i)^2)

    where ``y_i`` is 1 if the actual verdict is "fail" else 0.

    Args:
        predictions: parallel to ``actual``; each (verdict, confidence) pair.
        actual: ground-truth verdicts.

    Returns:
        Brier score in [0, 1]. 0.0 = perfect; lower is better.

    Raises:
        ValueError: lengths don't match OR any confidence is outside [0, 1].
    """
    if len(predictions) != len(actual):
        raise ValueError(
            f"brier_score length mismatch: predictions={len(predictions)} vs actual={len(actual)}"
        )
    if not predictions:
        # Empty set is treated as perfectly-calibrated (no errors). Documenting
        # this so callers know we don't NaN out on empty.
        return 0.0

    sq_errs = []
    for (pred_verdict, conf), actual_verdict in zip(predictions, actual, strict=True):
        if not 0.0 <= conf <= 1.0:
            raise ValueError(f"brier_score confidence must be in [0, 1]; got {conf!r}")
        # p_fail is "probability that the verdict is 'fail'", which is conf if
        # the model said "fail" and (1 - conf) if it said "pass". This lets us
        # treat both verdicts in a single Brier sum.
        p_fail = conf if pred_verdict == "fail" else (1.0 - conf)
        y = 1.0 if actual_verdict == "fail" else 0.0
        sq_errs.append((p_fail - y) ** 2)

    return sum(sq_errs) / len(sq_errs)


def accuracy(
    predictions: Sequence[tuple[Literal["pass", "fail"], float]],
    actual: Sequence[Literal["pass", "fail"]],
) -> float:
    """Companion accuracy metric — fraction of predictions matching actual."""
    if len(predictions) != len(actual):
        raise ValueError(
            f"accuracy length mismatch: predictions={len(predictions)} vs actual={len(actual)}"
        )
    if not predictions:
        return 1.0
    correct = sum(1 for (pv, _), a in zip(predictions, actual, strict=True) if pv == a)
    return correct / len(predictions)


# --------------------------------------------------------------------------- #
# Calibration loader
# --------------------------------------------------------------------------- #


_DEFAULT_CALIBRATION_PATH = Path(__file__).parent / "_calibration.yaml"


def load_calibration_set(path: Path | None = None) -> list[CalibrationItem]:
    """Load the calibration set from YAML.

    YAML shape:
      ```
      items:
        - prompt: "..."
          target_response: "..."
          expected_verdict: pass    # or "fail"
          asi: ASI01_GOAL_HIJACKING
          rationale: "(optional) why this is a clear-pass label"
      ```

    Args:
        path: override path; defaults to packaged ``_calibration.yaml``.

    Returns:
        list of CalibrationItem; order matches YAML order.
    """
    src = path if path is not None else _DEFAULT_CALIBRATION_PATH
    if not src.exists():
        raise FileNotFoundError(f"Calibration set not found at {src}")
    raw = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
    raw_items = raw.get("items") or []
    items: list[CalibrationItem] = []
    for i, entry in enumerate(raw_items):
        try:
            items.append(
                CalibrationItem(
                    prompt=entry["prompt"],
                    target_response=entry["target_response"],
                    expected_verdict=entry["expected_verdict"],
                    asi=AsiCategory(entry["asi"]),
                    rationale=entry.get("rationale", ""),
                )
            )
        except (KeyError, ValueError) as e:
            # Re-raise with the row index so an operator authoring a malformed
            # YAML can find the bad row immediately.
            raise ValueError(f"Calibration item #{i} is malformed: {e}") from e
    _LOG.debug("PhaseC.C7 calibration_loaded: n_items=%d source=%s", len(items), src)
    return items


# --------------------------------------------------------------------------- #
# Run-a-calibration runner
# --------------------------------------------------------------------------- #


# Judge interface: anything callable that takes (prompt, target_response) and
# returns an awaitable yielding (verdict, confidence). This intentionally
# matches the existing Judge / PanelJudge .verdict() signature so the runner
# composes with both. We use a generic Callable typing rather than importing
# the Judge ABC so the runner stays decoupled from the agents layer.
JudgeFn = Callable[[str, str], Awaitable[Any]]


async def run_calibration(
    judge: Any,
    items: Sequence[CalibrationItem],
    judge_label: str = "",
) -> CalibrationReport:
    """Run a calibration set against one judge or judge panel.

    The ``judge`` argument must expose an async ``.verdict(prompt, response)
    -> JudgeVerdict``. Both :class:`agent_guardian.agents.base.Judge` and
    :class:`agent_guardian.judges.panel.PanelJudge` satisfy this.

    Returns a CalibrationReport with Brier + accuracy + sample count. The
    report can be persisted into the Scan model or printed by the CLI.
    """
    if not items:
        return CalibrationReport(
            brier_score=0.0,
            accuracy=1.0,
            n_items=0,
            judge_label=judge_label or "<unspecified>",
        )

    predictions: list[tuple[Literal["pass", "fail"], float]] = []
    actuals: list[Literal["pass", "fail"]] = []

    for item in items:
        verdict_obj = await judge.verdict(item.prompt, item.target_response)
        # JudgeVerdict carries .verdict (str) and .confidence (float). We accept
        # any literal close to "pass"/"fail" plus the heuristic-judge legacy
        # values; coerce to the binary axis.
        raw_v = str(getattr(verdict_obj, "verdict", "")).lower().strip()
        if raw_v in ("pass", "passed", "defended"):
            pv: Literal["pass", "fail"] = "pass"
        elif raw_v in ("fail", "failed", "exploited", "broken"):
            pv = "fail"
        else:
            # An ambiguous verdict counts as a wrong-class half-confidence prediction
            # so it contributes a meaningful Brier penalty rather than crashing.
            pv = "pass" if item.expected_verdict == "fail" else "fail"

        conf = float(getattr(verdict_obj, "confidence", 0.0))
        # Clamp to [0, 1] defensively — a buggy judge might return out-of-range.
        conf = max(0.0, min(1.0, conf))

        predictions.append((pv, conf))
        actuals.append(item.expected_verdict)

    brier = brier_score(predictions, actuals)
    acc = accuracy(predictions, actuals)

    label = judge_label or getattr(judge, "label", "") or judge.__class__.__name__

    _LOG.debug(
        "PhaseC.C7 calibration_done: n_items=%d brier=%.4f accuracy=%.4f judge=%s",
        len(items),
        brier,
        acc,
        label,
    )

    return CalibrationReport(
        brier_score=brier,
        accuracy=acc,
        n_items=len(items),
        judge_label=label,
    )


__all__ = [
    "CalibrationItem",
    "CalibrationReport",
    "accuracy",
    "brier_score",
    "load_calibration_set",
    "run_calibration",
]
