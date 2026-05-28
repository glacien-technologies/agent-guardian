"""PoV-as-oracle (M2 Pattern 2).

Every finding ships with a reproducible Proof-of-Vulnerability: a deterministic
scenario the :class:`PoVRunner` re-runs N times against the transport, asserting
an observable indicator. The finding is only credible if reliability clears the
gate (default 0.8). Reliability — not an evasion-tuned payload — is the
credibility metric.
"""

from agent_guardian.core.pov.harness import (
    IndicatorKind,
    PoVScript,
    SuccessIndicator,
)
from agent_guardian.core.pov.runner import PoVResult, PoVRunner, wilson_lower_bound

__all__ = [
    "IndicatorKind",
    "PoVResult",
    "PoVRunner",
    "PoVScript",
    "SuccessIndicator",
    "wilson_lower_bound",
]
