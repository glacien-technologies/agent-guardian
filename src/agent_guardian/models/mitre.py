"""MITRE ATLAS technique identifiers used by AgentGuardian probes and findings.

A valid ``MitreTechnique`` value is either:

1. An ATLAS technique ID matching the regex ``^AML\\.T\\d{4}(\\.\\d{3})?$`` — sub-techniques
   use a three-digit ``.NNN`` suffix.
2. One of the named v5.4.0 agent-specific techniques frozen in :data:`NAMED_TECHNIQUES`.

The frozen named set is sourced from MITRE ATLAS v5.4.0, February 2026, covering
agent-specific techniques that do not yet carry a stable ``AML.TNNNN`` identifier.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator

__all__ = ["ATLAS_ID_PATTERN", "NAMED_TECHNIQUES", "MitreTechnique"]

ATLAS_ID_PATTERN = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")

# Frozen set of named v5.4.0 ATLAS techniques specifically targeting agentic systems.
# Cite: MITRE ATLAS v5.4.0, February 2026.
NAMED_TECHNIQUES: frozenset[str] = frozenset(
    {
        "Publish Poisoned AI Agent Tool",
        "Escape to Host",
        "AI Agent Context Poisoning",
        "Modify AI Agent Configuration",
        "Memory Manipulation",
        "Thread Injection",
        "RAG Credential Harvesting",
        "Exfiltration via AI Agent Tool Invocation",
    }
)


def _validate(value: str) -> str:
    """Reject any string that isn't an ATLAS ID or one of the named techniques."""
    if not isinstance(value, str):  # pragma: no cover — pydantic coerces first
        raise ValueError("MITRE ATLAS technique must be a string")
    if value in NAMED_TECHNIQUES:
        return value
    if ATLAS_ID_PATTERN.match(value):
        return value
    raise ValueError(
        f"Invalid MITRE ATLAS technique {value!r}: expected an ID matching "
        f"'AML.TNNNN' or 'AML.TNNNN.NNN', or one of the named v5.4.0 techniques."
    )


MitreTechnique = Annotated[str, AfterValidator(_validate)]
