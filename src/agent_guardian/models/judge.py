"""Judge verdict — the structured output of the per-finding LLM evaluator."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["JudgeVerdict"]


class JudgeVerdict(BaseModel):
    """Structured judge output for a single attack attempt."""

    verdict: Literal["pass", "fail", "inconclusive"]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str

    model_config = ConfigDict(frozen=True, extra="forbid")
