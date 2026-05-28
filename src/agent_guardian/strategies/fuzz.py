"""Coverage-guided fuzzing strategy (M2 — FuzzingAgent engine).

A deterministic, LLM-free mutation engine in the :class:`Strategy` shape. Each
turn it mutates a corpus entry and sends it; the target's response is reduced to
a coarse *signature* (length bucket + error markers + shape), and any input that
elicits a previously-unseen signature is promoted back into the corpus — the
classic coverage-guided feedback loop (libFuzzer / AFL-style), with response
behaviour standing in for code coverage in a black-box setting.

No attacker LLM is used, so this strategy is effectively free and fully
deterministic given the seed — which is exactly what the PoV runner needs to
reproduce a fuzzing finding.
"""

from __future__ import annotations

import logging
import random
import re

from agent_guardian.strategies.base import (
    NextPrompt,
    Strategy,
    StrategyContext,
    StrategyDone,
    StrategyResult,
    Turn,
    seed_text,
)

__all__ = ["FuzzStrategy", "response_signature"]

_LOG = logging.getLogger(__name__)

_ERROR_MARKERS = (
    "traceback",
    "exception",
    "stack trace",
    "unhandled",
    "json.decoder",
    "keyerror",
    "valueerror",
    "typeerror",
    "internal server error",
    "500",
)


def response_signature(response: str) -> str:
    """Coarse behavioural signature of a response (the 'coverage' proxy).

    Combines a length bucket, presence of error/exception markers, whether it
    looks like structured (JSON-ish) output, and whether it's an apparent
    refusal. Distinct signatures => the fuzzer reached new target behaviour.
    """
    lowered = response.lower()
    length_bucket = len(response) // 200  # 200-char buckets
    has_error = any(m in lowered for m in _ERROR_MARKERS)
    looks_json = response.strip()[:1] in ("{", "[")
    looks_refusal = bool(re.match(r"\s*(i\s+can|i'm sorry|sorry|i cannot|unable)", lowered))
    return f"L{length_bucket}|E{int(has_error)}|J{int(looks_json)}|R{int(looks_refusal)}"


# --- mutators: pure str -> str, deterministic given the rng draw ------------


def _mut_oversize(text: str, rng: random.Random) -> str:
    return text + (" " + text) * rng.randint(5, 20)


def _mut_control_chars(text: str, rng: random.Random) -> str:
    inject = "".join(rng.choice(["\x00", "￿", "\r\n", "\t", "‮"]) for _ in range(8))
    pos = rng.randint(0, len(text)) if text else 0
    return text[:pos] + inject + text[pos:]


def _mut_truncate(text: str, rng: random.Random) -> str:
    if not text:
        return text
    return text[: rng.randint(0, len(text))]


def _mut_type_confusion(text: str, rng: random.Random) -> str:
    wrappers = [
        f'{{"arg": {text!r}, "n": -9999999999}}',
        f"[null, {text!r}, {{}}]",
        f'{{"limit": [], "q": {text!r}}}',
        f"{text!r} OR 1=1; --",
    ]
    return rng.choice(wrappers)


def _mut_encoding(text: str, rng: random.Random) -> str:
    forms = [
        text.encode("unicode_escape").decode("ascii", "ignore"),
        "".join(f"\\u{ord(c):04x}" for c in text[:60]),
        text[::-1],
    ]
    return rng.choice(forms) or text


_MUTATORS = (_mut_oversize, _mut_control_chars, _mut_truncate, _mut_type_confusion, _mut_encoding)


class FuzzStrategy(Strategy):
    """Coverage-guided black-box fuzzer (LLM-free, deterministic)."""

    name = "fuzz"
    orthogonality_class = "fuzzing"
    estimated_tokens = 200

    def __init__(self, ctx: StrategyContext, *, max_turns: int | None = None) -> None:
        super().__init__(ctx)
        self.max_turns = max_turns if max_turns is not None else ctx.max_turns
        if self.max_turns < 1:
            raise ValueError("max_turns must be >= 1")
        self._corpus: list[str] = [seed_text(s) for s in ctx.seeds] or ["test"]
        self._seen: set[str] = set()
        self._last_prompt: str | None = None

    def _mutate(self) -> str:
        base = self.ctx.rng.choice(self._corpus)
        mutator = self.ctx.rng.choice(_MUTATORS)
        mutated = mutator(base, self.ctx.rng)
        return mutated[:4000] or base  # cap payload size

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        if self._turn_count >= self.max_turns:
            return StrategyDone(reason="exhausted")

        # Coverage feedback: if the last input elicited a new signature, promote
        # it back into the corpus so future mutations build on it.
        if target_response is not None and self._last_prompt is not None:
            sig = response_signature(target_response)
            if sig not in self._seen:
                self._seen.add(sig)
                self._corpus.append(self._last_prompt)
                _LOG.debug("fuzz: new coverage signature %s (corpus=%d)", sig, len(self._corpus))

        payload = self._mutate()
        self._last_prompt = payload
        self._turn_count += 1
        meta = self._build_seed_metadata(None)
        meta["fuzz_corpus_size"] = len(self._corpus)
        meta["fuzz_signatures"] = len(self._seen)
        return NextPrompt(text=payload, rationale="fuzz-mutation", metadata=meta)
