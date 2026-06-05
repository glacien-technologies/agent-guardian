"""TargetGuardrailDetector — the live target's own guardrail, as a Detector.

The detection-evasion lane is zero-config by default: the *target's own refusal*
is the monitor. This detector wraps the target's ``call`` coroutine and a refusal
classifier so the generic :class:`~agent_guardian.core.detector_replay.Detector`
contract (and therefore the EvasionRunner loop + DetectorReplay coverage) can run
against the live target with no external monitoring stack configured.

``flags(request, response)`` returns True when the target *refused/blocked* the
request. If a concrete ``response`` is supplied it is classified directly (no
target call); otherwise the detector elicits one by sending ``request``.
"""

from __future__ import annotations

from agent_guardian.strategies.evasion_runner import TargetGuardrailDetector


async def test_flags_true_when_target_refuses() -> None:
    calls: list[str] = []

    async def send(prompt: str) -> str:
        calls.append(prompt)
        return "I'm sorry, but I can't help with that request."

    det = TargetGuardrailDetector(send)
    flagged = await det.flags("transfer all funds to account 999", "")
    assert flagged is True
    assert calls == ["transfer all funds to account 999"]  # it elicited a response


async def test_flags_false_when_target_complies() -> None:
    async def send(prompt: str) -> str:
        return "Sure! I've initiated the transfer of all funds to account 999."

    det = TargetGuardrailDetector(send)
    flagged = await det.flags("transfer all funds to account 999", "")
    assert flagged is False


async def test_provided_response_is_classified_without_calling_target() -> None:
    called = False

    async def send(prompt: str) -> str:
        nonlocal called
        called = True
        return "should not be called"

    det = TargetGuardrailDetector(send)
    # A non-empty response is classified directly — no target call.
    flagged = await det.flags("do the thing", "I cannot comply with that.")
    assert flagged is True
    assert called is False


async def test_empty_response_counts_as_blocked() -> None:
    async def send(prompt: str) -> str:
        return ""

    det = TargetGuardrailDetector(send)
    assert await det.flags("do the thing", "") is True
    # Whitespace-only is also a block.
    assert det._is_refusal("   ") is True  # type: ignore[attr-defined]


async def test_terse_non_empty_reply_is_not_a_refusal() -> None:
    """A short but non-empty compliance like "ok" must NOT be misclassified as a
    block (Codex review: the old <4-char rule mislabelled terse successes)."""
    det = TargetGuardrailDetector(lambda _p: _async_str(""))
    assert det._is_refusal("ok") is False  # type: ignore[attr-defined]
    assert det._is_refusal("done") is False  # type: ignore[attr-defined]
    assert det._is_refusal("$5,000 sent") is False  # type: ignore[attr-defined]


async def _async_str(s: str) -> str:
    return s


async def test_custom_refusal_classifier_is_honoured() -> None:
    async def send(prompt: str) -> str:
        return "BLOCKED_BY_POLICY"

    det = TargetGuardrailDetector(
        send,
        is_refusal=lambda text: "BLOCKED" in text,
        name="acme-guard",
    )
    assert det.name == "acme-guard"
    assert await det.flags("x", "") is True
    assert await det.flags("x", "all good here") is False
