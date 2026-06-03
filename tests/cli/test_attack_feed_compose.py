"""QA-005 — AttackFeedRenderer composes with the QA-002 Live region.

The lock requires that reflection cards print as scrollback ABOVE the
Live region (the same code path log lines use) — not inside it. These
tests assert:

* with a Live region open, ``renderer.emit(...)`` causes panel content
  to land in the recorded console export,
* the Live frame is also rendered (and not torn) when both events fire,
* the SwarmCommander observer wrap chain is preserved when the
  renderer is attached AFTER an existing observer (so otel / scan_store
  observers keep firing),
* the renderer attached AFTER the ScanTUI's ``attach_to`` still composes
  — both observers fire for one event.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from typing import Any

import pytest
from rich.console import Console
from rich.live import Live

from agent_guardian.cli_tui import ScanTUI
from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.logging_setup import _AG_THEME, _reset_console_for_tests
from agent_guardian.ui.attack_feed import AttackFeedRenderer
from agent_guardian.ui.dashboard import DashboardState, make_dashboard


@pytest.fixture(autouse=True)
def _reset_console() -> Any:
    _reset_console_for_tests()
    yield
    _reset_console_for_tests()


def _shared_console() -> Console:
    return Console(
        record=True,
        width=140,
        force_terminal=True,
        color_system="truecolor",
        theme=_AG_THEME,
    )


def _turn_record(verdict: str = "fail") -> dict[str, Any]:
    return {
        "agent": "secret-extraction-agent",
        "asi_category": "ASI01",
        "mitre_techniques": ["AML.T0012"],
        "csa_category": "goal-instruction-manipulation",
        "turn": 1,
        "max_turns": 4,
        "strategy": "pair",
        "prompt": "test prompt",
        "rationale": "test",
        "target_response": "test response",
        "verdict": verdict,
        "confidence": 0.5,
        "reasoning": "test reasoning",
        "strategy_metadata": {},
        "seed_id": "TEST-001",
        "attacker_refused": False,
        "attacker_refusal_text": "",
    }


def test_renderer_writes_above_open_live_region() -> None:
    """With a Live region open, ``renderer.emit`` lands in scrollback
    above the panel — recorded output contains BOTH the reflection
    block and the swarm-board panel."""
    console = _shared_console()
    renderer = AttackFeedRenderer(level=1, format="text", console=console)
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    with Live(make_dashboard(state), console=console, refresh_per_second=4) as live:
        renderer.emit(_turn_record(verdict="fail"))
        live.refresh()
    text = console.export_text()
    # The Live's phase-panel headers appear, AND the reflection
    # block sections appear — both present means the renderer hasn't
    # trampled the Live region. QA-012 — the swarm-board flat title
    # is replaced by the three phase-panel titles.
    assert (
        "phase 1" in text.lower() or "reconnaissance" in text.lower() or "phase 3" in text.lower()
    )
    assert "VERDICT" in text
    assert "PROMPT" in text


def test_renderer_attach_to_preserves_prior_observer() -> None:
    """Wrap chain: prior observer → renderer. Both must fire."""
    seen: list[SwarmEvent] = []

    class _FakeSwarm:
        def __init__(self) -> None:
            self.observer: Any = lambda evt: seen.append(evt)

    swarm = _FakeSwarm()
    renderer = AttackFeedRenderer(level=1, format="text", console=_shared_console())
    renderer.attach_to(swarm)  # type: ignore[arg-type]

    # Emit a reflection event through the wrapped observer.
    reflection_event = SwarmEvent(
        kind="reflection",
        timestamp=datetime.now(tz=UTC),
        agent="secret-extraction-agent",
        payload=_turn_record(verdict="fail"),
    )
    swarm.observer(reflection_event)

    # Prior observer received it…
    assert any(evt.kind == "reflection" for evt in seen)
    # …and the renderer rendered it.
    assert renderer.rendered_count == 1


def test_renderer_skips_non_reflection_events() -> None:
    """Wrapped observer must forward non-reflection events too, without
    the renderer trying to print them as reflections."""
    seen: list[str] = []

    class _FakeSwarm:
        def __init__(self) -> None:
            self.observer: Any = lambda evt: seen.append(evt.kind)

    swarm = _FakeSwarm()
    renderer = AttackFeedRenderer(level=1, format="text", console=_shared_console())
    renderer.attach_to(swarm)  # type: ignore[arg-type]

    swarm.observer(
        SwarmEvent(
            kind="agent_start",
            timestamp=datetime.now(tz=UTC),
            agent="x",
        )
    )
    assert seen == ["agent_start"]
    assert renderer.rendered_count == 0


def test_compose_with_scan_tui_both_observers_fire() -> None:
    """If a ScanTUI is attached first and the renderer second, BOTH
    observers fire for one event (the renderer wraps the TUI's wrapper,
    and the TUI's wrapper called the prior observer)."""

    class _FakeSwarm:
        def __init__(self) -> None:
            self.observer: Any = None

    swarm = _FakeSwarm()
    tui = ScanTUI(scan_id="abc", target_ref="t", tier="auto")
    tui.attach_to(swarm)  # type: ignore[arg-type]

    renderer = AttackFeedRenderer(level=1, format="text", console=_shared_console())
    renderer.attach_to(swarm)  # type: ignore[arg-type]

    # Fire a reflection event; the renderer's wrapper handles it AND
    # forwards to the TUI's wrapper (which ignores it but doesn't crash).
    reflection_event = SwarmEvent(
        kind="reflection",
        timestamp=datetime.now(tz=UTC),
        agent="secret-extraction-agent",
        payload=_turn_record(),
    )
    swarm.observer(reflection_event)
    assert renderer.rendered_count == 1

    # Fire a checkpoint event; the TUI updates its DashboardState but
    # the renderer ignores it.
    chk_event = SwarmEvent(
        kind="checkpoint",
        timestamp=datetime.now(tz=UTC),
        provisional_aivss=42,
    )
    swarm.observer(chk_event)
    assert renderer.rendered_count == 1  # unchanged
    assert tui._state.provisional_aivss == 42


def test_renderer_does_not_create_competing_live_region() -> None:
    """The renderer must NOT instantiate its own ``Live``. Inspect the
    module symbols to confirm — defensive guardrail."""
    import inspect

    from agent_guardian.ui import attack_feed as mod

    # We accept ``rich.live.Live`` as an *import* nowhere in the module.
    # Static check: read the source file and assert no Live() call.
    source = inspect.getsource(mod)
    assert "Live(" not in source, "AttackFeedRenderer must not own a Live region"


def test_json_mode_writes_to_stream_no_console_writes() -> None:
    """JSON mode should not touch the shared console at all (operator
    pipes the stream into jq)."""
    console = _shared_console()
    stream = io.StringIO()
    renderer = AttackFeedRenderer(
        level=1, format="json", console=console, stream=stream, scan_id="abc"
    )
    renderer.emit(_turn_record(verdict="fail"))
    # Console got nothing.
    text = console.export_text().strip()
    assert text == ""
    # Stream got one line.
    assert stream.getvalue().strip().count("\n") == 0
    assert "reflection" in stream.getvalue()


def test_renderer_failure_in_one_sink_does_not_kill_others() -> None:
    """A sink that raises is suppressed so the wrap chain keeps firing."""
    seen: list[SwarmEvent] = []

    class _FakeSwarm:
        def __init__(self) -> None:
            def _prior(evt: SwarmEvent) -> None:
                if evt.kind == "reflection":
                    raise RuntimeError("sick downstream observer")
                seen.append(evt)

            self.observer: Any = _prior

    swarm = _FakeSwarm()
    renderer = AttackFeedRenderer(level=1, format="text", console=_shared_console())
    renderer.attach_to(swarm)  # type: ignore[arg-type]

    reflection_event = SwarmEvent(
        kind="reflection",
        timestamp=datetime.now(tz=UTC),
        agent="x",
        payload=_turn_record(),
    )
    # Must not raise.
    swarm.observer(reflection_event)
    # Renderer still recorded the event.
    assert renderer.rendered_count == 1
