"""Tests for SessionMachine across the three conversation modes."""

from __future__ import annotations

from agent_guardian.transports.base import Request, Response, Transport
from agent_guardian.transports.errors import TransportError, TransportErrorCategory
from agent_guardian.transports.session import SessionMachine, SessionMode


class RecordingTransport(Transport):
    """Records every Request and returns canned Responses in order."""

    def __init__(self, responses: list[Response]) -> None:
        self._responses = responses
        self.requests: list[Request] = []
        self._i = 0

    async def send(self, request: Request) -> Response:
        self.requests.append(request)
        resp = self._responses[self._i]
        self._i += 1
        return resp


async def test_stateless_mode_threads_nothing() -> None:
    t = RecordingTransport([Response(text="a"), Response(text="b")])
    sm = SessionMachine(t, mode=SessionMode.STATELESS)
    await sm.send("one")
    await sm.send("two")
    assert [r.prompt for r in t.requests] == ["one", "two"]
    assert all(r.conversation == () for r in t.requests)
    assert all(r.session is None for r in t.requests)
    assert sm.history == ()


async def test_server_session_mode_captures_and_replays_token() -> None:
    t = RecordingTransport(
        [
            Response(text="a", session="srv-123"),
            Response(text="b", session="srv-123"),
        ]
    )
    sm = SessionMachine(t, mode=SessionMode.SERVER_SESSION)
    await sm.send("one")
    assert t.requests[0].session is None  # nothing yet on first turn
    await sm.send("two")
    assert t.requests[1].session == "srv-123"  # replayed
    assert sm.session == "srv-123"
    # server mode does NOT resend prior turns as history
    assert all(r.conversation == () for r in t.requests)


async def test_client_history_mode_accumulates_and_resends() -> None:
    t = RecordingTransport([Response(text="r1"), Response(text="r2")])
    sm = SessionMachine(t, mode=SessionMode.CLIENT_HISTORY)
    await sm.send("u1")
    assert t.requests[0].conversation == ()
    await sm.send("u2")
    convo = t.requests[1].conversation
    assert [(m.role, m.content) for m in convo] == [
        ("user", "u1"),
        ("assistant", "r1"),
    ]
    assert len(sm.history) == 4


async def test_faulted_response_does_not_mutate_state() -> None:
    err = TransportError(TransportErrorCategory.RATE_LIMIT, "rl")
    t = RecordingTransport([Response(error=err), Response(text="ok")])
    sm = SessionMachine(t, mode=SessionMode.CLIENT_HISTORY)
    r1 = await sm.send("u1")
    assert not r1.ok
    assert sm.history == ()  # fault did not advance history
    r2 = await sm.send("u1-retry")
    assert r2.ok
    # second (successful) turn should see empty prior history
    assert t.requests[1].conversation == ()
    assert len(sm.history) == 2


async def test_server_session_fault_keeps_seed_token() -> None:
    err = TransportError(TransportErrorCategory.TIMEOUT, "to")
    t = RecordingTransport([Response(error=err)])
    sm = SessionMachine(t, mode=SessionMode.SERVER_SESSION, session="seed")
    await sm.send("x")
    assert sm.session == "seed"


async def test_isolate_per_scenario_returns_fresh_machine() -> None:
    t = RecordingTransport([Response(text="r1"), Response(text="r2")])
    sm = SessionMachine(t, mode=SessionMode.CLIENT_HISTORY)
    await sm.send("u1")
    assert len(sm.history) == 2

    fresh = sm.isolate_per_scenario()
    assert fresh is not sm
    assert fresh.mode is SessionMode.CLIENT_HISTORY
    assert fresh.history == ()
    # shares the same transport
    await fresh.send("new")
    assert t.requests[-1].prompt == "new"


async def test_reset_clears_history_and_session() -> None:
    t = RecordingTransport([Response(text="r1", session="srv")])
    sm = SessionMachine(t, mode=SessionMode.CLIENT_HISTORY, session="seed")
    await sm.send("u1")
    assert len(sm.history) == 2
    sm.reset()
    assert sm.history == ()
    assert sm.session == "seed"
