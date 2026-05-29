"""Conversation/session management over a :class:`Transport` (Stage 1A).

A target may track conversation state in one of three ways, and the swarm must
drive each correctly:

* ``stateless`` — every turn is independent. The machine sends only the current
  prompt and threads no history. No session token is used.
* ``server_session`` — the target keeps state behind a session token it returns.
  The machine captures the token from the first :class:`Response` and replays it
  on subsequent turns; it does *not* resend prior turns as history.
* ``client_history`` — the client owns the transcript. The machine accumulates
  every (user, assistant) pair and resends the full ``conversation`` on each
  turn so a stateless endpoint behaves multi-turn.

:meth:`SessionMachine.isolate_per_scenario` returns a *fresh* machine that
shares the same transport and mode but starts with empty history — used so each
adversarial scenario gets a clean conversation without re-instantiating the
transport. :meth:`reset` clears state in place.
"""

from __future__ import annotations

from enum import Enum

from agent_guardian.transports.base import Message, Request, Response, Transport

__all__ = ["SessionMachine", "SessionMode"]


class SessionMode(str, Enum):
    """How the target tracks conversation state."""

    STATELESS = "stateless"
    SERVER_SESSION = "server_session"
    CLIENT_HISTORY = "client_history"


class SessionMachine:
    """Drives a multi-turn conversation over a :class:`Transport` for one mode."""

    def __init__(
        self,
        transport: Transport,
        *,
        mode: SessionMode = SessionMode.STATELESS,
        session: str | None = None,
    ) -> None:
        self._transport = transport
        self._mode = mode
        self._initial_session = session
        self._session: str | None = session
        self._history: list[Message] = []

    @property
    def mode(self) -> SessionMode:
        return self._mode

    @property
    def session(self) -> str | None:
        """The current server-issued (or seeded) session token, if any."""
        return self._session

    @property
    def history(self) -> tuple[Message, ...]:
        """Accumulated conversation (only populated in ``client_history`` mode)."""
        return tuple(self._history)

    def _build_request(self, prompt: str) -> Request:
        if self._mode is SessionMode.CLIENT_HISTORY:
            return Request(prompt=prompt, conversation=tuple(self._history))
        if self._mode is SessionMode.SERVER_SESSION:
            return Request(prompt=prompt, session=self._session)
        return Request(prompt=prompt)

    async def send(self, prompt: str) -> Response:
        """Send one user turn, updating session/history state per the mode.

        A faulted response (``error`` set) does **not** mutate history or session
        — only successful turns advance conversation state — so a scenario can
        retry cleanly after a rate-limit or timeout.
        """
        request = self._build_request(prompt)
        response = await self._transport.send(request)

        if not response.ok:
            return response

        if self._mode is SessionMode.SERVER_SESSION and response.session is not None:
            self._session = response.session
        elif self._mode is SessionMode.CLIENT_HISTORY:
            self._history.append(Message(role="user", content=prompt))
            self._history.append(Message(role="assistant", content=response.text))

        return response

    def reset(self) -> None:
        """Clear accumulated history and reset the session token to its seed."""
        self._history.clear()
        self._session = self._initial_session

    def isolate_per_scenario(self) -> SessionMachine:
        """Return a fresh machine sharing the transport/mode but with empty state."""
        return SessionMachine(
            self._transport,
            mode=self._mode,
            session=self._initial_session,
        )
