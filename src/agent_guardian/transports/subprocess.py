"""Subprocess transport — scan a local CLI / process target (Stage 4).

A :class:`SubprocessTransport` is the thinnest seam over a *local executable*:
it spawns a process per turn, feeds it the prompt, and reads its reply back off
``stdout``. It exists so an operator can point AgentGuardian at an agent that
ships as a command-line tool (a ``python my_agent.py`` entrypoint, a compiled
binary, a wrapper script) without writing any HTTP plumbing.

The transport is built from **primitives**: a ``command`` argv list, how the
prompt is delivered (``prompt_mode``), and how the reply is read
(``output_mode``). It deliberately uses :func:`asyncio.create_subprocess_exec`
with a *list* argv and **never** ``shell=True`` — the prompt is adversarial
input by construction, so routing it through a shell would be a command-injection
hole.

* ``prompt_mode="stdin"`` — the prompt is written to the child's stdin (which is
  then closed). ``prompt_mode="arg"`` — the prompt is appended as a final argv
  element.
* ``output_mode="stdout_text"`` — the whole captured stdout (stripped) is the
  reply. ``output_mode="stdout_json"`` — stdout is parsed as JSON and a field is
  pulled out with the project's dotted-JSONPath walker
  :func:`agent_guardian.adapters.http_shapes.generic_shape.walk_jsonpath`
  (configured by ``output_path``).

As with every transport, :meth:`send` **never** raises for a fault: a timeout
yields a :class:`agent_guardian.transports.errors.TransportErrorCategory.TIMEOUT`
fault, a spawn failure (missing executable) yields ``UNREACHABLE``, a non-zero
exit yields ``PERMANENT``, and malformed JSON yields ``PARSE``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import ClassVar, Literal

from agent_guardian.adapters.http_shapes.generic_shape import walk_jsonpath
from agent_guardian.transports.base import (
    CapabilityReport,
    Request,
    Response,
    Transport,
)
from agent_guardian.transports.errors import TransportError, TransportErrorCategory

__all__ = ["SubprocessTransport"]

_LOG = logging.getLogger(__name__)

PromptMode = Literal["stdin", "arg"]
OutputMode = Literal["stdout_text", "stdout_json"]


class SubprocessTransport(Transport):
    """Spawn-per-turn transport over a local executable, built from primitives."""

    kind: ClassVar[str] = "subprocess"

    def __init__(
        self,
        command: list[str],
        *,
        prompt_mode: PromptMode = "stdin",
        output_mode: OutputMode = "stdout_text",
        output_path: str = "$.output",
        cwd: str | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        if not command:
            raise ValueError("SubprocessTransport requires a non-empty command argv list")
        if timeout_seconds <= 0:
            raise ValueError("SubprocessTransport timeout_seconds must be positive")
        self._command = list(command)
        self._prompt_mode: PromptMode = prompt_mode
        self._output_mode: OutputMode = output_mode
        self._output_path = output_path
        self._cwd = cwd
        self._timeout_seconds = timeout_seconds

    def _argv(self, prompt: str) -> list[str]:
        if self._prompt_mode == "arg":
            return [*self._command, prompt]
        return list(self._command)

    def _parse_stdout(self, stdout: bytes) -> Response:
        """Turn captured stdout bytes into a :class:`Response`.

        Raises :class:`_ParseError` for the JSON modes when the payload is
        malformed or the configured path produces nothing; :meth:`send` folds
        that into a PARSE fault.
        """
        text = stdout.decode("utf-8", errors="replace")
        if self._output_mode == "stdout_text":
            return Response(text=text.strip(), raw=text)
        # stdout_json
        try:
            data = json.loads(text)
        except (ValueError, json.JSONDecodeError) as exc:
            raise _ParseError(f"subprocess: stdout was not valid JSON: {exc}") from exc
        value = walk_jsonpath(data, self._output_path)
        if value is None:
            raise _ParseError(f"subprocess: output_path {self._output_path!r} produced no value")
        reply = value if isinstance(value, str) else str(value)
        return Response(text=reply, raw=data)

    async def send(self, request: Request) -> Response:
        """Spawn the process, feed the prompt, read the reply. Never raises."""
        argv = self._argv(request.prompt)
        stdin_bytes = request.prompt.encode("utf-8") if self._prompt_mode == "stdin" else None
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self._cwd,
            )
        except (OSError, ValueError) as exc:
            # Missing executable, permission denied, bad cwd, etc.
            _LOG.debug("subprocess transport: spawn failed for %r (%s)", argv, exc)
            return Response(
                error=TransportError(
                    TransportErrorCategory.UNREACHABLE,
                    f"subprocess: failed to spawn {self._command[0]!r}: {exc}",
                )
            )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes), timeout=self._timeout_seconds
            )
        except TimeoutError:
            # asyncio.TimeoutError is an alias of builtins.TimeoutError on 3.11+.
            _LOG.debug("subprocess transport: %r timed out after %ss", argv, self._timeout_seconds)
            await _terminate(proc)
            return Response(
                error=TransportError(
                    TransportErrorCategory.TIMEOUT,
                    f"subprocess: {self._command[0]!r} exceeded {self._timeout_seconds}s",
                )
            )

        if proc.returncode != 0:
            err_preview = stderr.decode("utf-8", errors="replace").strip()[:512]
            _LOG.debug(
                "subprocess transport: %r exited %s (%s)", argv, proc.returncode, err_preview
            )
            return Response(
                error=TransportError(
                    TransportErrorCategory.PERMANENT,
                    f"subprocess: {self._command[0]!r} exited {proc.returncode}: {err_preview}",
                    status_code=proc.returncode,
                )
            )

        try:
            return self._parse_stdout(stdout)
        except _ParseError as exc:
            _LOG.debug("subprocess transport: parse failed (%s)", exc)
            return Response(error=TransportError(TransportErrorCategory.PARSE, str(exc)))

    def describe(self) -> CapabilityReport:
        """Report this subprocess transport's static capabilities.

        A spawn-per-turn process surfaces no tool calls and no server session;
        it can run stateless or replay client history (prior turns are inlined
        into the prompt by the swarm).
        """
        return CapabilityReport(
            kind=self.kind,
            supports_tools=False,
            session_modes=("stateless", "client_history"),
            endpoint=" ".join(self._command),
        )


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    """Best-effort kill of a process that overran its timeout."""
    if proc.returncode is not None:
        return
    try:
        proc.kill()
    except ProcessLookupError:
        _LOG.debug("subprocess transport: process already gone on kill")
        return
    try:
        await proc.wait()
    except ChildProcessError as exc:
        _LOG.debug("subprocess transport: wait after kill failed (%s)", exc)


class _ParseError(Exception):
    """Internal signal: stdout could not be parsed into a reply."""
