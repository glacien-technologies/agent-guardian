"""Outbound-network sandbox (PRD §14.3).

The :class:`Sandbox` context manager patches :mod:`httpx` and the low-level
:mod:`socket` API so that a misbehaving target agent inside a scan cannot
exfiltrate data to a host outside the LLM provider allow-list.

The default policy permits exactly the hosts AgentGuardian itself needs to
talk to (OpenAI, Anthropic, localhost / Ollama, plus wildcard rules for
Bedrock and Vertex regional endpoints). Everything else is blocked, and
every blocked attempt is recorded on :attr:`Sandbox.violations` so the
reproducibility receipt can include the evidence.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from dataclasses import dataclass, field
from typing import Any, Literal
from unittest.mock import patch

import httpx

__all__ = ["Sandbox", "SandboxPolicy", "SandboxViolation"]


class SandboxViolation(Exception):
    """Raised when the target attempts an outbound action the sandbox forbids."""

    def __init__(
        self,
        message: str,
        *,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        super().__init__(message)
        self.host = host
        self.port = port


@dataclass(frozen=True)
class SandboxPolicy:
    """Per-scan sandbox policy.

    Defaults block any outbound network call to a host not in the LLM
    provider allow-list. ``allow_side_effects=True`` relaxes filesystem /
    subprocess restrictions (against a tmpfs jail) but does *not* relax
    the network rules.
    """

    allow_hosts: frozenset[str] = frozenset(
        {
            "api.openai.com",
            "api.anthropic.com",
            "localhost",
            "127.0.0.1",
            "::1",
        }
    )
    allow_aws_bedrock_regions: bool = True
    allow_vertex_regions: bool = True
    allow_ollama_local_only: bool = True
    allow_side_effects: bool = False
    on_violation: Literal["raise", "log"] = "raise"


# Thread-local stack of active sandboxes — supports nested patching cleanly.
_ACTIVE = threading.local()


def _stack() -> list[Sandbox]:
    if not hasattr(_ACTIVE, "stack"):
        _ACTIVE.stack = []
    stack: list[Sandbox] = _ACTIVE.stack
    return stack


def _current() -> Sandbox | None:
    stack = _stack()
    return stack[-1] if stack else None


@dataclass
class _Patches:
    """Tracks the active monkey-patches so we can clean them up."""

    handles: list[Any] = field(default_factory=list)


class Sandbox:
    """Async context manager that enforces :class:`SandboxPolicy`.

    Attributes:
        violations: Tuple of every blocked attempt during the scan. Useful
            for the reproducibility receipt even in ``on_violation='log'``
            mode.
    """

    def __init__(self, policy: SandboxPolicy | None = None) -> None:
        self.policy = policy or SandboxPolicy()
        self._violations: list[SandboxViolation] = []
        self._patches = _Patches()

    @property
    def violations(self) -> tuple[SandboxViolation, ...]:
        return tuple(self._violations)

    @staticmethod
    def is_allowed(host: str, port: int, policy: SandboxPolicy) -> bool:
        """Pure rule: would ``policy`` permit a connect to ``(host, port)``?"""
        if not host:
            return False
        host = host.lower().strip("[]")  # strip ipv6 literal brackets
        if host in policy.allow_hosts:
            return True
        if policy.allow_ollama_local_only and host in {"localhost", "127.0.0.1", "::1"}:
            return True
        if (
            policy.allow_aws_bedrock_regions
            and host.endswith(".amazonaws.com")
            and "bedrock" in host
        ):
            return True
        return bool(policy.allow_vertex_regions and host.endswith("-aiplatform.googleapis.com"))

    def _record(self, message: str, *, host: str | None, port: int | None) -> SandboxViolation:
        viol = SandboxViolation(message, host=host, port=port)
        self._violations.append(viol)
        return viol

    def _check_host(self, host: str | None, port: int | None) -> None:
        if host is None:
            host = ""
        if Sandbox.is_allowed(host, port or 0, self.policy):
            return
        viol = self._record(
            f"sandbox: blocked outbound to {host!r}:{port}",
            host=host,
            port=port,
        )
        if self.policy.on_violation == "raise":
            raise viol

    # --- patching -----------------------------------------------------

    def _install_httpx_patches(self) -> None:
        sandbox = self

        original_async_send = httpx.AsyncClient.send
        original_sync_send = httpx.Client.send

        async def patched_async_send(
            self: httpx.AsyncClient,
            request: httpx.Request,
            *args: Any,
            **kwargs: Any,
        ) -> httpx.Response:
            host = request.url.host
            port = request.url.port
            sandbox._check_host(host, port)
            return await original_async_send(self, request, *args, **kwargs)

        def patched_sync_send(
            self: httpx.Client,
            request: httpx.Request,
            *args: Any,
            **kwargs: Any,
        ) -> httpx.Response:
            host = request.url.host
            port = request.url.port
            sandbox._check_host(host, port)
            return original_sync_send(self, request, *args, **kwargs)

        p1 = patch.object(httpx.AsyncClient, "send", patched_async_send)
        p2 = patch.object(httpx.Client, "send", patched_sync_send)
        p1.start()
        p2.start()
        self._patches.handles.extend([p1, p2])

    def _install_socket_patches(self) -> None:
        sandbox = self
        original_connect = socket.socket.connect
        original_connect_ex = socket.socket.connect_ex

        def _extract_host_port(address: Any) -> tuple[str, int]:
            # AF_INET → (host, port); AF_INET6 → (host, port, flowinfo, scopeid)
            if isinstance(address, tuple) and len(address) >= 2:
                host = str(address[0])
                try:
                    port = int(address[1])
                except (TypeError, ValueError):
                    port = 0
                return host, port
            return "", 0

        def patched_connect(self: socket.socket, address: Any) -> None:
            host, port = _extract_host_port(address)
            # Only inspect IP / TCP-ish families; AF_UNIX has a path, allow it.
            if self.family in (socket.AF_INET, socket.AF_INET6):
                sandbox._check_host(host, port)
            return original_connect(self, address)

        def patched_connect_ex(self: socket.socket, address: Any) -> int:
            host, port = _extract_host_port(address)
            if self.family in (socket.AF_INET, socket.AF_INET6):
                try:
                    sandbox._check_host(host, port)
                except SandboxViolation:
                    # connect_ex semantics: return errno-like int rather than raise.
                    # But we still want raise-mode to raise — match _check_host's
                    # behaviour by re-raising here.
                    raise
            return original_connect_ex(self, address)

        p1 = patch.object(socket.socket, "connect", patched_connect)
        p2 = patch.object(socket.socket, "connect_ex", patched_connect_ex)
        p1.start()
        p2.start()
        self._patches.handles.extend([p1, p2])

    # --- context manager ----------------------------------------------

    async def __aenter__(self) -> Sandbox:
        _stack().append(self)
        try:
            self._install_httpx_patches()
            self._install_socket_patches()
        except Exception:
            self._teardown()
            _stack().pop()
            raise
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._teardown()
        stack = _stack()
        if stack and stack[-1] is self:
            stack.pop()

    def _teardown(self) -> None:
        # Stop in reverse order so the most-recently-applied patch unwinds first.
        while self._patches.handles:
            handle = self._patches.handles.pop()
            with contextlib.suppress(RuntimeError):
                # Patch already stopped; safe to ignore.
                handle.stop()

    # Synchronous context-manager fallback — useful for non-async tests.
    def __enter__(self) -> Sandbox:
        _stack().append(self)
        try:
            self._install_httpx_patches()
            self._install_socket_patches()
        except Exception:
            self._teardown()
            _stack().pop()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        self._teardown()
        stack = _stack()
        if stack and stack[-1] is self:
            stack.pop()


def current_sandbox() -> Sandbox | None:
    """Return the innermost active sandbox, if any.

    Useful for callers that want to inspect the active policy without
    holding the context-manager reference.
    """
    return _current()
