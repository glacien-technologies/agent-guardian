"""Tests for the network sandbox."""

from __future__ import annotations

import contextlib
import socket

import httpx
import pytest

from agent_guardian.core.sandbox import (
    Sandbox,
    SandboxPolicy,
    SandboxViolation,
    current_sandbox,
)


def test_policy_defaults_allow_known_provider_hosts() -> None:
    p = SandboxPolicy()
    assert Sandbox.is_allowed("api.openai.com", 443, p)
    assert Sandbox.is_allowed("api.anthropic.com", 443, p)
    assert Sandbox.is_allowed("localhost", 11434, p)
    assert Sandbox.is_allowed("127.0.0.1", 11434, p)
    assert Sandbox.is_allowed("::1", 11434, p)


def test_policy_default_blocks_arbitrary_host() -> None:
    p = SandboxPolicy()
    assert not Sandbox.is_allowed("evil.example.com", 443, p)
    assert not Sandbox.is_allowed("1.2.3.4", 80, p)


def test_policy_allows_bedrock_regional_host() -> None:
    p = SandboxPolicy()
    assert Sandbox.is_allowed("bedrock-runtime.us-west-2.amazonaws.com", 443, p)
    assert Sandbox.is_allowed("bedrock-runtime.ap-southeast-2.amazonaws.com", 443, p)


def test_policy_rejects_unrelated_amazonaws_host() -> None:
    p = SandboxPolicy()
    # s3.amazonaws.com doesn't contain "bedrock" → blocked.
    assert not Sandbox.is_allowed("s3.amazonaws.com", 443, p)


def test_policy_allows_vertex_regional_host() -> None:
    p = SandboxPolicy()
    assert Sandbox.is_allowed("us-central1-aiplatform.googleapis.com", 443, p)
    assert Sandbox.is_allowed("europe-west4-aiplatform.googleapis.com", 443, p)


def test_policy_rejects_unrelated_googleapis_host() -> None:
    p = SandboxPolicy()
    assert not Sandbox.is_allowed("storage.googleapis.com", 443, p)


def test_policy_can_disable_bedrock() -> None:
    p = SandboxPolicy(allow_aws_bedrock_regions=False)
    assert not Sandbox.is_allowed("bedrock-runtime.us-west-2.amazonaws.com", 443, p)


def test_policy_can_disable_vertex() -> None:
    p = SandboxPolicy(allow_vertex_regions=False)
    assert not Sandbox.is_allowed("us-central1-aiplatform.googleapis.com", 443, p)


def test_policy_strips_ipv6_brackets() -> None:
    p = SandboxPolicy()
    assert Sandbox.is_allowed("[::1]", 443, p)


def test_policy_empty_host_blocked() -> None:
    p = SandboxPolicy()
    assert not Sandbox.is_allowed("", 443, p)


# --- Sandbox context manager -------------------------------------------


async def test_sandbox_blocks_disallowed_http_async() -> None:
    async with Sandbox() as sb:
        async with httpx.AsyncClient() as client:
            with pytest.raises(SandboxViolation):
                await client.get("https://evil.example.com")
        assert len(sb.violations) == 1
        assert sb.violations[0].host == "evil.example.com"


async def test_sandbox_logs_instead_of_raising_in_log_mode() -> None:
    policy = SandboxPolicy(on_violation="log")
    async with Sandbox(policy=policy) as sb:
        async with httpx.AsyncClient() as client:
            # Connection will fail at the network layer (DNS / route), but the
            # sandbox itself must not raise SandboxViolation.
            try:
                await client.get("https://evil.example.com", timeout=0.001)
            except SandboxViolation:
                pytest.fail("policy=log should not raise SandboxViolation")
            except (httpx.HTTPError, OSError):
                pass  # expected: real network call fails
        assert len(sb.violations) >= 1


async def test_sandbox_records_multiple_violations() -> None:
    policy = SandboxPolicy(on_violation="log")
    async with Sandbox(policy=policy) as sb:
        async with httpx.AsyncClient() as client:
            for host in ("a.example.com", "b.example.com", "c.example.com"):
                with contextlib.suppress(httpx.HTTPError, OSError, SandboxViolation):
                    await client.get(f"https://{host}", timeout=0.001)
        recorded = {v.host for v in sb.violations}
        assert {"a.example.com", "b.example.com", "c.example.com"} <= recorded


def test_sandbox_blocks_disallowed_socket_connect() -> None:
    with Sandbox():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(SandboxViolation):
                s.connect(("93.184.216.34", 443))  # example.com IP literal
        finally:
            s.close()


def test_sandbox_blocks_disallowed_connect_ex_in_raise_mode() -> None:
    with Sandbox():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(SandboxViolation):
                s.connect_ex(("93.184.216.34", 443))
        finally:
            s.close()


def test_sandbox_allows_loopback_socket() -> None:
    # Bind a server on localhost and confirm we can connect.
    with Sandbox():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            try:
                client.connect(("127.0.0.1", port))
            finally:
                client.close()
        finally:
            srv.close()


def test_sandbox_ignores_af_unix() -> None:
    """AF_UNIX paths must not be inspected as IP hosts."""
    with Sandbox():
        if not hasattr(socket, "AF_UNIX"):
            pytest.skip("AF_UNIX not available on this platform")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # connecting to a non-existent unix path → OSError, but no SandboxViolation
            with pytest.raises(OSError):
                s.connect("/nonexistent/path.sock")
        finally:
            s.close()


def test_sandbox_restores_patches_on_exit() -> None:
    original_connect = socket.socket.connect
    original_async_send = httpx.AsyncClient.send
    with Sandbox():
        # Patches active.
        assert socket.socket.connect is not original_connect
        assert httpx.AsyncClient.send is not original_async_send
    # Restored.
    assert socket.socket.connect is original_connect
    assert httpx.AsyncClient.send is original_async_send


def test_sandbox_restores_patches_on_exception_during_setup() -> None:
    """If setup fails midway, patches must be torn down cleanly."""
    original_connect = socket.socket.connect

    class _Broken(Sandbox):
        def _install_socket_patches(self) -> None:  # type: ignore[override]
            super()._install_socket_patches()
            raise RuntimeError("simulated setup failure")

    with pytest.raises(RuntimeError, match="simulated"), _Broken():
        pytest.fail("should not enter body")
    assert socket.socket.connect is original_connect


def test_current_sandbox_tracks_active() -> None:
    assert current_sandbox() is None
    with Sandbox() as sb:
        assert current_sandbox() is sb
    assert current_sandbox() is None


def test_nested_sandboxes_track_innermost() -> None:
    with Sandbox() as outer:
        with Sandbox() as inner:
            assert current_sandbox() is inner
        assert current_sandbox() is outer


async def test_sandbox_async_aenter_exception_restores() -> None:
    """Even when aenter fails after partial install, patches are restored."""
    original_connect = socket.socket.connect

    class _Broken(Sandbox):
        async def __aenter__(self) -> Sandbox:  # type: ignore[override]
            await super().__aenter__()
            await self.__aexit__(None, None, None)
            raise RuntimeError("teardown immediately")

    with pytest.raises(RuntimeError):
        async with _Broken():
            pass
    assert socket.socket.connect is original_connect


def test_sandbox_violation_attributes() -> None:
    v = SandboxViolation("nope", host="x.com", port=443)
    assert v.host == "x.com"
    assert v.port == 443
    assert str(v) == "nope"


def test_sandbox_violation_default_attrs() -> None:
    v = SandboxViolation("nope")
    assert v.host is None
    assert v.port is None


async def test_sandbox_permits_openai_host() -> None:
    """Allowed host should pass the sandbox check (we mock the network)."""
    import respx
    from httpx import Response

    with respx.mock(base_url="https://api.openai.com") as mock:
        mock.get("/ping").mock(return_value=Response(200, json={"ok": True}))
        async with Sandbox() as sb:
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://api.openai.com/ping")
                assert resp.status_code == 200
            assert sb.violations == ()


def test_sandbox_sync_httpx_blocked() -> None:
    """The sync httpx.Client.send patch must also enforce the policy."""
    policy = SandboxPolicy(on_violation="log")
    with Sandbox(policy=policy) as sb, httpx.Client() as client:
        with contextlib.suppress(httpx.HTTPError, OSError, SandboxViolation):
            client.get("https://evil.example.com", timeout=0.001)
        recorded = {v.host for v in sb.violations}
        # `recorded` is a set of host strings — `in` is set-membership equality,
        # not URL substring matching, so this is safe.
        assert "evil.example.com" in recorded  # lgtm[py/incomplete-url-substring-sanitization]


def test_sandbox_sync_httpx_allowed_via_respx() -> None:
    """Sync client to an allow-listed host passes through."""
    import respx
    from httpx import Response

    with respx.mock(base_url="https://api.openai.com") as mock:
        mock.get("/ok").mock(return_value=Response(200, json={"ok": True}))
        with Sandbox() as sb:
            with httpx.Client() as client:
                resp = client.get("https://api.openai.com/ok")
                assert resp.status_code == 200
            assert sb.violations == ()


def test_sandbox_socket_connect_with_non_tuple_address() -> None:
    """Connecting with a non-tuple address (e.g. AF_UNIX path) is ignored by the IP guard."""
    # We've already covered AF_UNIX; this checks the _extract_host_port fallback.
    with Sandbox():
        # IPv4 socket with a malformed address tuple — should still pass to socket.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises((TypeError, SandboxViolation, OSError)):
                s.connect("not-a-tuple")  # type: ignore[arg-type]
        finally:
            s.close()
