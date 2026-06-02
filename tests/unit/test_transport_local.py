"""Tests for the local transports: SdkTransport + SubprocessTransport (Stage 4)."""

from __future__ import annotations

import sys

import pytest

from agent_guardian.transports.base import Request
from agent_guardian.transports.errors import TransportErrorCategory
from agent_guardian.transports.sdk import SdkTransport
from agent_guardian.transports.subprocess import SubprocessTransport

# --------------------------------------------------------------------------- #
# SdkTransport
# --------------------------------------------------------------------------- #


def _sync_echo(prompt: str) -> str:
    return f"sync:{prompt}"


async def _async_echo(prompt: str) -> str:
    return f"async:{prompt}"


def _raising(prompt: str) -> str:
    raise RuntimeError("boom")


def _non_string(prompt: str) -> int:
    return len(prompt)


class _CallableAgent:
    async def __call__(self, prompt: str) -> str:
        return f"obj:{prompt}"


def _sync_returning_awaitable(prompt: str) -> object:
    # Statically a sync def, but returns a coroutine the transport must await.
    async def _inner() -> str:
        return f"awaited:{prompt}"

    return _inner()


class _DefaultCtorAgent:
    """Resolves via dotted path; default ctor, sync ``__call__``."""

    def __call__(self, prompt: str) -> str:
        return f"default-ctor:{prompt}"


class _NeedsArgsAgent:
    """Needs ctor args; dotted resolution falls back to the classmethod."""

    def __init__(self, required: int) -> None:
        self.required = required

    @classmethod
    def factory(cls, prompt: str) -> str:
        return f"classmethod:{prompt}"


async def test_sdk_sync_callable_returns_reply() -> None:
    transport = SdkTransport(_sync_echo)
    resp = await transport.send(Request(prompt="hi"))
    assert resp.ok
    assert resp.text == "sync:hi"
    assert resp.error is None


async def test_sdk_async_callable_returns_reply() -> None:
    transport = SdkTransport(_async_echo)
    resp = await transport.send(Request(prompt="hi"))
    assert resp.ok
    assert resp.text == "async:hi"


async def test_sdk_callable_object_with_async_dunder_call() -> None:
    transport = SdkTransport(_CallableAgent())
    resp = await transport.send(Request(prompt="x"))
    assert resp.ok
    assert resp.text == "obj:x"


async def test_sdk_raising_callable_yields_error_response() -> None:
    transport = SdkTransport(_raising)
    resp = await transport.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE
    assert "RuntimeError" in resp.error.message
    assert resp.text == ""


async def test_sdk_non_string_reply_is_coerced() -> None:
    transport = SdkTransport(_non_string)
    resp = await transport.send(Request(prompt="abcd"))
    assert resp.ok
    assert resp.text == "4"


async def test_sdk_sync_callable_returning_awaitable_is_awaited() -> None:
    transport = SdkTransport(_sync_returning_awaitable)
    resp = await transport.send(Request(prompt="z"))
    assert resp.ok
    assert resp.text == "awaited:z"


async def test_sdk_dotted_path_resolution() -> None:
    transport = SdkTransport(f"{__name__}:_sync_echo")
    resp = await transport.send(Request(prompt="dotted"))
    assert resp.ok
    assert resp.text == "sync:dotted"
    assert transport.ref == f"{__name__}:_sync_echo"


async def test_sdk_dotted_path_class_with_default_ctor_is_instantiated() -> None:
    transport = SdkTransport(f"{__name__}:_DefaultCtorAgent")
    resp = await transport.send(Request(prompt="q"))
    assert resp.ok
    assert resp.text == "default-ctor:q"


async def test_sdk_dotted_path_class_needing_args_falls_back_to_classmethod() -> None:
    # The terminal segment is a classmethod on a class whose ctor needs args;
    # mid-walk instantiation fails, so resolution uses the class itself.
    transport = SdkTransport(f"{__name__}:_NeedsArgsAgent.factory")
    resp = await transport.send(Request(prompt="m"))
    assert resp.ok
    assert resp.text == "classmethod:m"


def test_sdk_dotted_path_requires_colon() -> None:
    with pytest.raises(ValueError, match="must contain ':'"):
        SdkTransport("no_colon_here")


def test_sdk_dotted_path_malformed() -> None:
    with pytest.raises(ValueError, match="malformed"):
        SdkTransport("mod:")


def test_sdk_dotted_path_non_callable() -> None:
    with pytest.raises(TypeError, match="non-callable"):
        SdkTransport(f"{__name__}:_A_CONSTANT")


_A_CONSTANT = 42


def test_sdk_direct_non_callable_rejected() -> None:
    with pytest.raises(TypeError, match="not callable"):
        SdkTransport(123)  # type: ignore[arg-type]


def test_sdk_describe() -> None:
    transport = SdkTransport(_sync_echo)
    report = transport.describe()
    assert report.kind == "sdk"
    assert report.supports_tools is False
    assert report.session_modes == ("stateless", "client_history")
    assert report.endpoint == f"{__name__}:_sync_echo"


async def test_sdk_probe_uses_send() -> None:
    transport = SdkTransport(_sync_echo)
    result = await transport.probe()
    assert result.ok
    assert "sync:" in result.detail


# --------------------------------------------------------------------------- #
# SubprocessTransport
# --------------------------------------------------------------------------- #


async def test_subprocess_stdin_echo_with_cat() -> None:
    transport = SubprocessTransport(["cat"], prompt_mode="stdin")
    resp = await transport.send(Request(prompt="echoed text"))
    assert resp.ok
    assert resp.text == "echoed text"


async def test_subprocess_arg_mode_with_echo() -> None:
    transport = SubprocessTransport(["echo"], prompt_mode="arg")
    resp = await transport.send(Request(prompt="hello arg"))
    assert resp.ok
    assert resp.text == "hello arg"


async def test_subprocess_json_mode_parses_field() -> None:
    program = "import sys, json; p = sys.stdin.read(); print(json.dumps({'output': p.upper()}))"
    transport = SubprocessTransport(
        [sys.executable, "-c", program],
        prompt_mode="stdin",
        output_mode="stdout_json",
        output_path="$.output",
    )
    resp = await transport.send(Request(prompt="abc"))
    assert resp.ok
    assert resp.text == "ABC"


async def test_subprocess_json_mode_nested_path() -> None:
    program = "import json; print(json.dumps({'data': {'reply': 'nested-val'}}))"
    transport = SubprocessTransport(
        [sys.executable, "-c", program],
        output_mode="stdout_json",
        output_path="$.data.reply",
    )
    resp = await transport.send(Request(prompt="x"))
    assert resp.ok
    assert resp.text == "nested-val"


async def test_subprocess_json_mode_invalid_json_yields_parse_error() -> None:
    transport = SubprocessTransport(
        [sys.executable, "-c", "print('not json at all')"],
        output_mode="stdout_json",
    )
    resp = await transport.send(Request(prompt="x"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE


async def test_subprocess_json_mode_missing_path_yields_parse_error() -> None:
    transport = SubprocessTransport(
        [sys.executable, "-c", "import json; print(json.dumps({'other': 1}))"],
        output_mode="stdout_json",
        output_path="$.output",
    )
    resp = await transport.send(Request(prompt="x"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE


@pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason=(
        "Python 3.10 asyncio subprocess teardown leaks "
        "BaseSubprocessTransport.__del__ after loop close; fixed in 3.11"
    ),
)
async def test_subprocess_timeout_yields_timeout_error() -> None:
    transport = SubprocessTransport(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_seconds=0.3,
    )
    resp = await transport.send(Request(prompt="x"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.TIMEOUT


async def test_subprocess_nonexistent_command_yields_unreachable() -> None:
    transport = SubprocessTransport(["this-command-does-not-exist-xyz123"])
    resp = await transport.send(Request(prompt="x"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE


async def test_subprocess_nonzero_exit_yields_permanent_error() -> None:
    transport = SubprocessTransport(
        [sys.executable, "-c", "import sys; sys.stderr.write('failed'); sys.exit(3)"],
    )
    resp = await transport.send(Request(prompt="x"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PERMANENT
    assert resp.error.status_code == 3
    assert "failed" in resp.error.message


def test_subprocess_empty_command_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty command"):
        SubprocessTransport([])


def test_subprocess_nonpositive_timeout_rejected() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        SubprocessTransport(["cat"], timeout_seconds=0)


def test_subprocess_describe() -> None:
    transport = SubprocessTransport(["my-agent", "--flag"])
    report = transport.describe()
    assert report.kind == "subprocess"
    assert report.supports_tools is False
    assert report.session_modes == ("stateless", "client_history")
    assert report.endpoint == "my-agent --flag"
