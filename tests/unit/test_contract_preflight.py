"""Unit tests for the contract pre-flight stage logic (Stage 1B).

Drives :func:`run_preflight` against respx-mocked HTTP targets and contract YAML
written into ``tmp_path``. Each test isolates one stage's pass/fail behaviour:
the seven-stage happy path, the prod-without-authorization refusal, an
unreachable target (401/transport fault), the stateful session second turn, the
capability-report dangling-tool config error, and the resolve/lint failures.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from agent_guardian.cli import EXIT_CONFIG, EXIT_TARGET_UNREACHABLE
from agent_guardian.contract.preflight import PreflightReport, run_preflight

URL = "https://api.example.com/v1/chat"


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "agentguardian.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _stage(report: PreflightReport, name: str) -> object:
    for stage in report.stages:
        if stage.name == name:
            return stage
    raise AssertionError(f"stage {name!r} not in report: {[s.name for s in report.stages]}")


_MINIMAL = """
version: 1
target:
  name: demo-stateless
  environment: staging
  transport:
    kind: http
    url: https://api.example.com/v1/chat
  response:
    output_path: $.output.text
  session:
    mode: stateless
roe:
  data_egress:
    allow_external: true
  budgets:
    max_tokens: 1000
"""


# ---------------------------------------------------------------------------
# Happy path -- all seven stages green
# ---------------------------------------------------------------------------


@respx.mock
async def test_preflight_all_stages_green(tmp_path: Path) -> None:
    respx.post(URL).mock(
        return_value=httpx.Response(200, json={"output": {"text": "Hi, I am a demo bot."}})
    )
    path = _write(tmp_path, _MINIMAL)

    report = await run_preflight(path)

    assert report.ok is True
    assert report.exit_code == 0
    assert report.contract_sha256 is not None
    assert report.redacted_contract is not None
    names = [s.name for s in report.stages]
    assert names == [
        "resolve+lint",
        "connect",
        "authenticate/probe",
        "benign-round-trip",
        "session-check",
        "capability-report",
        "roe-echo",
    ]
    # The stateless contract skips the session continuity check with a note.
    assert "skipped" in _stage(report, "session-check").detail  # type: ignore[attr-defined]
    # The benign reply text is echoed in the round-trip stage.
    assert "demo bot" in _stage(report, "benign-round-trip").detail  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# QA #109 issue 2 -- --stage halts execution, not just display
# ---------------------------------------------------------------------------


@respx.mock
async def test_preflight_stop_after_connect_skips_probe(tmp_path: Path) -> None:
    """``stop_after="connect"`` must NOT run the probe stage — the slow,
    retrying network turn — so a connectivity-only check is cheap. We assert
    the target endpoint is never called and the walk halts at connect."""
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "hi"}}))
    path = _write(tmp_path, _MINIMAL)

    report = await run_preflight(path, stop_after="connect")

    names = [s.name for s in report.stages]
    assert names == ["resolve+lint", "connect"]
    assert "authenticate/probe" not in names
    # The decisive proof the probe stage never ran: no egress to the target.
    assert route.call_count == 0
    # Both recorded stages passed → the connectivity check exits clean.
    assert report.ok is True


@respx.mock
async def test_preflight_stop_after_unknown_runs_full_walk(tmp_path: Path) -> None:
    """An unrecognised ``stop_after`` is ignored — the full pre-flight runs."""
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "hi"}}))
    path = _write(tmp_path, _MINIMAL)

    report = await run_preflight(path, stop_after="not-a-stage")

    names = [s.name for s in report.stages]
    assert names[-1] == "roe-echo"
    assert "authenticate/probe" in names


# ---------------------------------------------------------------------------
# Stage 7 -- prod without authorization_ref is refused (EXIT_CONFIG)
# ---------------------------------------------------------------------------


_PROD_AUTHORIZED = """
version: 1
target:
  name: prod-gateway
  environment: prod
  transport:
    kind: http
    url: https://api.example.com/v1/chat
  response:
    output_path: $.output.text
  session:
    mode: stateless
roe:
  authorization_ref: JIRA-1234
  data_egress:
    allow_external: true
"""


@respx.mock
async def test_preflight_prod_with_authorization_passes_roe(tmp_path: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "ok"}}))
    path = _write(tmp_path, _PROD_AUTHORIZED)

    report = await run_preflight(path)

    assert report.ok is True
    roe = _stage(report, "roe-echo")
    assert "JIRA-1234" in roe.detail  # type: ignore[attr-defined]
    assert "environment=prod" in roe.detail  # type: ignore[attr-defined]


# A prod contract missing authorization_ref fails the loader at parse time, so
# the refusal surfaces at stage 1 (resolve+lint) as an EXIT_CONFIG.
_PROD_UNAUTHORIZED = """
version: 1
target:
  name: prod-gateway
  environment: prod
  transport:
    kind: http
    url: https://api.example.com/v1/chat
  response:
    output_path: $.output.text
"""


async def test_preflight_prod_without_authorization_fails(tmp_path: Path) -> None:
    path = _write(tmp_path, _PROD_UNAUTHORIZED)

    report = await run_preflight(path)

    assert report.ok is False
    failure = report.first_failure
    assert failure is not None
    assert failure.name == "resolve+lint"
    assert failure.exit_code == EXIT_CONFIG
    # No transport stage runs once resolve fails.
    assert [s.name for s in report.stages] == ["resolve+lint"]


# ---------------------------------------------------------------------------
# Stage 3 -- unreachable / 401 target
# ---------------------------------------------------------------------------


@respx.mock
async def test_preflight_target_401_is_unreachable(tmp_path: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))
    path = _write(tmp_path, _MINIMAL)

    report = await run_preflight(path)

    assert report.ok is False
    failure = report.first_failure
    assert failure is not None
    assert failure.name == "authenticate/probe"
    assert failure.exit_code == EXIT_TARGET_UNREACHABLE


@respx.mock
async def test_preflight_target_connection_error_is_unreachable(tmp_path: Path) -> None:
    respx.post(URL).mock(side_effect=httpx.ConnectError("refused"))
    path = _write(tmp_path, _MINIMAL)

    report = await run_preflight(path)

    assert report.ok is False
    failure = report.first_failure
    assert failure is not None
    assert failure.name == "authenticate/probe"
    assert failure.exit_code == EXIT_TARGET_UNREACHABLE


# ---------------------------------------------------------------------------
# Stage 5 -- stateful session sends a second turn
# ---------------------------------------------------------------------------


_SERVER_SESSION = """
version: 1
target:
  name: stateful-gateway
  environment: staging
  transport:
    kind: http
    url: https://api.example.com/v1/chat
  response:
    output_path: $.output.text
  session:
    mode: server_session
roe:
  data_egress:
    allow_external: true
"""


@respx.mock
async def test_preflight_session_check_sends_second_turn(tmp_path: Path) -> None:
    route = respx.post(URL).mock(
        return_value=httpx.Response(200, json={"output": {"text": "still here"}})
    )
    path = _write(tmp_path, _SERVER_SESSION)

    report = await run_preflight(path)

    assert report.ok is True
    session_stage = _stage(report, "session-check")
    assert session_stage.ok is True  # type: ignore[attr-defined]
    assert "server_session" in session_stage.detail  # type: ignore[attr-defined]
    # Three benign turns: the stage-3 probe (straight at the transport) plus the
    # two real turns the session-check drives through the session machine to
    # genuinely exercise capture/replay continuity.
    assert route.call_count == 3


# ---------------------------------------------------------------------------
# Stage 6 -- capability report: dangling RoE tool reference
# ---------------------------------------------------------------------------


_DANGLING_TOOL = """
version: 1
target:
  name: tool-gateway
  environment: staging
  transport:
    kind: http
    url: https://api.example.com/v1/chat
  response:
    output_path: $.output.text
  session:
    mode: stateless
  tools:
    discovery: manual
    expected:
      - name: search
roe:
  data_egress:
    allow_external: true
  tools:
    allowlist: [search, nonexistent_tool]
"""


@respx.mock
async def test_preflight_capability_dangling_tool_ref_fails(tmp_path: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "ok"}}))
    path = _write(tmp_path, _DANGLING_TOOL)

    report = await run_preflight(path)

    assert report.ok is False
    failure = report.first_failure
    assert failure is not None
    assert failure.name == "capability-report"
    assert failure.exit_code == EXIT_CONFIG
    assert "nonexistent_tool" in failure.detail


@respx.mock
async def test_preflight_capability_no_discovery_note(tmp_path: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "ok"}}))
    path = _write(tmp_path, _MINIMAL)

    report = await run_preflight(path)

    cap = _stage(report, "capability-report")
    assert cap.ok is True  # type: ignore[attr-defined]
    # The capability stage now reads transport.describe(): an HTTP transport with
    # no tool_call_path reports tools=no and no declared expected tools.
    assert "transport 'http'" in cap.detail  # type: ignore[attr-defined]
    assert "tools=no" in cap.detail  # type: ignore[attr-defined]
    assert "no declared expected tools" in cap.detail  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Stage 4 -- empty reply (bad output_path) is a config error
# ---------------------------------------------------------------------------


@respx.mock
async def test_preflight_missing_output_is_unreachable(tmp_path: Path) -> None:
    # The endpoint returns a body that does NOT contain $.output.text, so the
    # transport raises a format fault -> classified as target-unreachable.
    respx.post(URL).mock(return_value=httpx.Response(200, json={"unexpected": "shape"}))
    path = _write(tmp_path, _MINIMAL)

    report = await run_preflight(path)

    assert report.ok is False
    failure = report.first_failure
    assert failure is not None
    assert failure.name == "authenticate/probe"


# ---------------------------------------------------------------------------
# Stage 1 -- resolve/lint failures
# ---------------------------------------------------------------------------


async def test_preflight_missing_file_fails_resolve(tmp_path: Path) -> None:
    report = await run_preflight(tmp_path / "does-not-exist.yaml")

    assert report.ok is False
    failure = report.first_failure
    assert failure is not None
    assert failure.name == "resolve+lint"
    assert failure.exit_code == EXIT_CONFIG


async def test_preflight_migration_needed_fails_resolve(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "version: 2\n"
        "target:\n"
        "  name: future\n"
        "  environment: staging\n"
        "  transport:\n"
        "    kind: http\n"
        "    url: https://api.example.com/v1/chat\n"
        "  response:\n"
        "    output_path: $.output.text\n",
    )

    report = await run_preflight(path)

    assert report.ok is False
    failure = report.first_failure
    assert failure is not None
    assert failure.name == "resolve+lint"
    assert failure.exit_code == EXIT_CONFIG
    assert failure.remediation is not None
    assert "migrate" in failure.remediation


def test_preflight_report_to_dict_round_trips() -> None:
    report = PreflightReport()
    assert report.ok is True
    assert report.exit_code == 0
    payload = report.to_dict()
    assert payload["ok"] is True
    assert payload["stages"] == []


@pytest.mark.parametrize(
    "message,expected_code",
    [
        ("transport error: blocked: 401 Unauthorized", EXIT_TARGET_UNREACHABLE),
        ("transport error: provider: invalid api key", 4),
    ],
)
def test_classify_send_error(message: str, expected_code: int) -> None:
    from agent_guardian.contract.preflight import _classify_send_error

    code, remediation = _classify_send_error(message)
    assert code == expected_code
    assert remediation


def test_classify_transport_error_uses_category() -> None:
    from agent_guardian.contract.preflight import _classify_transport_error
    from agent_guardian.transports.errors import TransportError, TransportErrorCategory

    # A structured AUTH fault from the target -> target-unreachable.
    code, remediation = _classify_transport_error(
        TransportError(TransportErrorCategory.AUTH, "http: auth failed: 401")
    )
    assert code == EXIT_TARGET_UNREACHABLE
    assert remediation

    # An AUTH fault whose message carries a provider marker -> LLM-provider code.
    code, _ = _classify_transport_error(
        TransportError(TransportErrorCategory.AUTH, "invalid api key")
    )
    assert code == 4

    # A non-auth fault falls back to the message classifier (unreachable).
    code, _ = _classify_transport_error(
        TransportError(TransportErrorCategory.PARSE, "output_path produced no value")
    )
    assert code == EXIT_TARGET_UNREACHABLE


# ---------------------------------------------------------------------------
# Stage 6 -- capability stage reads transport.describe()
# ---------------------------------------------------------------------------


_TOOL_CAPABLE = """
version: 1
target:
  name: tool-aware
  environment: staging
  transport:
    kind: http
    url: https://api.example.com/v1/chat
  response:
    output_path: $.output.text
    tool_call_path: $.tool_calls
  session:
    mode: stateless
  tools:
    discovery: manual
    expected:
      - name: search
roe:
  data_egress:
    allow_external: true
  tools:
    allowlist: [search]
"""


@respx.mock
async def test_preflight_capability_reports_describe(tmp_path: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "ok"}}))
    path = _write(tmp_path, _TOOL_CAPABLE)

    report = await run_preflight(path)

    assert report.ok is True
    cap = _stage(report, "capability-report")
    # describe() surfaces the configured tool_call_path as tools=yes.
    assert "tools=yes" in cap.detail  # type: ignore[attr-defined]
    assert "1 expected tool(s)" in cap.detail  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Stage 5 -- a faulted second session turn fails the session-check
# ---------------------------------------------------------------------------


@respx.mock
async def test_preflight_session_second_turn_fault_fails(tmp_path: Path) -> None:
    # First two POSTs (probe + first session turn) succeed; the third (the real
    # second session turn) returns a 401 -> session-check fails as unreachable.
    responses = [
        httpx.Response(200, json={"output": {"text": "hi"}}),
        httpx.Response(200, json={"output": {"text": "still here"}}),
        httpx.Response(401, json={"error": "unauthorized"}),
    ]
    respx.post(URL).mock(side_effect=responses)
    path = _write(tmp_path, _SERVER_SESSION)

    report = await run_preflight(path)

    assert report.ok is False
    failure = report.first_failure
    assert failure is not None
    assert failure.name == "session-check"
    assert failure.exit_code == EXIT_TARGET_UNREACHABLE


# ---------------------------------------------------------------------------
# Wizard -- scripted interactive path + secret-reference handling
# ---------------------------------------------------------------------------


def test_wizard_yes_writes_minimal_valid_contract(tmp_path: Path) -> None:
    from agent_guardian.contract import load_contract
    from agent_guardian.contract.wizard import WizardDefaults, run_wizard

    out = tmp_path / "wiz.yaml"
    written = run_wizard(out, yes=True, defaults=WizardDefaults(name="wiz-target"))

    assert written == out
    contract = load_contract(out)
    assert contract.target.name == "wiz-target"
    assert contract.target.session.mode == "stateless"


def test_wizard_interactive_scripted_answers(tmp_path: Path) -> None:
    from agent_guardian.contract import load_contract
    from agent_guardian.contract.wizard import ScriptedPrompter, run_wizard

    out = tmp_path / "interactive.yaml"
    prompter = ScriptedPrompter(
        answers=[
            "scripted-bot",  # name
            "https://api.example.com/v1/chat",  # url
            "staging",  # environment
            "bearer",  # auth kind
            "${env:AG_TOKEN}",  # secret reference
            "$.reply",  # output_path
            "stateless",  # session mode
            "",  # authorization ref (optional, staging)
            "5",  # max rps
            "100",  # max requests
            "delete_account, drop_table",  # blocklist
        ]
    )

    run_wizard(out, prompter=prompter)

    contract = load_contract(out)
    assert contract.target.name == "scripted-bot"
    assert contract.target.response.output_path == "$.reply"
    assert contract.target.auth.kind == "bearer"
    assert contract.roe.rate.max_rps == 5.0
    assert contract.roe.budgets.max_requests == 100
    assert contract.roe.tools is not None
    assert contract.roe.tools.blocklist == ["delete_account", "drop_table"]


def test_wizard_interactive_does_not_echo_contract_written(tmp_path: Path) -> None:
    """QA #110 — the 'contract written to …' confirmation is the CLI's job: the
    ``init`` command prints it exactly once for both ``--yes`` and interactive
    runs. The wizard must NOT also echo it, otherwise interactive mode (where
    the prompter's echo routes to stdout) prints the line twice."""
    from agent_guardian.contract.wizard import ScriptedPrompter, run_wizard

    out = tmp_path / "interactive.yaml"
    prompter = ScriptedPrompter(
        answers=[
            "scripted-bot",  # name
            "https://api.example.com/v1/chat",  # url
            "staging",  # environment
            "bearer",  # auth kind
            "${env:AG_TOKEN}",  # secret reference
            "$.reply",  # output_path
            "stateless",  # session mode
            "",  # authorization ref
            "5",  # max rps
            "100",  # max requests
            "delete_account",  # blocklist
        ]
    )

    run_wizard(out, prompter=prompter)

    written_echoes = [e for e in prompter.echoes if "contract written to" in e]
    assert written_echoes == [], (
        f"wizard must not echo the written-path line (the CLI owns it); got {written_echoes}"
    )


def test_wizard_rejects_raw_secret_then_accepts_reference(tmp_path: Path) -> None:
    from agent_guardian.contract import load_contract
    from agent_guardian.contract.wizard import ScriptedPrompter, run_wizard

    out = tmp_path / "secret.yaml"
    prompter = ScriptedPrompter(
        answers=[
            "secret-bot",  # name
            "https://api.example.com/v1/chat",  # url
            "staging",  # environment
            "api_key",  # auth kind
            "sk-RAW-SECRET-1234",  # invalid raw secret -> re-asked
            "${env:AG_KEY}",  # valid reference
            "$.output.text",  # output_path
            "stateless",  # session mode
            "",  # authorization ref
            "",  # max rps
            "",  # max requests
            "",  # blocklist
        ]
    )

    run_wizard(out, prompter=prompter)

    # The written contract carries the *reference*, never the raw secret.
    raw = out.read_text(encoding="utf-8")
    assert "sk-RAW-SECRET" not in raw
    assert "${env:AG_KEY}" in raw
    contract = load_contract(out)
    assert contract.target.auth.kind == "api_key"
    # The re-ask warning was echoed.
    assert any("not a valid secret reference" in line for line in prompter.echoes)


def test_wizard_prod_requires_authorization_ref(tmp_path: Path) -> None:
    from agent_guardian.contract.wizard import WizardDefaults, build_contract_dict

    with pytest.raises(Exception, match="authorization_ref"):
        build_contract_dict(WizardDefaults(name="p", environment="prod"))


# ---------------------------------------------------------------------------
# Stage 6 -- MCP discovery feeds the capability-stage tool reconciliation
# ---------------------------------------------------------------------------


MCP_URL = "https://mcp.example.com/rpc"


def _mcp_rpc_side_effect() -> list[httpx.Response]:
    """initialize + tools/list + tools/call for the benign probe round-trip.

    The MCP transport runs ``initialize`` then ``tools/list`` (discovering
    ``search`` + ``send_email``) then ``tools/call`` against the entry tool; the
    probe's reply text comes from the tools/call ``content``.
    """
    return [
        httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}},
            headers={"Mcp-Session-Id": "sess-1"},
        ),
        httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"tools": [{"name": "search"}, {"name": "send_email"}]},
            },
        ),
        httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "result": {"content": [{"type": "text", "text": "I am the MCP demo."}]},
            },
        ),
    ]


_MCP_DISCOVERY_OK = """
version: 1
target:
  name: mcp-demo
  environment: staging
  transport:
    kind: mcp
    url: https://mcp.example.com/rpc
    entry_tool: search
  response:
    output_path: $.output.text
  session:
    mode: stateless
roe:
  data_egress:
    allow_external: true
  tools:
    allowlist: [search]
    blocklist: [send_email]
"""


@respx.mock
async def test_preflight_mcp_capability_validates_against_discovered_tools(
    tmp_path: Path,
) -> None:
    respx.post(MCP_URL).mock(side_effect=_mcp_rpc_side_effect())
    path = _write(tmp_path, _MCP_DISCOVERY_OK)

    report = await run_preflight(path)

    assert report.ok is True, [s.detail for s in report.stages if not s.ok]
    cap = _stage(report, "capability-report")
    assert cap.ok is True  # type: ignore[attr-defined]
    # describe() reports an MCP transport supporting tools.
    assert "transport 'mcp'" in cap.detail  # type: ignore[attr-defined]
    assert "tools=yes" in cap.detail  # type: ignore[attr-defined]
    # The two tools discovered live via tools/list are surfaced.
    assert "2 discovered tool(s)" in cap.detail  # type: ignore[attr-defined]
    # The RoE allowlist (search) + blocklist (send_email) are both a subset of
    # the discovered set, so reconciliation passes.
    assert "subset" in cap.detail  # type: ignore[attr-defined]


_MCP_DISCOVERY_DANGLING = """
version: 1
target:
  name: mcp-demo
  environment: staging
  transport:
    kind: mcp
    url: https://mcp.example.com/rpc
    entry_tool: search
  response:
    output_path: $.output.text
  session:
    mode: stateless
roe:
  data_egress:
    allow_external: true
  tools:
    blocklist: [tool_that_does_not_exist]
"""


@respx.mock
async def test_preflight_mcp_capability_dangling_against_discovered_fails(
    tmp_path: Path,
) -> None:
    # The RoE blocklist names a tool the server does NOT advertise → because the
    # MCP transport discovered a real tool set, this is now an enforceable
    # dangling reference (EXIT_CONFIG), not a silently-ignored ref.
    respx.post(MCP_URL).mock(side_effect=_mcp_rpc_side_effect())
    path = _write(tmp_path, _MCP_DISCOVERY_DANGLING)

    report = await run_preflight(path)

    assert report.ok is False
    failure = report.first_failure
    assert failure is not None
    assert failure.name == "capability-report"
    assert failure.exit_code == EXIT_CONFIG
    assert "tool_that_does_not_exist" in failure.detail
