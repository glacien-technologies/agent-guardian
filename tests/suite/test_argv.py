"""Suite argv mapping — workload knobs -> real `agent-guardian scan` flags."""

from __future__ import annotations

from agent_guardian.suite.argv import FORCED_HEADLESS_FLAGS, build_scan_argv
from agent_guardian.suite.schema import WorkloadFields


def _argv(**kw: object) -> list[str]:
    return build_scan_argv(WorkloadFields(name="w", **kw))


def _has_pair(argv: list[str], flag: str, value: str) -> bool:
    return any(argv[i] == flag and argv[i + 1] == value for i in range(len(argv) - 1))


def test_starts_with_scan() -> None:
    assert _argv(endpoint="https://a.test")[0] == "scan"


def test_endpoint_option() -> None:
    argv = _argv(endpoint="https://a.test/agent")
    assert _has_pair(argv, "--endpoint", "https://a.test/agent")


def test_target_is_positional_not_a_flag() -> None:
    argv = _argv(target="pkg.mod:run")
    assert "pkg.mod:run" in argv
    assert "--target" not in argv


def test_system_prompt_and_framework_flags() -> None:
    assert _has_pair(_argv(system_prompt="./p.txt"), "--system-prompt", "./p.txt")
    fw = _argv(framework="langgraph", framework_ref="app:graph")
    assert _has_pair(fw, "--framework", "langgraph")
    assert _has_pair(fw, "--framework-ref", "app:graph")


def test_model_role_overrides() -> None:
    argv = _argv(
        endpoint="https://a.test",
        model="gemini:gemini-2.5-flash",
        commander_model="x:c",
        attacker_model="x:a",
        evaluator_model="x:e",
    )
    assert _has_pair(argv, "--model", "gemini:gemini-2.5-flash")
    assert _has_pair(argv, "--commander-model", "x:c")
    assert _has_pair(argv, "--attacker-model", "x:a")
    assert _has_pair(argv, "--evaluator-model", "x:e")


def test_int_and_float_knobs_rendered_as_str() -> None:
    argv = _argv(
        endpoint="https://a.test",
        seed=7,
        max_turns=20,
        budget_usd=0.5,
        fail_under=70,
        max_high=2,
    )
    assert _has_pair(argv, "--seed", "7")
    assert _has_pair(argv, "--max-turns", "20")
    assert _has_pair(argv, "--budget-usd", "0.5")
    assert _has_pair(argv, "--fail-under", "70")
    assert _has_pair(argv, "--max-high", "2")


def test_true_bool_emits_bare_flag() -> None:
    argv = _argv(endpoint="https://a.test", pov_gate=True, pretext=True, log_agent_io=True)
    assert "--pov-gate" in argv
    assert "--pretext" in argv
    assert "--log-agent-io" in argv


def test_false_or_unset_bool_omitted() -> None:
    argv = _argv(endpoint="https://a.test", pov_gate=False)
    assert "--pov-gate" not in argv
    assert "--critic" not in argv  # unset


def test_forced_headless_flags_always_present() -> None:
    argv = _argv(endpoint="https://a.test")
    for flag in ("--no-serve", "--no-tui", "--yes", "--no-publish", "--no-open"):
        assert flag in argv
    assert set(FORCED_HEADLESS_FLAGS) <= set(argv)


def test_child_writes_native_json_report() -> None:
    # Child always renders report.json natively; extra formats are rendered
    # post-scan by the aggregator, so --output json is forced regardless of
    # the workload's requested deliverable formats.
    argv = _argv(endpoint="https://a.test", formats=["sarif", "pdf"])
    assert _has_pair(argv, "--output", "json")


def test_orchestration_only_fields_never_leak_into_argv() -> None:
    argv = _argv(
        endpoint="https://a.test",
        env={"OPENAI_API_KEY": "x"},
        timeout_seconds=120,
        workdir="./t",
        formats=["json"],
    )
    joined = " ".join(argv)
    assert "OPENAI_API_KEY" not in joined
    assert "--timeout-seconds" not in joined
    assert "--workdir" not in joined
    assert "--formats" not in joined
    assert "--name" not in joined
