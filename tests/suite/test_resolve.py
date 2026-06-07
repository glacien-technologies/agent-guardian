"""Suite resolve — merge suite defaults into each workload + target validation."""

from __future__ import annotations

import pytest

from agent_guardian.suite.errors import SuiteConfigError
from agent_guardian.suite.resolve import resolve_workloads
from agent_guardian.suite.schema import SuiteFile


def _suite(defaults: dict | None = None, workloads: list[dict] | None = None) -> SuiteFile:
    return SuiteFile.model_validate(
        {
            "version": 1,
            "suite": {"name": "demo", "formats": ["json", "pdf"]},
            "defaults": defaults or {},
            "workloads": workloads or [{"name": "a", "endpoint": "https://a.test/agent"}],
        }
    )


def test_defaults_fill_unset_fields() -> None:
    sf = _suite(
        defaults={"model": "gemini:gemini-2.5-flash", "mode": "full"},
        workloads=[{"name": "a", "endpoint": "https://a.test/agent"}],
    )
    [r] = resolve_workloads(sf)
    assert r.model == "gemini:gemini-2.5-flash"
    assert r.mode == "full"


def test_workload_overrides_default() -> None:
    sf = _suite(
        defaults={"mode": "full"},
        workloads=[{"name": "a", "endpoint": "https://a.test/agent", "mode": "fast"}],
    )
    [r] = resolve_workloads(sf)
    assert r.mode == "fast"


def test_workload_false_overrides_default_true() -> None:
    sf = _suite(
        defaults={"no_owasp_llm": True},
        workloads=[{"name": "a", "endpoint": "https://a.test/agent", "no_owasp_llm": False}],
    )
    [r] = resolve_workloads(sf)
    assert r.no_owasp_llm is False


def test_formats_fall_back_to_suite_default() -> None:
    sf = _suite(workloads=[{"name": "a", "endpoint": "https://a.test/agent"}])
    [r] = resolve_workloads(sf)
    assert r.formats == ["json", "pdf"]  # from suite.formats


def test_workload_formats_win() -> None:
    sf = _suite(workloads=[{"name": "a", "endpoint": "https://a.test/agent", "formats": ["sarif"]}])
    [r] = resolve_workloads(sf)
    assert r.formats == ["sarif"]


def test_exactly_one_target_required_none() -> None:
    sf = _suite(workloads=[{"name": "a", "mode": "fast"}])
    with pytest.raises(SuiteConfigError, match="exactly one target"):
        resolve_workloads(sf)


def test_exactly_one_target_required_two() -> None:
    sf = _suite(workloads=[{"name": "a", "endpoint": "https://a.test/agent", "target": "pkg:run"}])
    with pytest.raises(SuiteConfigError, match="exactly one target"):
        resolve_workloads(sf)


def test_framework_ref_is_not_a_standalone_target() -> None:
    # framework_ref alone (no framework) is not a valid mode.
    sf = _suite(workloads=[{"name": "a", "framework_ref": "app:graph"}])
    with pytest.raises(SuiteConfigError):
        resolve_workloads(sf)


def test_defaults_can_supply_target_mode() -> None:
    # A shared endpoint base in defaults is allowed (unusual but valid).
    sf = _suite(
        defaults={"endpoint": "https://shared.test/agent"},
        workloads=[{"name": "a"}],
    )
    [r] = resolve_workloads(sf)
    assert r.endpoint == "https://shared.test/agent"
