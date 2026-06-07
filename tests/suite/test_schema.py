"""Suite YAML schema — strict validation of the multi-workload config."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_guardian.suite.schema import SuiteConfig, SuiteFile, WorkloadFields


def _minimal_doc() -> dict:
    return {
        "version": 1,
        "suite": {"name": "demo"},
        "workloads": [
            {"name": "a", "endpoint": "https://a.test/agent"},
            {"name": "b", "target": "pkg.mod:run"},
        ],
    }


def test_minimal_doc_parses() -> None:
    sf = SuiteFile.model_validate(_minimal_doc())
    assert sf.suite.name == "demo"
    assert sf.suite.isolate_home is True  # isolation is the default
    assert sf.suite.register_scans is True  # dashboard discoverability default
    assert sf.suite.serve is False
    assert sf.suite.formats == ["json"]
    assert [w.name for w in sf.workloads] == ["a", "b"]


def test_unknown_key_is_rejected() -> None:
    doc = _minimal_doc()
    doc["suite"]["nonsense"] = True
    with pytest.raises(ValidationError):
        SuiteFile.model_validate(doc)


def test_unknown_workload_key_is_rejected() -> None:
    doc = _minimal_doc()
    doc["workloads"][0]["typo_flag"] = 1
    with pytest.raises(ValidationError):
        SuiteFile.model_validate(doc)


def test_bad_format_rejected() -> None:
    doc = _minimal_doc()
    doc["suite"]["formats"] = ["json", "docx"]
    with pytest.raises(ValidationError):
        SuiteFile.model_validate(doc)


def test_duplicate_workload_names_rejected() -> None:
    doc = _minimal_doc()
    doc["workloads"][1]["name"] = "a"
    with pytest.raises(ValidationError):
        SuiteFile.model_validate(doc)


def test_empty_workloads_rejected() -> None:
    doc = _minimal_doc()
    doc["workloads"] = []
    with pytest.raises(ValidationError):
        SuiteFile.model_validate(doc)


def test_exit_code_enum_enforced() -> None:
    doc = _minimal_doc()
    doc["suite"]["exit_code"] = "whatever"
    with pytest.raises(ValidationError):
        SuiteFile.model_validate(doc)


def test_workload_fields_all_optional_for_defaults() -> None:
    # ``defaults`` is a WorkloadFields with nothing required.
    wf = WorkloadFields()
    assert wf.name is None
    assert wf.endpoint is None


def test_suite_config_defaults() -> None:
    sc = SuiteConfig(name="x")
    assert sc.out_dir == "./suite-out"
    assert sc.fail_fast is False
    assert sc.exit_code == "any-gate-fail"
