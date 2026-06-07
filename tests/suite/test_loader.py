"""Suite loader — YAML parse + ${ENV} expansion + friendly errors."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardian.suite.errors import SuiteConfigError
from agent_guardian.suite.loader import load_suite_file

_DOC = """
version: 1
suite:
  name: demo
defaults:
  model: gemini:gemini-2.5-flash
workloads:
  - name: a
    endpoint: ${AG_TEST_ENDPOINT}
    env:
      OPENAI_API_KEY: ${AG_TEST_KEY}
"""


def test_loads_and_expands_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AG_TEST_ENDPOINT", "https://expanded.test/agent")
    monkeypatch.setenv("AG_TEST_KEY", "sk-123")
    p = tmp_path / "suite.yaml"
    p.write_text(_DOC, encoding="utf-8")

    sf = load_suite_file(p)

    assert sf.workloads[0].endpoint == "https://expanded.test/agent"
    assert sf.workloads[0].env == {"OPENAI_API_KEY": "sk-123"}


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(SuiteConfigError):
        load_suite_file(tmp_path / "nope.yaml")


def test_invalid_schema_raises_friendly(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("version: 1\nsuite:\n  name: x\nworkloads: []\n", encoding="utf-8")
    with pytest.raises(SuiteConfigError):
        load_suite_file(p)


def test_non_mapping_doc_raises(tmp_path: Path) -> None:
    p = tmp_path / "list.yaml"
    p.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(SuiteConfigError):
        load_suite_file(p)
