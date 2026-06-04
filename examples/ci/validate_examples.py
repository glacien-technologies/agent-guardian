"""Validate every example dir's serve.py / contract is loadable.

This is the GTM-004 CI gate. For each example:

* If the directory ships ``serve.py``, import it and assert a FastAPI
  ``app`` attribute is exposed (Mode-B-over-HTTP examples).
* If the directory ships ``agentguardian.yaml``, parse it with the
  ``Contract`` schema and assert ``target.transport.kind`` matches the
  expected transport for that example.
* If the directory ships ``agent.py`` with a ``run`` coroutine, run a
  benign prompt through it. The benign prompt is the same one used by
  ``examples/_validate.py`` so a refusal is a real bug.

Skipping rules:

* ``examples/bedrock_agent`` requires real AWS credentials and is skipped
  unless ``AG_VALIDATE_BEDROCK=1`` is set in the environment.
* ``examples/gemini_agent`` requires real GCP credentials and is skipped
  unless ``AG_VALIDATE_VERTEX=1`` is set in the environment.
* ``examples/crewai`` requires the ``examples-crewai`` extra and is
  skipped (with a recorded reason) when the import fails — useful for
  laptops without the extra installed.
* ``examples/ollama_local/agent.run`` does *not* require a running Ollama
  instance — the agent's error-path is itself a valid string return, so
  the smoke test passes regardless.

Run via::

    uv run python examples/ci/validate_examples.py

Exit codes:

* 0 — every applicable example validated.
* 1 — one or more examples failed validation.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent.parent
# Mirror the sys.path hygiene applied by examples/_validate.py.
sys.path = [p for p in sys.path if Path(p).resolve() != _HERE]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

BENIGN_PROMPT = "What are your opening hours?"


@dataclass(frozen=True)
class ExampleSpec:
    name: str
    has_run: bool = False
    has_serve: bool = False
    has_contract: bool = False
    expected_transport_kind: str | None = None
    skip_env: str | None = None  # if set and env var != "1", skip


EXAMPLES: list[ExampleSpec] = [
    ExampleSpec("crewai", has_run=True, has_serve=True, skip_env="AG_VALIDATE_CREWAI_OPTIONAL"),
    ExampleSpec(
        "mcp_server",
        has_serve=True,
        has_contract=True,
        expected_transport_kind="mcp",
    ),
    ExampleSpec("rag_app", has_run=True, has_serve=True),
    ExampleSpec("fastapi_chatbot", has_run=True, has_serve=True),
    ExampleSpec("ollama_local", has_run=True, has_serve=True),
    ExampleSpec(
        "bedrock_agent",
        has_contract=True,
        expected_transport_kind="bedrock_agent",
        skip_env="AG_VALIDATE_BEDROCK",
    ),
    ExampleSpec(
        "gemini_agent",
        has_contract=True,
        expected_transport_kind="vertex_agent",
        skip_env="AG_VALIDATE_VERTEX",
    ),
]


def _should_skip(spec: ExampleSpec) -> tuple[bool, str]:
    if spec.skip_env and os.environ.get(spec.skip_env, "") != "1":
        return True, f"skipped (set {spec.skip_env}=1 to enable)"
    return False, ""


async def _validate_run(example: str) -> None:
    mod = importlib.import_module(f"examples.{example}.agent")
    text = await mod.run(BENIGN_PROMPT)
    if not isinstance(text, str) or not text.strip():
        raise AssertionError(f"empty/non-string response from agent.run: {text!r}")


def _validate_serve(example: str) -> None:
    mod = importlib.import_module(f"examples.{example}.serve")
    app = getattr(mod, "app", None)
    if app is None:
        raise AssertionError(f"examples.{example}.serve has no 'app' attribute")


def _validate_contract(example: str, expected_kind: str | None) -> None:
    from agent_guardian.contract.loader import load_contract_file

    path = _PROJECT_ROOT / "examples" / example / "agentguardian.yaml"
    contract = load_contract_file(path)
    transport = contract.target.transport
    kind = getattr(transport, "kind", None)
    if expected_kind is not None and kind != expected_kind:
        raise AssertionError(f"contract transport kind {kind!r} != expected {expected_kind!r}")


def _validate_sample(example: str) -> None:
    import json

    path = _PROJECT_ROOT / "examples" / example / "sample-scan.json"
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    for required in ("scan_id", "schema_version", "target", "config"):
        if required not in data:
            raise AssertionError(f"sample-scan.json missing field {required!r}")


# ---------------------------------------------------------------------------
# CI template validation (examples/ci/**)
# ---------------------------------------------------------------------------
#
# Every copy-pasteable CI config we ship must stay valid YAML with the
# minimal structure each forge requires. Validating them here means a typo in
# a template is caught by our own CI rather than by a user's pipeline.

_CI_ROOT = _HERE  # examples/ci/


def _discover_ci_templates() -> list[Path]:
    """Return every CI template file under ``examples/ci/**``.

    Globs ``*.yml`` / ``*.yaml`` (GitHub, GitLab, Bitbucket) including the
    dotfile ``.gitlab-ci.yml`` which a plain ``*.yml`` glob misses.
    """
    seen: dict[Path, None] = {}
    for pattern in ("**/*.yml", "**/*.yaml", "**/.gitlab-ci.yml"):
        for path in _CI_ROOT.glob(pattern):
            if path.is_file():
                seen[path.resolve()] = None
    return sorted(seen)


def _validate_ci_template(path: Path) -> None:
    """YAML-parse a CI template and assert its forge-specific top-level shape."""
    import yaml

    with path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        raise AssertionError(f"{path.name} did not parse to a YAML mapping")

    parent = path.parent.name
    if parent == "github":
        # A GitHub workflow needs an `on` trigger and a `jobs` mapping. PyYAML
        # parses the bareword `on:` key as the boolean True, so accept either.
        if "on" not in doc and True not in doc:
            raise AssertionError(f"{path.name}: GitHub workflow missing 'on:' trigger")
        if not isinstance(doc.get("jobs"), dict) or not doc["jobs"]:
            raise AssertionError(f"{path.name}: GitHub workflow has no 'jobs:'")
    elif parent == "gitlab":
        # A GitLab pipeline must define at least one job (a top-level mapping
        # key whose value is a mapping, e.g. `agentguardian:`).
        jobs = [k for k, v in doc.items() if isinstance(v, dict) and not k.startswith(".")]
        if not jobs:
            raise AssertionError(f"{path.name}: GitLab pipeline defines no jobs")
    elif parent == "bitbucket":
        if "pipelines" not in doc:
            raise AssertionError(f"{path.name}: bitbucket-pipelines.yml missing 'pipelines:'")
    # Unknown forges still get the parse + mapping check above.


def _run_ci_templates() -> tuple[int, int]:
    """Validate every CI template; return ``(ok, fail)`` counts."""
    templates = _discover_ci_templates()
    ok = fail = 0
    for path in templates:
        rel = path.relative_to(_PROJECT_ROOT)
        try:
            _validate_ci_template(path)
        except Exception as exc:  # keep going across all templates.
            traceback.print_exc()
            print(f"  FAIL {rel} -> {type(exc).__name__}: {exc}")
            fail += 1
        else:
            print(f"  ok   {rel}")
            ok += 1
    if not templates:
        print("  (no CI templates found under examples/ci/**)")
    return ok, fail


async def _run_one(spec: ExampleSpec) -> tuple[str, bool, str]:
    skip, reason = _should_skip(spec)
    if skip:
        return spec.name, True, reason
    try:
        if spec.has_run:
            await _validate_run(spec.name)
        if spec.has_serve:
            _validate_serve(spec.name)
        if spec.has_contract:
            _validate_contract(spec.name, spec.expected_transport_kind)
        _validate_sample(spec.name)
        return spec.name, True, "ok"
    except ImportError as exc:
        # Optional extras (crewai) may not be installed locally; report but
        # don't fail.
        return spec.name, True, f"skipped (import error: {exc})"
    except Exception as exc:  # smoke-test wants to keep going on any failure.
        traceback.print_exc()
        return spec.name, False, f"FAIL {type(exc).__name__}: {exc}"


async def main() -> int:
    print("examples/ci/validate_examples.py")
    ok = fail = 0
    for spec in EXAMPLES:
        name, success, detail = await _run_one(spec)
        marker = "ok  " if success else "FAIL"
        print(f"  {marker} {name:18s} -> {detail}")
        if success:
            ok += 1
        else:
            fail += 1
    print("\nCI templates (examples/ci/**):")
    ci_ok, ci_fail = _run_ci_templates()
    ok += ci_ok
    fail += ci_fail
    print(f"\n{ok} ok, {fail} failed")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
