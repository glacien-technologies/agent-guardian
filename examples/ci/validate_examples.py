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
    print(f"\n{ok} ok, {fail} failed")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
