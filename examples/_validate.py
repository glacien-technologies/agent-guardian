"""Smoke-test every example target by running a benign prompt through it.

We use a single benign prompt across all six targets so the prompt is
meaningful in every context and any *refusal* of a benign question is
a real bug, not a "this attack succeeded" signal. The real scan
happens via ``agent-guardian scan`` in a later milestone.

Run via::

    uv run python examples/_validate.py

Expected cost: ~6 Gemini calls of ~100 tokens each = a fraction of a
US cent.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import traceback
from pathlib import Path

# Make ``examples.*`` importable when this file is invoked directly via
# ``uv run python examples/_validate.py`` (no ``-m`` flag, no editable
# install of the ``examples`` package — which doesn't exist on purpose).
#
# When Python runs a script directly it prepends the script's own
# directory (here: ``examples/``) to ``sys.path[0]``. That shadows the
# real ``langgraph`` PyPI package with our ``examples/langgraph/``
# sub-package (the latter looks like an implicit namespace package).
# We strip the script directory first, then prepend the project root.
_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
sys.path = [p for p in sys.path if Path(p).resolve() != _HERE]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

EXAMPLES: list[tuple[str, str]] = [
    ("langgraph", "simple_chatbot"),
    ("langgraph", "support_with_tool"),
    ("langgraph", "personal_assistant_pii"),
    ("openai_agents", "simple_chatbot"),
    ("openai_agents", "support_with_tool"),
    ("openai_agents", "personal_assistant_pii"),
]

BENIGN_PROMPT = "What are your opening hours?"


async def main() -> int:
    ok = 0
    fail = 0
    for framework, name in EXAMPLES:
        mod_name = f"examples.{framework}.{name}"
        try:
            mod = importlib.import_module(mod_name)
            text = await mod.run(BENIGN_PROMPT)
            if not isinstance(text, str) or not text.strip():
                raise ValueError(f"empty / non-string response: {text!r}")
            preview = text[:120].replace("\n", " ")
            print(f"  ok   {framework:14s} / {name:30s} -> {preview!r}")
            ok += 1
        except Exception as exc:  # smoke test wants to keep going on any failure.
            print(f"  FAIL {framework:14s} / {name:30s} -> {type(exc).__name__}: {exc}")
            traceback.print_exc()
            fail += 1
    print(f"\n{ok} ok, {fail} failed")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
