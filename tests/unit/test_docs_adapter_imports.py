"""Guard adapter docs against drifting back to fictional ``scan_*`` helpers.

`docs/adapters/{prompt,code,http,framework}.md` previously documented a
``from agent_guardian import scan_system_prompt`` / ``scan_code`` / ``scan_http``
/ ``scan_framework`` surface that does not exist on the public package. The fix
rewrote those snippets to use the real public surface — ``PromptAdapter``,
``CodeAdapter``, ``HttpAdapter``, the six concrete framework adapter classes,
and ``SwarmCommander`` — and this test parses every Python fenced block under
``docs/adapters/`` and asserts every ``from agent_guardian import X`` symbol is
in ``agent_guardian.__all__``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import agent_guardian

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTERS_DIR = REPO_ROOT / "docs" / "adapters"

_FENCE_RE = re.compile(r"```python\n(.*?)```", re.DOTALL)
_IMPORT_RE = re.compile(
    r"^from\s+agent_guardian\s+import\s+(.+?)$",
    re.MULTILINE,
)

_FICTIONAL_HELPERS = {
    "scan_system_prompt",
    "scan_code",
    "scan_http",
    "scan_framework",
}


def _iter_python_blocks() -> list[tuple[Path, str]]:
    blocks: list[tuple[Path, str]] = []
    for doc in sorted(ADAPTERS_DIR.glob("*.md")):
        body = doc.read_text(encoding="utf-8")
        for match in _FENCE_RE.finditer(body):
            blocks.append((doc, match.group(1)))
    return blocks


def _parse_imports(block: str) -> list[str]:
    """Pull out symbols from `from agent_guardian import ...` lines.

    Handles single-line and parenthesised multi-line imports.
    """
    symbols: list[str] = []
    # Collapse parenthesised imports onto one logical line.
    flattened = re.sub(r"\(\s*([^)]*?)\s*\)", lambda m: m.group(1).replace("\n", " "), block)
    for match in _IMPORT_RE.finditer(flattened):
        raw = match.group(1)
        # Strip trailing comments.
        raw = raw.split("#", 1)[0]
        for token in raw.split(","):
            sym = token.strip()
            if sym:
                symbols.append(sym)
    return symbols


def test_adapter_docs_have_python_examples() -> None:
    blocks = _iter_python_blocks()
    assert blocks, "no python code blocks found under docs/adapters/ — expected at least one"


@pytest.mark.parametrize(
    "doc_path,block",
    [(doc, block) for doc, block in _iter_python_blocks()],
    ids=lambda v: v.name if isinstance(v, Path) else "block",
)
def test_no_fictional_scan_helpers(doc_path: Path, block: str) -> None:
    """The fictional ``scan_system_prompt`` / ``scan_code`` / ``scan_http`` /
    ``scan_framework`` symbols must never appear in adapter docs again."""

    symbols = set(_parse_imports(block))
    leaked = symbols & _FICTIONAL_HELPERS
    assert not leaked, (
        f"{doc_path.relative_to(REPO_ROOT)} imports fictional symbol(s) {sorted(leaked)} from "
        f"agent_guardian — these helpers do not exist."
    )


@pytest.mark.parametrize(
    "doc_path,block",
    [(doc, block) for doc, block in _iter_python_blocks()],
    ids=lambda v: v.name if isinstance(v, Path) else "block",
)
def test_every_imported_symbol_is_real(doc_path: Path, block: str) -> None:
    """Every ``from agent_guardian import X`` symbol must be in ``__all__``."""

    public = set(agent_guardian.__all__)
    for symbol in _parse_imports(block):
        assert symbol in public, (
            f"{doc_path.relative_to(REPO_ROOT)} imports {symbol!r} from agent_guardian, but it is "
            f"not in agent_guardian.__all__"
        )
