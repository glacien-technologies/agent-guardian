"""Shared LLM helper used by example target agents.

Loads ``GEMINI_API_KEY`` from the project's ``.env`` (CWD or any parent
directory). Provides :func:`make_llm` for the LangGraph trio and
:func:`make_openai_client_for_gemini` for the OpenAI Agents trio so the
same key, the same model id, and the same provider routing apply across
all six demo targets.

The default model is ``gemini-3.1-pro-preview`` — override with the
``AG_DEMO_MODEL`` environment variable if you need to point the demos at
a different Gemini SKU.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# Auto-load ``.env`` from the cwd or any parent directory. Mirrors what
# ``agent_guardian.cli._try_load_dotenv`` does so the demos behave
# consistently whether you invoke them via ``uv run`` from the repo root
# or from a deeper sub-directory.
try:  # pragma: no cover - dev-only convenience
    from dotenv import load_dotenv

    for parent in (Path.cwd(), *Path.cwd().parents):
        candidate = parent / ".env"
        if candidate.exists():
            load_dotenv(candidate)
            break
except ImportError:
    pass

MODEL_ID = os.environ.get("AG_DEMO_MODEL", "gemini-3.1-pro-preview")

# Google's OpenAI-compatible Gemini endpoint. Documented at
# https://ai.google.dev/gemini-api/docs/openai — accepts Gemini model
# IDs (e.g. ``gemini-3.1-pro-preview``) directly.
GEMINI_OPENAI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"


def _require_key() -> str:
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        raise RuntimeError(
            "Neither GEMINI_API_KEY nor GOOGLE_API_KEY is set. "
            "Add it to .env at the project root or export it in your shell."
        )
    return key


def make_llm(temperature: float = 0.3) -> Any:
    """Construct the shared ``ChatGoogleGenerativeAI`` client.

    Used by the LangGraph trio. Returns ``Any`` because we don't want
    ``langchain_google_genai`` to be a typed dependency of the module
    signature (callers only need an LCEL-compatible chat model).
    """
    from langchain_google_genai import ChatGoogleGenerativeAI

    return ChatGoogleGenerativeAI(
        model=MODEL_ID,
        temperature=temperature,
        google_api_key=_require_key(),
    )


def coerce_to_text(content: Any) -> str:
    """Flatten a LangChain message ``.content`` payload to plain text.

    Gemini 3.x's LangChain bindings return message content as a list of
    typed blocks (``[{'type': 'text', 'text': '...', 'extras': {...}}]``)
    rather than a flat string. This helper unwraps that structure for
    the demo targets so their ``run()`` contract stays ``-> str``.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                txt = block.get("text")
                if isinstance(txt, str):
                    parts.append(txt)
            else:
                txt = getattr(block, "text", None)
                if isinstance(txt, str):
                    parts.append(txt)
        if parts:
            return "".join(parts)
    return str(content)


def make_openai_client_for_gemini() -> Any:
    """Return an :class:`openai.AsyncOpenAI` pointed at Gemini's OAI shim.

    Used by the OpenAI Agents trio so a single Gemini API key covers
    both adapter flavours. The Agents SDK accepts an ``AsyncOpenAI``
    instance via :class:`agents.OpenAIChatCompletionsModel`.
    """
    from openai import AsyncOpenAI

    return AsyncOpenAI(
        api_key=_require_key(),
        base_url=GEMINI_OPENAI_BASE_URL,
    )
