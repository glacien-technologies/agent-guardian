"""HTTP wrapper for the RAG demo.

Exposes ``POST /chat`` accepting ``{"input": "<prompt>"}`` and returning
``{"output": "<text>", "retrieved": [...]}``. The ``retrieved`` field
lets you eyeball indirect-injection probes after a scan.

Run::

    uv run uvicorn examples.rag_app.serve:app --port 8000
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from examples.rag_app.agent import chat as rag_chat

app = FastAPI(title="agent-guardian RAG demo")


class ChatRequest(BaseModel):
    input: str


class ChatResponse(BaseModel):
    output: str
    retrieved: list[str]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> dict[str, Any]:
    return rag_chat(req.model_dump())
