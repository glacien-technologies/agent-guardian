"""HTTP wrapper for the Ollama-backed agent.

Run::

    uv run uvicorn examples.ollama_local.serve:app --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from examples.ollama_local.agent import run as run_agent

app = FastAPI(title="agent-guardian Ollama demo")


class ChatRequest(BaseModel):
    input: str


class ChatResponse(BaseModel):
    output: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
    return ChatResponse(output=await run_agent(req.input))
