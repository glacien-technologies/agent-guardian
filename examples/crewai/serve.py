"""Minimal HTTP wrapper for the CrewAI demo crew.

Exposes ``POST /chat`` accepting ``{"input": "<prompt>"}`` and returning
``{"output": "<text>"}``. Lets the CrewAI example be scanned via
``--endpoint http://localhost:8000/chat`` as well as the in-process
``--framework crewai`` mode.

Run::

    uv run uvicorn examples.crewai.serve:app --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from examples.crewai.agent import run as run_crew

app = FastAPI(title="agent-guardian CrewAI demo")


class ChatRequest(BaseModel):
    input: str


class ChatResponse(BaseModel):
    output: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
    text = await run_crew(req.input)
    return ChatResponse(output=text)
