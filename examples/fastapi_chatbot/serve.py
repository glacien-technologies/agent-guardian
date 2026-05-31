"""FastAPI wrapper for the chatbot demo.

Run::

    uv run uvicorn examples.fastapi_chatbot.serve:app --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from examples.fastapi_chatbot.agent import respond

app = FastAPI(title="agent-guardian FastAPI chatbot demo")


class ChatRequest(BaseModel):
    input: str


class ChatResponse(BaseModel):
    output: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    return ChatResponse(output=respond(req.input))
