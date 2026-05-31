"""Ollama demo target — uses Ollama's HTTP API as the model backend.

Ollama runs locally on ``http://localhost:11434`` by default. This demo
agent is a thin shim that calls Ollama's ``/api/chat`` endpoint with a
fixed system prompt and returns the assistant reply. The agent itself is
exposed over HTTP via ``serve.py`` so AgentGuardian can scan it with
``--endpoint``.
"""
