"""MCP-server demo target — a tiny FastAPI-hosted MCP-style server.

The Model Context Protocol uses JSON-RPC 2.0 over Streamable HTTP. This
demo ships a minimal server that responds to ``initialize``, ``tools/list``
and ``tools/call`` so AgentGuardian's MCP transport can drive it end-to-end
via a target contract.

The server is intentionally simple — it implements only the surface the
``McpTransport`` exercises. It is **not** a reference MCP implementation.
"""
