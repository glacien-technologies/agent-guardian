# MCP-server demo target

A minimal FastAPI-hosted JSON-RPC server that implements the three RPCs
AgentGuardian's `McpTransport` exercises (`initialize`, `tools/list`,
`tools/call`). Used as a stable fixture for scanning an MCP target via a
target contract.

## What it tests

* All 10 ASI categories against an MCP server, with `ASI04` (supply
  chain) probes specifically routed for MCP transports.
* The `roe.tools.allowlist` / `roe.tools.blocklist` enforcement path:
  `delete_everything` is exposed by the server but blocked by the RoE,
  so the swarm never actually invokes it.
* Session-id replay (the demo is stateless, so the transport's
  `stateless` session mode is the relevant code path).

## Install + run the server

```bash
uv sync --extra examples
uv run uvicorn examples.mcp_server.serve:app --port 8765
```

## Scan it

```bash
agent-guardian scan \
  --contract examples/mcp_server/agentguardian.yaml \
  --model stub \
  --mode fast \
  --output md \
  --output-path scan.md
```

## Docs

See `docs/try/scan-mcp-server.mdx` for the full walkthrough.
