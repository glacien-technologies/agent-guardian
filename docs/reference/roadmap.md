# Roadmap

What is shipped, what is in flight, and what is planned for
AgentGuardian, with semver windows. The detail-rich rendered version
lives in [`docs/reference/roadmap.mdx`](https://docs.agentguardian.io/reference/roadmap) on the Mintlify
site; this Markdown stub pins the legacy URL
(`docs/reference/roadmap.md`) and is the single source of truth the
GA-narrative guard reads.

Coming soon: this stub is intentionally minimal. The full roadmap with
dated milestones, M-numbers, and per-adapter status is folded into the
Mintlify build.

## v1.0 — Foundation (shipped)

The v1.0 release covers the eleven-agent core swarm plus the four
OWASP-LLM specialists, the full standards-alignment matrix, the signed
evidence pack, and the CLI / API / dashboard surface. `1.0.0` released
on 2026-05-27 as a Production / Stable wheel and a published Docker
image.

Highlights:

* Eleven specialist agents covering every ASI category.
* Four jailbreak strategies — PAIR, TAP, Crescendo, MAD-MAX.
* Six framework adapters dispatched via `--framework KIND`.
* Signed evidence packs (HMAC-SHA256 + Ed25519) and emitters for
  JSON / SARIF / JUnit / Markdown / PDF.
* FastAPI live dashboard at `localhost:7474`.

## v1.1 — Target: 2026 Q3 — semver `1.1.x`

The minor release that closes the post-GA backlog. Each line below
ships either as additive surface or behind an explicit flag; default
behaviour for v1.0 users is preserved unless explicitly called out.

* Additional adapters: LangChain, MCP server, Azure OpenAI, Anthropic
  Claude Agent SDK, PydanticAI, LlamaIndex.
* Demo target trios in `examples/` for CrewAI, AutoGen, Strands, and
  Google ADK.
* Consumer-side OTel exporter binary so customers can drop GenAI
  spans into their existing collector.
* `agentguardian_events_dropped_total` Prometheus counter on the
  `/metrics` endpoint.
* Stricter verification gates (`last-score --require-authoritative`,
  honest HMAC-skip rendering, calibration parity).

## v1.2 and beyond

Earlier exploratory work tracked in [`docs/community/oss-roadmap.md`](../community/oss-roadmap.md) at
the repository root. The hosted dashboard architecture is captured in
[`architecture/hosted-dashboard.md`](../architecture/hosted-dashboard.md);
ship date follows the v1.1 cycle.
