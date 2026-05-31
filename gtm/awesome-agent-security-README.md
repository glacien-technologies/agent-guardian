# Awesome Agent Security [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> A curated list of tools, papers, benchmarks, and resources for securing AI agents, RAG systems, MCP servers, and tool-using LLM applications.

Maintained by [Glacien Technologies](https://glacien.ai). Contributions welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md).

This list is intentionally narrow: it covers the security of *agentic* AI systems — systems where an LLM autonomously chooses tools, accesses external data, or executes actions. Generic prompt-engineering and generic ML-safety resources belong elsewhere.

## Contents

- [Agent Security Tools](#agent-security-tools)
- [Prompt Injection & LLM Security](#prompt-injection--llm-security)
- [RAG / Knowledge Base Security](#rag--knowledge-base-security)
- [MCP (Model Context Protocol) Security](#mcp-model-context-protocol-security)
- [AI Red Teaming Research, Benchmarks, and Datasets](#ai-red-teaming-research-benchmarks-and-datasets)
- [Contributing](#contributing)
- [License](#license)

---

## Agent Security Tools

Open-source tools that scan, fuzz, or harden agentic AI systems.

- [AgentGuardian](https://github.com/glacien-technologies/agent-guardian) — Adversarial swarm of eleven specialist agents that red-team AI agents, RAG, and MCP servers; outputs AIVSS score and SARIF/HTML evidence.
- [Garak](https://github.com/NVIDIA/garak) — NVIDIA's LLM vulnerability scanner covering prompt injection, data leakage, toxicity, and jailbreaks.
- [Guardrails AI](https://github.com/guardrails-ai/guardrails) — Validation framework that wraps LLM outputs with policy checks and structured-output guards.
- [LLM Guard](https://github.com/protectai/llm-guard) — Protect AI's input/output sanitization toolkit for LLM applications.
- [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) — NVIDIA's programmable rails for steering LLM conversations away from unsafe topics or tool calls.
- [Promptfoo](https://github.com/promptfoo/promptfoo) — Evaluation and red-teaming harness for prompts, agents, and RAG pipelines.
- [PyRIT](https://github.com/Azure/PyRIT) — Microsoft's Python Risk Identification Toolkit for generative AI red teaming.
- [Rebuff](https://github.com/protectai/rebuff) — Self-hardening prompt-injection detector with canary tokens.

## Prompt Injection & LLM Security

Foundational references on prompt injection, jailbreaks, and LLM application security.

- [Lakera PINT Benchmark](https://github.com/lakeraai/pint-benchmark) — Prompt Injection Test benchmark with public test set.
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) — OWASP's threat catalog for LLM apps, including LLM01 prompt injection.
- [OWASP Agentic AI Security Initiative (ASI)](https://genai.owasp.org/initiatives/#agentic-ai-security-initiative) — Threat taxonomy for agent systems.
- [Prompt Injection Primer for Engineers](https://github.com/jthack/PIPE) — Concise primer on prompt-injection attack classes and mitigations.
- [Simon Willison — Prompt Injection Archive](https://simonwillison.net/tags/prompt-injection/) — Long-running write-ups of real-world prompt-injection incidents.

## RAG / Knowledge Base Security

Attacks and defenses against retrieval-augmented generation pipelines.

- [PoisonedRAG](https://github.com/sleeepeer/PoisonedRAG) — Reference implementation of corpus-poisoning attacks against RAG systems.
- [RAG Security Best Practices (Pillar Security)](https://www.pillar.security/blog/rag-security-the-complete-guide) — Practitioner guide covering retrieval poisoning, indirect injection, and access control.
- [Vectara Hallucination Leaderboard](https://github.com/vectara/hallucination-leaderboard) — Benchmark for factuality in RAG outputs.

## MCP (Model Context Protocol) Security

Resources specific to securing MCP servers and clients.

- [MCP Official Specification](https://github.com/modelcontextprotocol/specification) — Reference specification; the security-considerations section is required reading.
- [MCP Security Best Practices (Anthropic)](https://modelcontextprotocol.io/docs/concepts/security) — Official guidance on authentication, tool scoping, and untrusted-content handling.
- [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) — Static analyzer for MCP server tool descriptions, detects shadow / rug-pull / injection patterns.

## AI Red Teaming Research, Benchmarks, and Datasets

Academic and applied research artifacts useful for building or evaluating defenses.

- [AdvBench](https://github.com/llm-attacks/llm-attacks) — Adversarial harmful-behavior benchmark; the canonical jailbreak test set from Zou et al.
- [AgentBench](https://github.com/THUDM/AgentBench) — Multi-environment benchmark for evaluating LLM agents on real tasks.
- [AgentDojo](https://github.com/ethz-spylab/agentdojo) — Dynamic evaluation environment for prompt-injection attacks against agentic systems.
- [AISI Inspect](https://github.com/UKGovernmentBEIS/inspect_ai) — UK AI Safety Institute's evaluation framework for LLM dangerous-capabilities testing.
- [HarmBench](https://github.com/centerforaisafety/HarmBench) — Standardized red-teaming evaluation across attack methods and defenses.
- [JailbreakBench](https://github.com/JailbreakBench/jailbreakbench) — Open benchmark for jailbreak attacks with leaderboard.
- [MITRE ATLAS](https://atlas.mitre.org/) — Threat taxonomy for adversarial ML, mirrors ATT&CK structure.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) — Government-issued risk-management taxonomy for AI systems.
- [Purple Llama CyberSecEval](https://github.com/meta-llama/PurpleLlama) — Meta's cybersecurity evaluation suite for LLMs.
- [SafeBench](https://github.com/SafeBench/SafeBench) — Safety evaluation benchmark across attack vectors.
- [TrustLLM](https://github.com/HowieHwong/TrustLLM) — Comprehensive trustworthiness study and benchmark for LLMs.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Submissions must be open-source or freely accessible, active in the last 12 months, and have a clear README or abstract. AgentGuardian-specific submissions are not given priority — this list is curated for usefulness, not promotion.

## License

[MIT](./LICENSE) © Glacien Pte. Ltd. and contributors.
