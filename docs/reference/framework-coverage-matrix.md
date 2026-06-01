# Framework-coverage matrix

> **Honest framing.** This page replaces the older README claim of "MITRE ATLAS v5.4.0 mappings" (which read as full-catalogue coverage). What AgentGuardian actually ships, today, against the corpus on disk: **11+ MITRE ATLAS techniques covered** (see the matrix below for the exact set - currently 26 techniques). The remaining ~85% of the v5.4.0 catalogue is out of scope for a black-box agent scanner - training-pipeline compromise, ML-platform-internal techniques, and infrastructure-layer attacks do not surface at the agent's I/O boundary and are therefore not probed.

All three tables below are auto-generated from 103 probe YAMLs by `scripts/build_coverage_matrix.py`. Re-run that script after adding or removing probes - the doc is the loader's view of the world, not a hand-maintained narrative.

## OWASP Top 10 for Agentic Applications 2026

Auto-generated from `src/agent_guardian/probes/asiNN/*.yaml` — one row per ASI category. All ten categories are present in the shipped corpus.

| ASI | Name | Probe count | Example probe IDs |
|-----|------|-------------|-------------------|
| ASI01 | Goal Hijack | 15 | `ASI01-GH-001`, `ASI01-GH-002`, `ASI01-GH-003` |
| ASI02 | Tool Misuse | 8 | `ASI02-TA-001`, `ASI02-TA-002`, `ASI02-TA-003` |
| ASI03 | Privilege Abuse | 9 | `ASI03-PII-001`, `ASI03-PR-001`, `ASI03-PR-002` |
| ASI04 | Supply Chain | 8 | `ASI04-SC-001`, `ASI04-SC-002`, `ASI04-SC-003` |
| ASI05 | Code Execution | 8 | `ASI05-CE-001`, `ASI05-CE-002`, `ASI05-CE-003` |
| ASI06 | Memory Poisoning | 13 | `ASI06-HITL-009`, `ASI06-HITL-010`, `ASI06-HITL-011` |
| ASI07 | Agent-to-Agent (A2A) | 8 | `ASI07-A2A-001`, `ASI07-A2A-002`, `ASI07-A2A-003` |
| ASI08 | Cascading Failures | 8 | `ASI08-CF-001`, `ASI08-CF-002`, `ASI08-CF-003` |
| ASI09 | Trust Exploitation | 18 | `ASI09-OH-001`, `ASI09-OH-002`, `ASI09-OH-003` |
| ASI10 | Rogue Agents (drift) | 8 | `ASI10-DR-001`, `ASI10-DR-002`, `ASI10-DR-003` |

## MITRE ATLAS v5.4.0

Auto-generated from `mitre_atlas:` entries in every probe YAML. Rows are listed for every technique the shipped corpus actually cites (no padding, no aspirational entries). Techniques the corpus does not yet exercise are flagged honestly rather than hidden.

| ATLAS Technique | Description | Probe count | Example probe IDs |
|-----------------|-------------|-------------|-------------------|
| `AI Agent Context Poisoning` | AI Agent Context Poisoning (named, v5.4.0) | 18 | `ASI01-GH-002`, `ASI01-GH-003`, `ASI01-GH-005` |
| `AML.T0012` | Valid Accounts | 8 | `ASI03-PR-001`, `ASI03-PR-002`, `ASI03-PR-003` |
| `AML.T0024` | Exfiltration via ML Inference API | 1 | `ASI03-PII-001` |
| `AML.T0029` | Denial of ML Service | 4 | `ASI09-RSE-009`, `ASI09-RSE-010`, `ASI09-RSE-011` |
| `AML.T0034` | Cost Harvesting | 8 | `ASI08-CF-001`, `ASI08-CF-002`, `ASI08-CF-003` |
| `AML.T0043` | Craft Adversarial Data | 9 | `ASI09-TE-001`, `ASI09-TE-002`, `ASI09-TE-003` |
| `AML.T0048` | External Harms | 8 | `ASI02-TA-007`, `ASI04-SC-001`, `ASI04-SC-002` |
| `AML.T0050` | Command and Scripting Interpreter | 10 | `ASI05-CE-001`, `ASI05-CE-002`, `ASI05-CE-003` |
| `AML.T0051` | LLM Prompt Injection | 8 | `ASI01-GH-001`, `ASI01-GH-003`, `ASI01-GH-004` |
| `AML.T0053` | LLM Plugin Compromise | 7 | `ASI02-TA-001`, `ASI02-TA-002`, `ASI02-TA-003` |
| `AML.T0054` | LLM Jailbreak | 10 | `ASI01-GH-001`, `ASI01-GH-002`, `ASI01-GH-004` |
| `AML.T0058` | Publish Hallucinated Entities | 1 | `ASI04-SC-008` |
| `AML.T0060` | ML Supply Chain Compromise: Hardware | 7 | `ASI04-SC-001`, `ASI04-SC-002`, `ASI04-SC-003` |
| `AML.T0062` | Discover ML Artifacts | 4 | `ASI04-SC-008`, `ASI06-MP-001`, `ASI06-MP-002` |
| `AML.T0064` | LLM Prompt Injection: Direct | 8 | `ASI01-GH-001`, `ASI01-GH-002`, `ASI01-HCOT-001` |
| `AML.T0067` | LLM Prompt Injection: Indirect | 4 | `ASI01-GH-002`, `ASI01-GH-006`, `ASI01-GH-008` |
| `AML.T0068` | LLM Prompt Self-Replication | 2 | `ASI02-TA-004`, `ASI02-TA-008` |
| `AML.T0070` | RAG Poisoning | 2 | `ASI01-GH-001`, `ASI01-GH-006` |
| `AML.T0071` | False RAG Entry Injection | 2 | `ASI03-PII-001`, `ASI03-PR-007` |
| `Escape to Host` | Escape to Host (named, v5.4.0) | 6 | `ASI05-CE-001`, `ASI05-CE-002`, `ASI05-CE-003` |
| `Exfiltration via AI Agent Tool Invocation` | Exfiltration via AI Agent Tool Invocation (named, v5.4.0) | 5 | `ASI02-TA-001`, `ASI02-TA-002`, `ASI02-TA-004` |
| `Memory Manipulation` | Memory Manipulation (named, v5.4.0) | 14 | `ASI03-PR-007`, `ASI05-CE-008`, `ASI06-HITL-009` |
| `Modify AI Agent Configuration` | Modify AI Agent Configuration (named, v5.4.0) | 14 | `ASI01-GH-007`, `ASI03-PR-008`, `ASI04-SC-006` |
| `Publish Poisoned AI Agent Tool` | Publish Poisoned AI Agent Tool (named, v5.4.0) | 10 | `ASI02-TA-007`, `ASI04-SC-001`, `ASI04-SC-002` |
| `RAG Credential Harvesting` | RAG Credential Harvesting (named, v5.4.0) | 3 | `ASI06-MP-001`, `ASI06-MP-004`, `ASI06-MP-007` |
| `Thread Injection` | Thread Injection (named, v5.4.0) | 2 | `ASI06-MP-002`, `ASI06-MP-003` |

> **Honest scope note.** MITRE ATLAS v5.4.0 ships roughly 80 techniques across the full matrix. AgentGuardian is a black-box agent scanner — it can only meaningfully exercise techniques that manifest at the agent's input / output / tool-call surface. Techniques targeting model training, data-pipeline infrastructure, or out-of-band ML-platform compromise are out of scope by design and **not covered by the current corpus**. Roughly 85% of the v5.4.0 catalogue falls into that out-of-scope set; the matrix above lists the in-scope subset we exercise.

## CSA Agentic AI Red Teaming Guide

Auto-generated from `csa_category:` entries in every probe YAML. All 12 categories from the CSA Agentic AI Red Teaming Guide (Huang et al., 2025-05-28) are listed; zero-coverage rows are marked honestly rather than dropped.

| CSA Category | Name | Probe count | Example probe IDs |
|--------------|------|-------------|-------------------|
| `goal-instruction-manipulation` | Goal & Instruction Manipulation | 15 | `ASI01-GH-001`, `ASI01-GH-002`, `ASI01-GH-003` |
| `authorization-control-hijacking` | Authorization & Control Hijacking | 9 | `ASI03-PII-001`, `ASI03-PR-001`, `ASI03-PR-002` |
| `agent-critical-system-interaction` | Agent ↔ Critical-System Interaction | 16 | `ASI02-TA-001`, `ASI02-TA-002`, `ASI02-TA-003` |
| `supply-chain-dependency` | Supply Chain & Dependency | 8 | `ASI04-SC-001`, `ASI04-SC-002`, `ASI04-SC-003` |
| `knowledge-base-poisoning` | Knowledge Base Poisoning | 2 | `ASI06-MP-001`, `ASI06-MP-004` |
| `memory-context-manipulation` | Memory & Context Manipulation | 6 | `ASI06-MP-002`, `ASI06-MP-003`, `ASI06-MP-005` |
| `multi-agent-exploitation` | Multi-Agent Exploitation | 8 | `ASI07-A2A-001`, `ASI07-A2A-002`, `ASI07-A2A-003` |
| `impact-chain-blast-radius` | Impact Chain & Blast Radius | 8 | `ASI08-CF-001`, `ASI08-CF-002`, `ASI08-CF-003` |
| `hallucination-exploitation` | Hallucination Exploitation | 14 | `ASI09-OH-001`, `ASI09-OH-002`, `ASI09-OH-003` |
| `checker-out-of-the-loop` | Checker-Out-of-the-Loop | 5 | `ASI06-HITL-009`, `ASI06-HITL-010`, `ASI06-HITL-011` |
| `agent-untraceability` | Agent Untraceability | 8 | `ASI10-DR-001`, `ASI10-DR-002`, `ASI10-DR-003` |
| `resource-service-exhaustion` | Resource & Service Exhaustion | 4 | `ASI09-RSE-009`, `ASI09-RSE-010`, `ASI09-RSE-011` |

---

Regenerate this page with:

```bash
uv run python scripts/build_coverage_matrix.py
```
