# Threat coverage

!!! abstract "TL;DR"
    How OWASP ASI / MITRE ATLAS / CSA Agentic-RT map onto the bundled probe corpus. Every probe carries all three tags or the loader rejects it. Use this page to find "which probe proves the swarm covers ATLAS technique X".

## The triple-framework gate

Every probe carries three required taxonomy tags:

- `asi:` — one of `ASI01` … `ASI10` from the OWASP 2026 Top 10 for Agentic Applications.
- `mitre_atlas:` — at least one MITRE ATLAS technique ID (e.g. `AML.T0051`) or technique name.
- `csa_category:` — one CSA Agentic Red Teaming Guide category (e.g. `goal-instruction-manipulation`).

`ProbeLoader` ([`src/agent_guardian/probes/loader.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/loader.py)) rejects any probe that's missing any of the three; the `Probe` Pydantic model raises `ProbeValidationError`. The CI guard is [`tests/unit/test_probe_corpus.py::test_triple_framework_tagging`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/test_probe_corpus.py).

The schema and an example probe with all three tags live in [Probes](probes.md).

## Coverage matrix — ASI01 through ASI10

One specialist agent owns each ASI category. The table maps the category to the dedicated agent, a representative MITRE ATLAS technique observed on a real probe, the CSA Agentic-RT category, and a probe YAML you can read to see the wiring.

| ASI category | Owning agent              | Representative ATLAS                          | CSA Agentic-RT category               | Representative probe                                                                                                                            |
|--------------|---------------------------|-----------------------------------------------|---------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| ASI01 Goal Hijack       | `goal-hijack-agent`     | `AML.T0051` Prompt Injection / `AI Agent Context Poisoning` | `goal-instruction-manipulation`       | [`asi01/echoleak-zero-click.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi01/echoleak-zero-click.yaml) |
| ASI02 Tool Misuse        | `tool-abuse-agent`      | `AML.T0053` / `Exfiltration via AI Agent Tool Invocation`   | `agent-critical-system-interaction`   | [`asi02/chain-exfil.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi02/chain-exfil.yaml)                  |
| ASI03 Privilege Abuse    | `privilege-agent`       | `AML.T0012` / `Modify AI Agent Configuration`               | `authorization-control-hijacking`     | [`asi03/device-code-phish-relay.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi03/device-code-phish-relay.yaml) |
| ASI04 Supply Chain       | `supply-chain-agent`    | `Modify AI Agent Configuration` / `Publish Poisoned AI Agent Tool` | `supply-chain-dependency`             | [`asi04/agent-in-middle-via-card.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi04/agent-in-middle-via-card.yaml) |
| ASI05 Code Execution     | `code-exec-agent`       | `AML.T0050` Escape to Host                                  | `agent-critical-system-interaction`   | [`asi05/eval-smuggle.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi05/eval-smuggle.yaml)                |
| ASI06 Memory Poisoning   | `memory-poison-agent`   | `Memory Manipulation`                                       | `checker-out-of-the-loop`             | [`asi06/after-hours-autonomous-action.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi06/after-hours-autonomous-action.yaml) |
| ASI07 A2A                | `a2a-agent`             | `Modify AI Agent Configuration`                             | `multi-agent-exploitation`            | [`asi07/agent-card-spoof.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi07/agent-card-spoof.yaml)        |
| ASI08 Cascading Failures | `cascade-agent`         | `AML.T0034`                                                 | `impact-chain-blast-radius`           | [`asi08/alarm-suppression.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi08/alarm-suppression.yaml)      |
| ASI09 Trust Exploitation | `trust-exploit-agent`   | `AML.T0043`                                                 | `hallucination-exploitation`          | [`asi09/anthropomorphic-persuasion.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi09/anthropomorphic-persuasion.yaml) |
| ASI10 Rogue / Drift      | `drift-agent`           | `AI Agent Context Poisoning`                                | `agent-untraceability`                | [`asi10/capability-mask.yaml`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/asi10/capability-mask.yaml)          |

These are *representative* — each ASI directory ships multiple probes. List the full set per category:

```bash
agent-guardian list-probes --asi ASI05
```

The corpus version is `2026.05` ([`probes/loader.py:34`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/loader.py#L34)). For the schema, see [Probes](probes.md); for how findings collapse into the AIVSS score, see [AIVSS scoring](aivss.md).

## OWASP-LLM specialists

Five additional specialists cover the LLM-class concerns from OWASP's earlier *Top 10 for LLM Applications* (LLM01–LLM10). Each maps to the nearest ASI slot for scoring — there is no separate LLM01–LLM10 axis in AIVSS.

| OWASP-LLM ID | Agent                       | Scoring slot      | What it tests                                                                                  |
|--------------|-----------------------------|-------------------|------------------------------------------------------------------------------------------------|
| LLM02        | `output-handling-agent`     | ASI09             | Insecure output handling — markdown injection, XSS, command smuggling in rendered responses.   |
| LLM05        | `fuzzing-agent`             | ASI02             | Improper-output-handling fuzzing — unicode confusables, format-string injection, etc.          |
| LLM07        | `secret-extraction-agent`   | ASI01             | System-prompt and transport-secret extraction across direct and indirect channels.             |
| LLM10        | `denial-of-wallet-agent`    | ASI08             | Token / cost amplification — long-prompt loops, reasoning-trace flooding.                      |
| (coverage)   | `detection-evasion-agent`   | ASI10             | Coverage report for the eight detection-evasion vectors (cipher, dialect, semantic stretch...). |

Source: [`src/agent_guardian/agents/__init__.py:39`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/__init__.py#L39). These five specialists run by default; pass `--no-owasp-llm` to scope the scan to the 11-agent ASI-only slate (see [The swarm](swarm.md)).

## What we don't cover yet — honest gaps

The OSS corpus at `2026.05` is the v1.0 baseline, not the ceiling. Tracked on the [roadmap](../reference/roadmap.md):

- **CWE tagging** — every finding will carry a CWE ID alongside ASI / ATLAS / CSA. v1.2.
- **More ATLAS coverage** — the 2026.05 corpus emphasises `AML.T0050` / `AML.T0051` / `AML.T0053` / `AML.T0054` / `AML.T0012`. Other ATLAS techniques (e.g. data-poisoning sub-techniques, model-supply-chain) are partially covered via ASI04 but a wider sweep is on the roadmap.
- **Probe-authoring DSL + `probe-lint`** — community probe contributions land via a structured authoring tool. v1.1.
- **Chain-finding annotations** — explicit links between findings that share an attack path (e.g. an ASI06 poison → ASI01 hijack chain), with chain bonuses surfaced in the report. v1.1.

If you need a category not yet covered, the right loop is: author a probe (see [Authoring a probe](../contributing/probe-authoring.md)), open a PR with the YAML and a golden test, and tag the corpus bump in `_meta/version.yaml`.

--8<-- "_glossary-abbreviations.md"
