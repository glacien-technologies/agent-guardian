# Ethics and responsible use

!!! warning "Authorised use only"
    **TL;DR** — AgentGuardian is for testing systems you own or are explicitly authorised to test. Use against third-party systems without authorisation is unlawful in most jurisdictions and a violation of these terms.

## Scope restrictions

AgentGuardian is designed exclusively for **defensive security**. The acceptable-use scope is:

- Agents you own or operate.
- Agents you have written authorisation to test (a signed red-team engagement letter, a bug-bounty programme scope, or a written authorisation from the agent's operator).
- Public testbed agents that explicitly invite red-teaming (e.g. CTF agents, research benchmarks, the OWASP ASI reference implementation).

The acceptable-use scope is **not**:

- Third-party production agents you do not own and have not been authorised to test.
- Public APIs of commercial AI products without an authorisation letter.
- Any system where your testing might affect users other than yourself.

## Why this matters

The probes shipped in v1.0 are functional jailbreak attempts. Some exploit known vulnerabilities in published frameworks. Running them against a third-party production system without authorisation is, in most jurisdictions:

- A violation of the Computer Fraud and Abuse Act (US) or its local equivalent.
- A violation of the target's Terms of Service.
- A potential civil claim under tortious interference or trespass.

We have not seen a case-law test of "but my probe was just a prompt" and we strongly recommend you do not become the case that sets the precedent.

## Responsible disclosure

If AgentGuardian finds a real, exploitable vulnerability in a **third-party framework or product**, please disclose it responsibly:

- Contact the vendor first, with a 90-day disclosure window.
- File a CVE if the vendor agrees the issue warrants one.
- Do not publish proof-of-concept exploit code until the vendor has shipped a fix.

If you find a vulnerability **in AgentGuardian itself**, see [responsible-disclosure.md](responsible-disclosure.md) for our policy.

## Telemetry

AgentGuardian ships with **essential-tier telemetry on by default** (operational counts only — no environment fingerprint, no prompts, no findings, no paths, no keys) and an explicit opt-out. The complete allowlist, the never-collected list, and the CLI to disable it are in [telemetry.md](telemetry.md).

If you need *zero* telemetry, run `agent-guardian telemetry disable` — that also sends a `forget` event so your `install_id` is deleted server-side.

## Probe content

The seed-probe corpus contains adversarial prompts. Some are deliberately offensive, manipulative, or misleading — that is the nature of adversarial security testing. The probes are not recommendations and are not endorsements. They are stimuli designed to test whether your agent's guardrails hold.

If a probe causes harm during scanning — for example, if your agent under test sends an offensive reply to a real human user — you should treat that as a finding (the agent's guardrail did not engage) and not as a flaw in AgentGuardian.

## Reporting misuse

If you become aware of AgentGuardian being used outside its acceptable scope — for example, scanning a third-party production agent without authorisation — please report it to [security@glacien.ai](mailto:security@glacien.ai). We will assist law enforcement where appropriate.

## Disclaimer

AgentGuardian is provided under the Apache License 2.0 "as is," without warranty of any kind. The authors and Glacien Pte. Ltd. accept no liability for damages arising from use of this software — including, but not limited to, damages caused by use of the software outside its acceptable scope.

## See also

- [Threat model](threat-model.md) — what AgentGuardian defends and what it doesn't.
- [Responsible disclosure](responsible-disclosure.md) — vulnerability disclosure policy.
- [Telemetry transparency](telemetry.md) — what AgentGuardian sends home.
