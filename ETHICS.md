# AgentGuardian Ethics Policy

AgentGuardian is offensive-security tooling for agentic AI systems. It exists to help builders
find — and fix — failure modes in agents *they own or are explicitly authorised to test*.

## You may use AgentGuardian to

- Test agents you have built.
- Test agents your employer owns and has authorised you to test.
- Test agents under a written bug-bounty or penetration-testing scope that explicitly permits
  automated adversarial probing.
- Reproduce published research against your own copies of public models / agents.

## You may not use AgentGuardian to

- Probe production agents you do not own or have not been authorised to test.
- Bypass authentication, rate limits, or terms of service of third-party services.
- Generate adversarial output for downstream harm (harassment, fraud, CSAM, disinformation
  campaigns, weapons synthesis, etc.).
- Evade detection of attacks that are themselves harmful in the real world.

## Reporting misuse

If you believe AgentGuardian is being used against systems without authorisation, or to produce
real-world harm, please contact `security@glacien.tech` (PGP key in [SECURITY.md](./SECURITY.md)).

## Responsible disclosure of new probes

New probes submitted via PR must:

1. Target a public, documented failure mode (or a coordinated-disclosure-cleared private one).
2. Avoid embedding live exploits against named third-party production systems.
3. Be reproducible against the bundled stub target or a synthetic fixture.

We will reject probes whose only realistic use is attacking a specific third party's live system
without their consent.
