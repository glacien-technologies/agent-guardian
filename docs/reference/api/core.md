# Core (Swarm)

**TL;DR** — The orchestration core: the Swarm Commander, budget controller, shared memory, sandbox, PII redactor, AIVSS scorer, and the signing / verification entry points. For the conceptual tour of how the swarm runs, see [The swarm](../../concepts/swarm.md).

## `SwarmCommander`

The entry point for programmatic scans. The CLI wraps this; library users call it directly.

::: agent_guardian.core.swarm
    options:
      show_root_heading: false

## `BudgetController`

::: agent_guardian.core.budget
    options:
      show_root_heading: false

## `SharedMemory`

::: agent_guardian.core.memory
    options:
      show_root_heading: false

## `Sandbox`

::: agent_guardian.core.sandbox
    options:
      show_root_heading: false

## PII redaction

::: agent_guardian.core.redact
    options:
      show_root_heading: false

## AIVSS scoring

::: agent_guardian.core.scoring
    options:
      show_root_heading: false

## Tier detection

::: agent_guardian.core.tiering
    options:
      show_root_heading: false

## Signing and verification

The signing entry points live alongside the JSON report emitter so a single canonical payload feeds both writing and verifying. They are documented in full on the [Reports](reports.md#signing-and-verification) page; the directive below is mirrored here so cross-links from the CLI module and from [Signing & verification](../../security/signing.md) resolve to a stable anchor.

::: agent_guardian.reports.json_report
    options:
      members:
        - sign_payload
        - verify_signatures
        - VerifyResult
      show_root_heading: false
      heading_level: 3
