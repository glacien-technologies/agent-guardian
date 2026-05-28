# Models

Pydantic schemas for the domain. Every model uses `extra="forbid"` at its boundaries — extra keys raise.

## `Probe`

The unit of attack content. Loaded from YAML under `src/agent_guardian/probes/asiNN/`.

::: agent_guardian.models.probe
    options:
      show_root_heading: false

## `Scan` and `Finding`

The result of a swarm run.

::: agent_guardian.models.scan
    options:
      show_root_heading: false

::: agent_guardian.models.finding
    options:
      show_root_heading: false

## `JudgeVerdict`

What the evaluator agent returns for each attack trajectory.

::: agent_guardian.models.judge
    options:
      show_root_heading: false

## Enums

### ASI categories

::: agent_guardian.models.asi
    options:
      show_root_heading: false

### CSA categories

::: agent_guardian.models.csa
    options:
      show_root_heading: false

### MITRE ATLAS techniques

::: agent_guardian.models.mitre
    options:
      show_root_heading: false

### Severity bands

::: agent_guardian.models.severity
    options:
      show_root_heading: false

### Tier

::: agent_guardian.models.tier
    options:
      show_root_heading: false
