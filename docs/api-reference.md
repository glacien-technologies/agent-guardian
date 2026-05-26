# API Reference

The public Python API of `agent_guardian` is intentionally small. The
package's primary surface is the `agent-guardian` CLI; the Python API
exists so you can embed scans into your own CI scripts or test suites.

## High-level scan functions

```python
from agent_guardian import (
    scan_system_prompt,
    scan_code,
    scan_http,
    scan_framework,
)
```

All four return the same `ScanResult` object — see below.

### `scan_system_prompt`

```python
def scan_system_prompt(
    prompt: str,
    *,
    model: str = "anthropic:claude-opus-4-7",
    seed: int | None = None,
    budget_requests: int = 500,
    strategies: list[str] | None = None,
) -> ScanResult: ...
```

### `scan_code`

```python
def scan_code(
    path: str | os.PathLike,
    *,
    model: str = "anthropic:claude-opus-4-7",
    seed: int | None = None,
    budget_requests: int = 500,
) -> ScanResult: ...
```

### `scan_http`

```python
def scan_http(
    url: str,
    *,
    shape: HttpShape = "auto",
    headers: dict[str, str] | None = None,
    template: str | os.PathLike | None = None,
    max_qps: float = 5.0,
    max_requests: int = 500,
    model: str = "anthropic:claude-opus-4-7",
    seed: int | None = None,
) -> ScanResult: ...
```

### `scan_framework`

```python
def scan_framework(
    target: Any,                       # framework runtime object
    *,
    model: str = "anthropic:claude-opus-4-7",
    seed: int | None = None,
    budget_requests: int = 500,
) -> ScanResult: ...
```

## `ScanResult`

```python
from agent_guardian.models import ScanResult

class ScanResult(BaseModel):
    scan_id: str
    aivss_score: int                   # 0–100
    band: Literal["negligible", "low", "medium", "high", "critical"]
    colour: str                        # hex colour for the band
    findings: list[Finding]
    per_asi: dict[str, int]            # ASI category → finding count
    evidence_pack_path: pathlib.Path
    signed_report_path: pathlib.Path
    duration_s: float
```

## `Finding`

```python
class Finding(BaseModel):
    finding_id: str
    asi: str                           # e.g. "ASI01"
    atlas: list[str]                   # e.g. ["AML.T0051"]
    csa: list[str]                     # CSA Agentic-RT IDs
    tier: Literal["T1", "T2", "T3", "T4"]
    title: str
    description: str
    evidence: list[EvidenceItem]
    guardrail_engaged: bool
    exploit_succeeded: bool
    payload_executed: bool
    persistence: bool
```

## `SwarmCommander`

The orchestration loop is exposed for advanced use:

```python
from agent_guardian.agents import SwarmCommander

commander = SwarmCommander(model="anthropic:claude-opus-4-7", seed=42)
result = commander.run(target_profile)
```

You can subclass `SwarmCommander` to customise the convergence policy or
plug in a non-default agent roster. See
`src/agent_guardian/agents/commander.py` for the protocol.

## CLI reference

```
agent-guardian --help
agent-guardian scan --help
agent-guardian serve --help
agent-guardian verify --help
agent-guardian report --help
agent-guardian badge --help
agent-guardian doctor
agent-guardian list-probes
agent-guardian last-score
```

Every command is documented in its `--help`. The full CLI is also
covered by `tests/unit/test_cli.py`, which is the canonical contract.
