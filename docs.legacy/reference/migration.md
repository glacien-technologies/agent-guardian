# Migration guide

**TL;DR.** Upgrade notes per minor / major release. Honest about
breaking changes — if you're on `1.0.x` and want to move to `1.1`, the
default `--mode` flips from the implicit `smart` to `full`. Everything
else listed here is additive.

## Upgrading to 1.1 (target: 2026 Q3)

### Breaking default change — scans without `--mode` now run `full`

Pre-`1.1` scans implicitly ran the equivalent of `smart` (early-stop
when AIVSS variance stabilises). In `1.1` the default flips to `full`,
which runs every probe on every agent to completion. The rationale: for
a security tool, the right failure mode is "you paid 2× more for
thorough coverage" — not "you got a fast misleading score".

#### Restore the v1.0 cost / wall profile

Pass `--mode smart` explicitly:

```bash
agent-guardian scan --system-prompt prompt.txt \
  --model openai:gpt-4o \
  --mode smart
```

Or pin it in `.agentguardian.yaml` (when the v1.1 schema lands —
[track in roadmap](roadmap.md)).

Empirical numbers from the vulnerable-by-design target on Gemini 2.5
Flash:

| Mode    | Wall      | Cost (USD) | Tokens   |
|---------|-----------|------------|----------|
| `fast`  | ~165 s    | ~$0.016    | ~32 k    |
| `smart` | ~190 s    | ~$0.019    | ~38 k    |
| `full`  | ~365 s    | ~$0.030    | ~66 k    |

See [concepts / scan modes](../concepts/scan-modes.md) for the full
trade-off matrix.

### Other changes

The full set of additions, fixes, and removals lands in the
[v1.1 entry of the changelog](changelog.md). Notable adoption items:

- New OWASP-LLM specialist agents run **by default**. Suppress with
  `--no-owasp-llm` to keep the 10-agent ASI-only slate from v1.0. The
  effective parallel-agent cap rises from 10 to 14 when the
  specialists are active. See [reference / cli — scan](cli.md#scan).
- Active detection-evasion generation is now part of
  `DetectionEvasionAgent`. **This reverses the v1.0 "we do NOT produce
  evasion-tuned payloads" caveat** — scoped strictly to authorized
  detection-coverage testing of the operator's own declared monitoring
  stack under the scan Rules of Engagement.

## Earlier releases

`1.0.0` was the first stable, generally-available release (2026-05-27).
There is no migration story from a pre-`1.0` release because none
shipped under a stable contract. See
[reference / changelog](changelog.md) for the full `1.0.0` content.
