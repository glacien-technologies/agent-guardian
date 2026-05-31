# Scan modes — when to use which

!!! abstract "TL;DR"
    Three modes — `fast` for CI, `smart` for cost-tuned dev loops, `full` for the audit. FULL is the default since v1.0 because under-eager early-stop produces misleading scores. Source: [`SwarmConfig._MODE_PRESETS`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L357).

AgentGuardian's scan has three explicit modes that trade thoroughness against cost and wall time. The default (`full`) is the most thorough; `fast` is intended for CI gates; `smart` is the variance-gated early-stop behaviour preserved for cost-tuned runs that still want the full probe corpus.

```sh
agent-guardian scan target.py                  # mode=full (default)
agent-guardian scan target.py --mode smart
agent-guardian scan target.py -m fast
```

## The three modes at a glance

| Mode | Probes per agent | Turns per agent | Early-stop | Measured wall | Measured cost (Gemini) | When to use |
|---|---|---|---|---|---|---|
| **`fast`** | top 3 | 4 | aggressive (variance ≥ 5.0 *or* no recent findings) | ~165s | ~$0.016 | Pre-merge CI gate. "Did I obviously break something?" |
| **`smart`** | all | 12 (default) | enabled (variance-gated early-stop — variance ≥ 2.0 *and* no recent findings) | ~190s | ~$0.019 | Iterative dev loops. You want the full corpus but accept that some slow-burn categories may stop early. |
| **`full`** *(default)* | all | 12 (default) | **suppressed** until every agent has used its full turn budget | ~365s | ~$0.030 | Pre-release audit. Security review. Coverage measurement. Any time the score will be quoted to a stakeholder. |

The numbers above were measured against the OWASP-vulnerable-by-design target in `agentguardian-benchmarks/targets/vulnerable/owasp_asi_all.py` on Gemini 2.5 Flash (`gemini-2.5-flash`) on 2026-05-28, single run per mode, T2 tier. Your wall time will vary with target complexity, LLM latency, and provider region; cost scales roughly linearly with attacker + judge token volume.

In the validation run all three modes scored AIVSS 31–34 (CRITICAL band) on the vulnerable target, with 7–9 findings spanning 5/10 ASI categories. The categories *which* mode caught differ run-to-run because of LLM stochasticity — FAST hit ASI01+ASI03 the others missed; FULL hit ASI05 that FAST missed. Use FULL when consistency across runs matters; use FAST when speed matters.

## Why `full` is the default

FULL is the default since v1.0 (commit `91c73c4`, 2026-05-28). The reason: **the early-stop heuristic has a bias against slow-burn attack categories**. Goal hijack, memory poisoning, and trust exploitation often need 6–10 turns to land a first finding — exactly the window where the "no findings in the last N seconds" half of the early-stop signal fires. On the vulnerable-by-design target, disabling early-stop took coverage from 5/10 → 6/10 ASI categories and from 9 → 11 total findings.

For a security tool, the cost of an over-eager early stop (a misleading score the user trusts) is much worse than the cost of an under-eager one (you paid 2× more). So FULL is the safe default; SMART and FAST are explicit opt-downs.

## What changes between modes

Three knobs vary by mode. They live on `SwarmConfig` and are populated from `_MODE_PRESETS` ([`swarm.py:357`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L357)) in `__post_init__` ([`swarm.py:294-296`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L294)). Any value you pass explicitly to the constructor overrides the preset — useful in tests that want "FULL semantics with a tiny turn budget."

```python
class SwarmConfig:
    mode: ScanMode = ScanMode.FULL
    probes_per_category: int | None = None    # FAST=3, others=all
    max_turns_per_agent: int | None = None    # FAST=4, others=12
    min_turns_before_early_stop: int = 0      # FAST=0, SMART=0, FULL=999
```

The early-stop *gate* compares `min_turns_before_early_stop` against the per-agent `max_turns_per_agent`. FULL sets the gate to 999 — much larger than the per-agent budget — so the gate never opens and EARLY_STOP is suppressed even when the variance signal is screaming.

FULL also pins `early_stop_variance_threshold` to `0.0` (variance is always ≥ 0, so the variance arm of the signal can't fire either). Belt-and-braces — either arm being closed is sufficient.

## Mode is recorded in the report

Every `Scan` JSON includes a `mode` field. The public analytics dashboard breaks coverage down by mode so you can fairly compare FAST-mode runs against FAST-mode runs, rather than mixing a 45-second smoke check into the same aggregate as a 5-minute audit.

```json
{
  "id": "scan-abc123",
  "aivss": 28,
  "band": "POOR",
  "mode": "full",
  "duration_seconds": 287.4,
  "cost_usd": 0.058
}
```

A FULL-mode scan that passed `scoring_valid` also carries `mode_authoritative: true` ([`swarm.py:2054`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L2054)). Downstream CI gates should only honour scans with `mode_authoritative: true`; everything else is for debugging.

## CI integration

For CI gates, `fast` is the sensible default — it runs in under a minute and catches the obvious regressions. If you need stronger guarantees on `main`, schedule a nightly `full` scan. The complete workflow recipe lives at [Add to your CI pipeline](../tutorials/ci-gate.md).

## Picking a `--fail-under` per mode

Because each mode has a different expected AIVSS distribution, your `--fail-under` threshold should match. Rough rules of thumb:

| Mode | Suggested `--fail-under` for new code | Why |
|---|---|---|
| `fast` | 60 | FAST under-counts findings, so an absolute threshold of 60 catches obvious regressions without false-failing on slow-burn categories the mode skipped. |
| `smart` | 70 | SMART is a balanced threshold for projects that previously ran with variance-gated early-stop. |
| `full` | 80 | FULL finds more, so the bar is higher. A FULL scan that scores below 80 has real gaps. |

These are starting points — tune to your project's tolerance.

## Tier vs mode

Tier (T1–T4) and mode (FAST/SMART/FULL) are orthogonal. Tier sets the *target's* threat level — it drives probe selection (only probes whose `tier_floor` ≤ tier) and tier-weighted AIVSS aggregation. Mode sets the *scan's* thoroughness — it drives early-stop, per-agent budgets, and probe-subset gating. See [Target tiers](tiers.md) for the four tiers themselves and the AIVSS weights per tier.

## What this does NOT add

- **No per-probe priority weights.** FAST relies on positional order in each agent's seed list; the first 3 are taken as the "most likely to find something" subset. Adding an explicit `priority: int` on each probe YAML is on the [roadmap](../reference/roadmap.md).
- **No Tier × Mode matrix.** We use the same mode preset for every tier today; per-tier mode tuning is on the [roadmap](../reference/roadmap.md).
- **No CI auto-detection.** `--mode` always defaults to FULL, even in CI environments. We considered auto-downgrading to SMART when `GITHUB_ACTIONS=true` etc., but decided the explicitness was worth more than the convenience. Set `--mode fast` in your workflow file (see [CI gate tutorial](../tutorials/ci-gate.md)).

--8<-- "_glossary-abbreviations.md"
