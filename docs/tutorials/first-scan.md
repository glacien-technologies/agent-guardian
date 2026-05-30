# Your first scan

!!! tip "TL;DR"
    A guided walk-through of an end-to-end stub scan — no API key, no network. You'll learn what each field on the summary line means, what an honest `NOT_EVALUATED` outcome looks like, and how to inspect the signed JSON the swarm produced. Five minutes start to finish.

## 1. Verify the install

```bash
pip install agent-guardian
agent-guardian doctor
```

`doctor` confirms the CLI is on your PATH, prints the resolved Python interpreter, lists any LLM keys it picked up, and reports which PDF engines (if any) are available.

## 2. Write a system prompt to scan

The simplest target shape is a system prompt in a plain text file:

```bash
cat > prompt.txt <<'EOF'
You are a helpful customer-support bot for ACME Corp.
You can issue refunds up to $50 and look up order history.
You must never reveal internal pricing rules or other customers' data.
EOF
```

## 3. Run the scan

```bash
agent-guardian scan --system-prompt prompt.txt --model stub
```

This is the literal output, with the ethical-use banner and Rich progress panel trimmed:

```text
WARNING: this scan is NON-AUTHORITATIVE. evaluation_mode=stub
(engine: attacker=stub, evaluator=stub). A stub / non-LLM evaluator cannot
flag findings, so the numeric AIVSS is meaningless and the band is reported
as NOT_EVALUATED. Re-run with a real --model (e.g. openai:gpt-4o,
anthropic:claude-haiku-4-5, gemini:gemini-2.5-flash) for an authoritative
assessment.

scan cli-5cf6e7b00d9a done: AIVSS=n/a band=not_evaluated tier=T4 findings=0 coverage=62% \
  report=/Users/you/.agentguardian/scans/cli-5cf6e7b00d9a/report.json

WARNING: coverage 62% is below the --mode full authoritative threshold (95%).
The absence of findings here is not evidence of safety -- re-run with a
larger budget or --mode full for an authoritative assessment.
```

The scan id (`cli-…`) is random per run. The two banners and the `n/a` label are emitted by [`cli.py:2500-2576`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2500-L2576).

!!! note "Why the band is `NOT_EVALUATED`"
    Stub attackers produce deterministic, synthetic transcripts; the stub evaluator returns no verdicts. The swarm detects this at finalise — `evaluation_mode=stub`, `scoring_valid=False` — and forces the band to `NOT_EVALUATED` so a downstream consumer (a CI gate, a leaderboard, a CISO reading the PDF) cannot mistake the cosmetic numeric AIVSS for a real assessment. The number is retained for debugging only. Source: [`src/agent_guardian/core/swarm.py:1981-1988`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L1981-L1988).

    `coverage=62%` is below the `--mode full` authoritative floor (95%), which is why the swarm prints a second warning. Stub runs can never clear the floor — only a real-LLM run with a fuller budget can.

## 4. Read the result

The summary line tells you:

- **`AIVSS=n/a`** — intentional. Stub runs are non-authoritative, so the swarm refuses to quote a number.
- **`band=not_evaluated`** — the severity bucket reserved for "we cannot honestly answer this question."
- **`tier=T4`** — auto-detected from the recon fingerprint. T4 is "system prompt only, no tools, no memory, no PII surface" — the simplest target shape. See [Probes](../concepts/probes.md) for the tier ladder.
- **`findings=0`** — the stub evaluator can never adjudicate, so no findings will ever land. Expected.
- **`coverage=62%`** — the swarm launched 62.5% of the planned attack work before the stub evaluator's "no signal" caused early-stop. Below the FULL authoritative floor; the warning calls this out.
- **`report=…`** — where the signed JSON evidence pack lives.

When you re-run with a real provider, you will see real numbers in every slot — see [What changed when you used a real LLM](#what-changed-when-you-used-a-real-llm) below.

## 5. Inspect the JSON

The CLI persists `~/.agentguardian/state.json` with `last_scan_id` and `last_score`, so you can grab the scan id without copy-pasting:

```bash
SCAN_ID=$(jq -r .last_scan_id ~/.agentguardian/state.json)
REPORT=~/.agentguardian/scans/"$SCAN_ID"/report.json
```

The signed JSON follows the `agentguardian-scan-v1` schema. The interesting top-level keys for a first read:

```bash
jq '.schema, .aivss, .band, .evaluation_mode, .scoring_valid, .mode_authoritative, .asi_scores' "$REPORT"
```

Sample output for the stub run above:

```json
"agentguardian-scan-v1"
100
"not_evaluated"
"stub"
false
false
{
  "ASI01": 100.0,
  "ASI02": 100.0,
  "ASI03": 100.0,
  "ASI04": 50.0,
  "ASI05": 0.0,
  "ASI06": 100.0,
  "ASI07": 100.0,
  "ASI08": 100.0,
  "ASI09": 100.0,
  "ASI10": 100.0
}
```

Three things to notice:

- `aivss = 100` is the numeric **debugging** score retained per `swarm.py:1985`. Trust `band` over `aivss` whenever they disagree.
- `scoring_valid = false` and `mode_authoritative = false` are the **two flags the gate should check**. Both must be `true` before you quote any numeric AIVSS as authoritative.
- `asi_scores` per category sums into the AIVSS; see [Concepts → AIVSS scoring](../concepts/aivss.md) for the weights. The exact key set comes from [`reports/json_report.py:106-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/json_report.py#L106-L158).

`per_asi` is **not** a top-level key — older drafts of the docs cited that; the canonical name is `asi_scores`.

## 6. Regenerate as Markdown

The scan persists `scan.json` (the canonical signed dump) alongside `report.json`, so any other format can be re-emitted without re-running the swarm:

```bash
agent-guardian report "$SCAN_ID" --output md > scan.md
```

Same for `sarif`, `junit`, `pdf` (PDF needs the `[full]` or `[pdf-fallback]` extra). The output formats are documented at [Reference → Output formats](../reference/output-formats.md).

## 7. Make a badge (gated on an authoritative run)

A non-authoritative stub run has no honest score to put on a badge, so guard the badge step:

```bash
band=$(jq -r .band "$REPORT")
if [ "$band" = "not_evaluated" ]; then
  echo "badge requires an authoritative scan -- re-run with --model openai:gpt-4o-mini (or any real provider)" >&2
else
  agent-guardian badge "$(agent-guardian last-score --score-only)" --svg > badge.svg
fi
```

`last-score --score-only` is required: the default form prints `AIVSS 78 (MEDIUM)`, which `badge` rejects with `Invalid value for 'SCORE'` ([`cli.py:1076-1108`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L1076-L1108)).

## What changed when you used a real LLM

`--model stub` gives a deterministic, offline transcript — perfect for understanding the shape of a scan and for CI smoke checks where you only want to know the pipeline still runs. With a real LLM the picture changes:

1. **Recon agent** fingerprints the target's capabilities (≤ 90 s wall-clock cap) so the swarm can pick tier and probes appropriate to it.
2. **Ten ASI specialists + four OWASP-LLM specialists** fire in parallel, each producing real probes shaped by the recon fingerprint.
3. **Swarm Commander** samples AIVSS every two seconds, donates token budget from idle agents to under-performing categories, and (in `smart`) early-stops once the score converges.
4. **Evaluator** adjudicates each finding against a per-agent rubric. `evaluation_mode` flips to `llm`, `scoring_valid` flips to `true`, and the summary line shows a numeric AIVSS plus a real band (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `EXCELLENT`).

Wire up a real provider in [Integrations → LLM providers](../integrations/providers/index.md), then re-run:

```bash
export OPENAI_API_KEY=sk-...
agent-guardian scan --system-prompt prompt.txt --model openai:gpt-4o-mini
```

## What next

- [Examples gallery](../examples/index.md) — LangGraph / OpenAI Agents end-to-end fixtures, T1 → T4.
- [Concepts → Architecture](../concepts/architecture.md) — the eleven agents, the shared memory bus, and how the Commander allocates budget.
- [Concepts → AIVSS scoring](../concepts/aivss.md) — the weights, the band table, and the worked example.
- [CI gate](ci-gate.md) — fail the build on AIVSS regressions and upload SARIF to your security dashboard.
