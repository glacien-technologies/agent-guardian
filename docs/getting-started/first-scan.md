# Your first scan

A guided walk-through of an end-to-end scan using `--model stub` — no API key, no network, runs anywhere. Five minutes start to finish.

## 0. Verify the install

```bash
pip install agent-guardian
agent-guardian doctor
```

`doctor` confirms the CLI is on your PATH, prints the resolved Python interpreter, lists any LLM keys it picks up, and checks the sandbox is importable.

## 1. Write a system prompt to scan

The simplest target shape is a system prompt in a plain text file:

```bash
cat > prompt.txt <<'EOF'
You are a helpful customer-support bot for ACME Corp.
You can issue refunds up to $50 and look up order history.
You must never reveal internal pricing rules or other customers' data.
EOF
```

## 2. Run the scan

```bash
agent-guardian scan --system-prompt prompt.txt --model stub
```

What you'll see (lightly trimmed):

```text
AgentGuardian is intended for authorised security testing only. ...
cost estimate: $0.0000 (provider list prices, ...)
[Rich progress panel — recon, then 10 ASI agents in parallel]
scan cli-abc123def456 done: AIVSS=87 band=high tier=T2 findings=14 \
  report=/Users/you/.agentguardian/scans/cli-abc123def456/report.json
```

The first line is the [ethical-use banner](../ethics.md), shown once per user.

## 3. Read the result

The summary line tells you:

- **`AIVSS=87`** — the deterministic 0–100 score. See [AIVSS Score](../aivss-formula.md) for the formula and weights.
- **`band=high`** — the severity bucket the score falls into.
- **`tier=T2`** — what tier the target was scanned at (auto-detected from the recon fingerprint, or forced with `--tier`).
- **`findings=14`** — total findings across all 10 ASI categories.
- **`report=…`** — where the JSON evidence pack lives.

## 4. Inspect the JSON

```bash
jq '.aivss, .band, .per_asi' \
   ~/.agentguardian/scans/cli-abc123def456/report.json
```

You'll see the AIVSS score, the band, and a per-ASI breakdown (`{"ASI01": 3, "ASI02": 1, ...}`).

## 5. Regenerate as Markdown

The scan persists `scan.json` (the raw model dump) alongside `report.json`, so you can re-emit any other format without re-running the swarm:

```bash
agent-guardian report cli-abc123def456 --output md > scan.md
```

## 6. Make an AIVSS badge

```bash
agent-guardian badge $(agent-guardian last-score) --svg > badge.svg
```

Drop `badge.svg` into your README or status page.

## What changed when you used a real LLM

`--model stub` gives a deterministic synthetic transcript — fine for understanding the shape of a scan and for testing CI integration. With a real LLM, the swarm:

1. **Recon agent** fingerprints the target's capabilities (≤90s wall-clock cap).
2. **Ten ASI specialists** fire in parallel, each producing real probes shaped by the recon fingerprint.
3. **Swarm Commander** samples the AIVSS every 2 seconds, donates token budget from idle agents to under-performing categories, and early-stops if the score has converged.
4. **Evaluator** adjudicates each finding against a per-agent rubric.

Wire up a real provider in [LLM Providers](../providers/index.md), then re-run the same command with `--model openai:gpt-4o` (or whichever provider you picked).

## What next

- [CLI Reference](../cli.md) — every command and flag.
- [Configuration](../guide/configuration.md) — `.agentguardian.yaml` schema.
- [Output Formats](../guide/output-formats.md) — JSON / SARIF / JUnit / Markdown / PDF.
- [Agents & Swarm](../concepts/swarm.md) — how the eleven agents coordinate.
