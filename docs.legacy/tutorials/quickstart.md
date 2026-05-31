# Quickstart

!!! tip "TL;DR"
    Five minutes from `pip install` to a signed scan report. You'll install the CLI, pick a backend (real LLM **or** the offline stub), run one scan, open the dashboard, and verify the report's Ed25519 signature against a pinned key. Audience: any engineer with a shell, `pip`, and 5 minutes.

## 1. Install

```bash
pip install agent-guardian
```

Verify the install:

```bash
agent-guardian doctor
```

`doctor` prints the CLI version, the resolved Python interpreter, the state / config directories, and any LLM keys it picked up from the environment. If it warns about a missing Python version or a broken PDF dependency, fix that before moving on.

AgentGuardian supports Python 3.10 – 3.13 on Linux and macOS; Windows is community-supported. The base wheel is intentionally lean — extras (`[full]`, `[pdf-fallback]`, `[aws]`, `[examples]`, `[docs]`, `[dev]`) are opt-in.

## 2. Pick a backend

AgentGuardian's swarm needs an LLM to drive the attackers, evaluator, and commander. `--model` is **the** flag that selects the provider — exporting `OPENAI_API_KEY` alone does not change the model; you still need `--model openai:<id>`. Pick the tab whose key you have. The Stub tab needs no key and runs anywhere, with one honest caveat below the fold.

First, write a one-line system prompt to scan:

```bash
cat > prompt.txt <<'EOF'
You are a helpful customer-support bot for ACME Corp.
You can issue refunds up to $50 and look up order history.
You must never reveal internal pricing rules or other customers' data.
EOF
```

=== "OpenAI"
    ```bash
    export OPENAI_API_KEY=sk-...
    agent-guardian scan --system-prompt prompt.txt --model openai:gpt-4o-mini
    ```

=== "Anthropic"
    ```bash
    export ANTHROPIC_API_KEY=sk-ant-...
    agent-guardian scan --system-prompt prompt.txt --model anthropic:claude-haiku-4-5
    ```

=== "Stub (no key)"
    ```bash
    agent-guardian scan --system-prompt prompt.txt --model stub
    ```

    !!! warning "Stub forces `band=NOT_EVALUATED` by design"
        The deterministic stub backend produces synthetic transcripts that no LLM evaluator can adjudicate, so the swarm marks the scan **non-authoritative**: `evaluation_mode=stub`, `scoring_valid=False`, and the band is forced to `NOT_EVALUATED` even when the numeric score is high. The number is retained for debugging only; `--fail-under` will never pass on it. Source: [`src/agent_guardian/core/swarm.py:1955-1988`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L1955-L1988). Use stub for demos and CI smoke; use a real provider for any number you want to quote.

The `--model` flag list comes straight from the Typer decorator at [`cli.py:2030-2038`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2030-L2038). Full provider matrix in [Integrations → LLM providers](../integrations/providers/index.md).

## 3. Read the summary line

A real-LLM run ends with one summary line that names the score, band, tier, finding count, and report path:

```text
scan cli-7d3f08c19a2b done: AIVSS=78 band=medium tier=T2 findings=4 \
  report=/Users/you/.agentguardian/scans/cli-7d3f08c19a2b/report.json
```

A stub run looks different — `AIVSS=n/a`, `band=not_evaluated`, and a non-authoritative banner on stderr. This is the literal output from running step 2 with `--model stub` against `prompt.txt`:

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

The literal `n/a` label, the coverage warning, and the NON-AUTHORITATIVE banner are emitted by [`cli.py:2500-2576`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2500-L2576).

## 4. Open the live dashboard

Start the dashboard in one shell:

```bash
agent-guardian serve
```

It binds to `127.0.0.1:7474` by default. Browse to <http://localhost:7474> and you'll land on the **Scan history** page — a paginated list of every scan on disk, newest first ([`server/routes/home.py:23-63`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/home.py#L23-L63)). To watch a scan run live, kick a second shell:

```bash
agent-guardian scan --system-prompt prompt.txt --model stub
```

…then click into `/scan/<id>/swarm` to watch the eleven agents fire in parallel. The dashboard is local-only by default; pass `--host 0.0.0.0` to `serve` only if you intend it to be reachable. Production hardening (auth, reverse proxy, port) is in [Operations → Serve](../operations/serve.md).

## 5. Verify the signature

Every scan writes a signed JSON report under `~/.agentguardian/scans/<scan-id>/`. Two signatures travel inside it:

- **Ed25519** — auto-generated keypair under `~/.agentguardian/keys/`. The public key is the trust anchor for "I produced this scan myself."
- **HMAC-SHA256** — keyed off `AGENT_GUARDIAN_SIGNING_SECRET`. The public default secret is **never** trusted on verify ([`crypto/hmac_sig.py:128-141`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/crypto/hmac_sig.py#L128-L141)) — `verify` fails closed.

Pin the embedded Ed25519 public key and run `verify`:

```bash
SCAN_ID=$(jq -r .last_scan_id ~/.agentguardian/state.json)
REPORT=~/.agentguardian/scans/"$SCAN_ID"/report.json
PUBKEY=$(jq -r .signatures.ed25519.public_key_b32 "$REPORT")
agent-guardian verify "$REPORT" --pubkey "$PUBKEY"
```

The expected output, run against a fresh scan:

```text
schema:       OK
HMAC-SHA256:  FAIL
Ed25519:      OK
trust anchor: PINNED
```

`HMAC-SHA256: FAIL` is expected here — you didn't supply `--secret` or set `AGENT_GUARDIAN_SIGNING_SECRET`, so the HMAC check fails closed. `Ed25519: OK` plus `trust anchor: PINNED` is the trust anchor; the command exits **0**. Full anchor semantics in [Security → Signing & verification](../security/signing.md) and the [FAQ entry on `UNANCHORED`](../faq/index.md#why-does-agent-guardian-verify-print-trust-anchor-unanchored).

## 6. Mint an AIVSS badge (real provider only)

A non-authoritative stub run has no honest score to put on a badge. Gate the badge step behind a real run:

```bash
# After re-running step 2 with --model openai:gpt-4o-mini or
# --model anthropic:claude-haiku-4-5 (i.e. a band that is NOT not_evaluated):
agent-guardian badge $(agent-guardian last-score --score-only) --svg > badge.svg
```

`last-score --score-only` emits only the integer (e.g. `78`) so it composes in a `$(…)` substitution; without it, the default form is `AIVSS 78 (MEDIUM)` and the badge command will refuse the input with `Invalid value for 'SCORE'` ([`cli.py:1076-1108`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L1076-L1108)). Drop `badge.svg` into your README or status page.

## 7. Need a PDF?

The base install does not ship a PDF engine. The recommended path — works on every supported platform with no native deps — is the lightweight ReportLab fallback:

```bash
pip install 'agent-guardian[pdf-fallback]'
agent-guardian report "$SCAN_ID" --output pdf --output-path report.pdf
```

The richer WeasyPrint engine is available under `[full]` but needs Pango, Cairo, and HarfBuzz on the system. On macOS:

```bash
brew install pango cairo harfbuzz
# WeasyPrint sometimes can't find the Homebrew dylibs at import time;
# if 'doctor' or the scan still warns, point the loader at them:
export DYLD_FALLBACK_LIBRARY_PATH="$(brew --prefix)/lib:${DYLD_FALLBACK_LIBRARY_PATH-}"
pip install 'agent-guardian[full]'
```

On Debian/Ubuntu use `apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libcairo2 …` — full list in the [FAQ entry on WeasyPrint](../faq/index.md#pip-install-agent-guardianfull-fails-on-weasyprint-native-deps).

If the WeasyPrint deps aren't available and you still want PDF, `[pdf-fallback]` is always a safe fallback.

## What next

<div class="grid cards" markdown>

- :material-cog: __How the swarm works__

    Eleven agents, one Commander, shared memory. The technical tour.

    [Architecture →](../concepts/architecture.md)

- :material-test-tube: __Try a real demo__

    LangGraph, OpenAI Agents, vulnerable-by-design fixtures.

    [Examples gallery →](../examples/index.md)

- :material-source-branch: __Wire it into CI__

    GitHub Actions, SARIF upload, fail-the-build thresholds.

    [CI gate tutorial →](ci-gate.md)

</div>

Two questions everyone asks once: [Why does `verify` print `UNANCHORED`?](../faq/index.md#why-does-agent-guardian-verify-print-trust-anchor-unanchored) and [I see `EgressRefused` errors mid-scan](../faq/index.md#egressrefused).
