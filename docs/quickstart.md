# Quickstart

Five minutes from `pip install` to your first signed scan report.

## 1. Install

```bash
pip install agent-guardian
```

Verify the installation:

```bash
agent-guardian doctor
```

The `doctor` command checks Python version, native deps for PDF rendering,
and any LLM credentials it can find in the environment.

## 2. Pick an LLM backend

AgentGuardian's Swarm Commander needs an LLM. Pick whichever you have a
key for:

=== "OpenAI"
    ```bash
    export OPENAI_API_KEY=sk-...
    ```
=== "Anthropic"
    ```bash
    export ANTHROPIC_API_KEY=sk-ant-...
    ```
=== "Stub (no API key)"
    ```bash
    # Use the deterministic stub backend — great for CI and demos.
    # Append --model stub to every scan command.
    ```

## 3. Scan a system prompt

The simplest target shape — paste your agent's system prompt into a file
and scan it directly.

```bash
echo "You are a helpful customer-support bot for ACME Corp. \
You can issue refunds up to \$50 and look up order history." > prompt.txt

agent-guardian scan --system-prompt prompt.txt
```

You will see live progress in the terminal: the recon agent maps the
target, then the ten ASI-aligned attackers fire in parallel under the
Swarm Commander. The scan ends with a one-line summary including the
AIVSS score, severity band, and finding count.

## 4. Open the live dashboard

```bash
agent-guardian serve
```

Then browse to <http://localhost:7474>. You will see the current scan in
flight, per-agent activity, and a live AIVSS gauge. The dashboard is
local-only by default — bind to `0.0.0.0` explicitly if you want it
reachable elsewhere.

## 5. Get a signed report and a badge

After the scan completes, AgentGuardian has emitted a JSON evidence pack
to `~/.agentguardian/scans/<scan-id>/`. The pack is signed with Ed25519
and HMAC-SHA256. The Ed25519 keypair is auto-generated on first use
under `~/.agentguardian/keys/` — back that directory up if you need to
re-sign or hand the public key to a remote verifier.

Verify the signature with the public key embedded in the report (this
is the "I produced this scan myself" path — see
[CLI — verify](cli.md#verify) for full trust-anchor semantics):

```bash
SCAN_ID=$(jq -r .last_scan_id ~/.agentguardian/state.json)
REPORT=~/.agentguardian/scans/"$SCAN_ID"/report.json
PUBKEY=$(jq -r .signatures.ed25519.public_key_b32 "$REPORT")
agent-guardian verify "$REPORT" --pubkey "$PUBKEY"
```

Running `verify` without `--pubkey` / `--pubkey-file` / `--secret`
yields a non-zero exit and prints `trust anchor: UNANCHORED` — a
signed report only proves the bytes were not tampered with, not who
produced it. Pin the publisher's pubkey out-of-band when you receive
reports from someone else.

Generate the marketing badge:

```bash
agent-guardian badge $(agent-guardian last-score) --svg > badge.svg
```

Or regenerate the report in a different format from the stored scan —
no need to re-run the swarm:

```bash
agent-guardian report "$SCAN_ID" --output md
```

Need a PDF? Install the PDF extra (`[full]` for WeasyPrint, or
`[pdf-fallback]` for the lighter ReportLab engine on systems where
WeasyPrint's native deps are awkward) and regenerate from the stored
scan:

```bash
pip install 'agent-guardian[full]'
agent-guardian report "$SCAN_ID" --output pdf --output-path report.pdf
```

That's it — under five minutes, and you have a deterministic, signed,
standards-aligned AIVSS score for your agent.

## What next

- [Architecture](architecture.md) — how the swarm actually works.
- [Adapters](adapters/index.md) — scan a running HTTP endpoint, a
  LangGraph / CrewAI / AutoGen agent, or raw Python source.
- [AIVSS formula](aivss-formula.md) — read the formula and weights, and
  compute a score by hand on the supplied fixture.
