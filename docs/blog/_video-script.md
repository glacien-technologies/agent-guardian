# GTM-007 Demo Video — Recording Script

Operator-facing recording script for the 60–90s launch demo video. This file is **not** linked from the Mintlify nav (it lives under `docs/blog/` so it travels with the asset, but the `_` prefix excludes it from the build). The leading underscore matches the convention already used by `docs/_design/`.

## Owner

Human (founder voice). Claude can re-edit copy but does not produce the recording.

## Target

- **Length:** 60–90 seconds. Hard cap 95 seconds.
- **Format:** 1080p, H.264, mp4. 16:9.
- **Audio:** real human voice (founder or core maintainer). Do **not** use synthetic TTS for the launch cut.
- **Tone:** technical, direct, no marketing fluff. The same tone as the docs.
- **Hosting:** YouTube (Unlisted pre-launch, flip to Public on launch day). Channel: Glacien Technologies (or a per-project channel if one is set up).

## Pre-flight

```bash
# 1. Confirm testbench is up
curl https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app/health

# 2. Install latest agent-guardian into a clean venv
python -m venv /tmp/agentguardian-demo-venv
source /tmp/agentguardian-demo-venv/bin/activate
pip install --upgrade agent-guardian
agent-guardian --version   # should report 1.1.0 or later

# 3. Export the LLM key — do NOT show this on screen
export GEMINI_API_KEY=...   # set in shell, do not include in the cap

# 4. Pre-warm the dashboard
agent-guardian serve &
DASHBOARD_PID=$!
sleep 1
curl -s http://127.0.0.1:7474/health
```

Recording app: QuickTime Player (macOS, File -> New Screen Recording) or OBS. Capture at 1080p. Hide the menu bar (`defaults write NSGlobalDomain _HIHideMenuBar -bool true; killall Finder`) before starting.

## Scene-by-scene

### Scene 1 — Title card (0:00–0:05, 5s)

Static black slide with the AgentGuardian wordmark (`docs/images/logo-dark.svg`). Overlay one line: **"Red team your AI agents in 90 seconds."**

Voiceover:

> "AgentGuardian — open source red-teaming for AI agents. Here's the 90-second demo."

### Scene 2 — The vulnerable agent (0:05–0:15, 10s)

Terminal full-screen. Run the testbench healthcheck and show the five agents:

```bash
curl https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app/health | jq .
```

Voiceover:

> "This is our hosted testbench. Five demo agents — one clean, four planted with real OWASP-LLM vulnerabilities. We'll attack `finbot`, the banking assistant."

### Scene 3 — Run the scan (0:15–0:50, 35s)

Type the scan command live. Do **not** paste — typing reads as real.

```bash
agent-guardian scan \
  --endpoint https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app/finbot/chat \
  --model gemini:gemini-2.5-flash \
  --mode fast \
  --budget-usd 0.20
```

Press enter. Within a second two dashboard URLs appear. Speed the recording 2x through the swarm progress lines (most editors support a clip-speed multiplier; keep the per-agent `findings=` lines readable).

Voiceover during the run:

> "One command. Fourteen specialist attackers run in parallel against the agent — goal hijack, tool abuse, memory poisoning, secret extraction, the OWASP ASI categories. They share findings through an adversarial memory store, so multi-hop attacks compose. A live dashboard wires up before the swarm fires."

When the summary line lands, slow back to 1x and let the viewer read it:

```text
scan cli-XXXX done: AIVSS=23 band=CRITICAL tier=T1 findings=14 report=scan.json
```

Voiceover:

> "AIVSS 23, critical band, fourteen findings. Ninety seconds wall-clock, about a cent of Gemini Flash."

### Scene 4 — Open the report (0:50–1:10, 20s)

Open the HTML report in the live dashboard (browser tab). Scroll to one finding — show:

- the attacker prompt,
- the agent's verbatim reply,
- the OWASP ASI category badge,
- the MITRE ATLAS technique,
- the PoV reliability number.

Voiceover:

> "Every finding ships with the verbatim attack prompt, the agent's reply, the OWASP ASI category, the MITRE ATLAS technique, and a proof-of-vulnerability reliability score. The PoV is replayed against the target before the finding survives, so single-shot hallucinations don't land in the report."

### Scene 5 — Mitigation + re-run (1:10–1:25, 15s)

Back to the terminal. Run the scan against the `clean_control` agent (the testbench's hardened control):

```bash
agent-guardian scan \
  --endpoint https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app/clean_control/chat \
  --model gemini:gemini-2.5-flash \
  --mode fast \
  --budget-usd 0.20
```

Speed 4x through the run. Land on the summary:

```text
scan cli-YYYY done: AIVSS=96 band=EXCELLENT tier=T4 findings=0 report=scan.json
```

Voiceover:

> "Same swarm, same flags, the hardened agent. AIVSS 96, zero findings. The 73-point swing is the credibility evidence — the scan found a real defect on the vulnerable agent and confirms a clean control."

### Scene 6 — Outro (1:25–1:30, 5s)

Static slide. Three lines:

- `pip install agent-guardian`
- `agentguardian.io/quickstart`
- `github.com/glacien-technologies/agent-guardian`

Voiceover:

> "Apache 2.0. No telemetry. Local-first. Install it, scan your own agent, file an issue if you find a gap."

## YouTube metadata

**Title:**

```
AgentGuardian — open-source red-teaming for AI agents (90s demo)
```

**Description:**

```
AgentGuardian is an open-source, Apache-2.0, local-first red-teaming toolkit for AI agents. Point it at your LangGraph, CrewAI, MCP server, RAG app, or REST-API agent and it deploys a swarm of fourteen specialist attackers, produces a deterministic AIVSS score mapped to OWASP ASI 2026 / MITRE ATLAS v5.4 / CSA, and emits SARIF / JSON / JUnit / Markdown / PDF reports your CI can gate on.

In this 90-second demo:
- 0:05  the hosted testbench
- 0:15  one-command scan against the FinBot banking agent
- 0:50  reading the report — OWASP / ATLAS / PoV reliability
- 1:10  re-scan against the hardened control — zero findings

Try it:
  pip install agent-guardian

Docs: https://agentguardian.io
Quickstart: https://agentguardian.io/quickstart
Source: https://github.com/glacien-technologies/agent-guardian
Testbench: https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

Apache 2.0. No telemetry. Local-first.
```

**Tags:**

```
ai security, ai agents, llm security, prompt injection, red team, owasp, mitre atlas, langgraph, crewai, mcp, rag security, open source
```

**Visibility:** Unlisted until launch day; flip to Public when GTM-008 fires.

## Post-recording checklist

- [ ] Length verified (60–90s window; hard cap 95s).
- [ ] No API keys, env vars, or local paths visible in any frame.
- [ ] Sound levels normalised (voice peaks ~ -3 dB; no clipping).
- [ ] Closed captions auto-generated and reviewed for accuracy (YouTube Studio -> Subtitles).
- [ ] Thumbnail uploaded — 1280x720, AgentGuardian wordmark + "90-second demo" overlay.
- [ ] Public URL captured into `GTM_TASKS.md` GTM-007 status line.
- [ ] Public URL pasted into `README.md` Demo section (Edit operation in this plan).
- [ ] Public URL pasted into `docs/blog/introducing-agentguardian.mdx` (already references `README.md#demo` — refresh if a direct URL is preferred).
