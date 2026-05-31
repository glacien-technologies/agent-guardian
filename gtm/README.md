# gtm/ — AgentGuardian launch operational kit

This directory holds the **distribution execution** artifacts for GTM-008:
tone-locked channel copy, the launch-day stagger schedule, response
templates for live engagement, the newsletter outreach pack, and the
live tracking sheet that records every post + its traction.

Authoring of the *content* the launch points at — the demo video, the
launch blog, the deep-dive, the comparison page, the walkthrough — is
owned by GTM-007 and ships under `docs/blog/` (Mintlify). The
vulnerable-agent docker-compose story is owned by GTM-003. This
directory contains only the distribution layer on top of those assets.

## Layout

| File                            | Purpose                                                                 |
| ------------------------------- | ----------------------------------------------------------------------- |
| `launch-posts.md`               | The single source of truth. One row per channel post; updated live.     |
| `launch-schedule.md`            | The staggered day-by-day launch sequence with UTC timestamps.           |
| `tone-rules.md`                 | The non-negotiable voice rules every post must satisfy.                 |
| `channels/hn-show-hn.md`        | Hacker News submission copy (title + body + first comment).             |
| `channels/reddit-localllama.md` | r/LocalLLaMA post copy.                                                 |
| `channels/reddit-machinelearning.md` | r/MachineLearning post copy (research-tone variant).              |
| `channels/reddit-cybersecurity.md`   | r/cybersecurity post copy.                                        |
| `channels/reddit-netsec.md`     | r/netsec post copy (link-only post format).                             |
| `channels/reddit-llmdevs.md`    | r/LLMDevs post copy.                                                    |
| `channels/product-hunt.md`      | Product Hunt tagline + first comment + maker reply pack.                |
| `channels/linkedin-founder.md`  | LinkedIn founder long-form post.                                        |
| `channels/x-thread.md`          | X / Twitter 5-tweet launch thread.                                      |
| `channels/devto-medium.md`      | Dev.to + Medium repost canonical form.                                  |
| `channels/github-release.md`    | GitHub Release announcement body for the `v1.0.0` tag.                  |
| `channels/owasp-langchain-mcp.md` | Community-channel pings (OWASP GenAI Slack, LangChain Discord, MCP).  |
| `newsletter-outreach.md`        | The newsletter list + the cold-email template + the teaser library.    |
| `response-templates.md`         | Copy-paste replies for the 12 most common comments.                     |
| `metrics.md`                    | The success criteria + the kill-switch criteria.                        |

## How to use

1. Read `tone-rules.md` first. Every line of copy in `channels/` already
   complies — do not edit copy in a way that violates the rules.
2. Follow `launch-schedule.md` in order. Each row has a UTC timestamp,
   a channel, a file to copy-paste from, and a verification step.
3. After every post, append a row to `launch-posts.md` with the URL,
   timestamp, and current upvote / star count.
4. When new comments come in, find the closest match in
   `response-templates.md` and personalise the second sentence before
   replying. Never paste a template verbatim.

## What success looks like

The locked metrics — HN >200 upvotes, Reddit combined >100 upvotes,
Product Hunt >500 upvotes or Ship of the Day, 50+ GitHub stars in 48h —
live in `metrics.md`. The kill-switch criteria (when to pause and
reassess) live there too.
