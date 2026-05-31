# Launch schedule (staggered, T-0 = Tuesday 00:01 UTC)

Launch day is a **Tuesday** because (a) Hacker News traffic peaks
Tuesday/Wednesday, (b) Product Hunt's daily reset happens at 00:01 UTC
and a Tuesday launch maximises US wake-up exposure, and (c) Reddit
weekday engagement runs ~30 % higher than weekend on the target subs.

Every row points at one file under `channels/`. Copy-paste, fill the
two `{{ }}` slots (video URL, your handle), post, then append a row to
`launch-posts.md` with the live URL and the timestamp.

## T-7 to T-1 (the week before)

| When         | What                                                  | File                         |
| ------------ | ----------------------------------------------------- | ---------------------------- |
| T-7          | Submit the Product Hunt launch (scheduled, not live)  | `channels/product-hunt.md`   |
| T-7          | Newsletter outreach email round 1 (5 targets)         | `newsletter-outreach.md`     |
| T-5          | Newsletter outreach email round 2 (next 5 targets)    | `newsletter-outreach.md`     |
| T-3          | Tag `v1.0.0` on `main` (triggers `publish.yml`)       | n/a — git tag                |
| T-2          | Verify PyPI upload, signed-release attestation        | n/a — verify only            |
| T-1 (Mon UTC)| Brief the maker / founder on the response window      | `response-templates.md`      |

## T-0 (launch day, all times UTC)

| UTC time | Channel                | File                                    | Verify                                       |
| -------- | ---------------------- | --------------------------------------- | -------------------------------------------- |
| 00:01    | Product Hunt           | `channels/product-hunt.md`              | Post is live; first comment posted by maker  |
| 06:00    | GitHub Release         | `channels/github-release.md`            | Release notes attached to `v1.0.0` tag       |
| 13:00    | Hacker News (Show HN)  | `channels/hn-show-hn.md`                | Post not flagged after 15 min                |
| 14:00    | LinkedIn (founder)     | `channels/linkedin-founder.md`          | Engagement > 5 reactions in first hour       |
| 15:00    | X / Twitter thread     | `channels/x-thread.md`                  | All 5 tweets in single thread                |
| 18:00    | r/LocalLLaMA           | `channels/reddit-localllama.md`         | Not auto-removed by AutoModerator            |

## T+1 (day after launch)

| UTC time | Channel                | File                                       |
| -------- | ---------------------- | ------------------------------------------ |
| 14:00    | r/MachineLearning      | `channels/reddit-machinelearning.md`       |
| 18:00    | Dev.to repost          | `channels/devto-medium.md`                 |

## T+2

| UTC time | Channel                | File                                       |
| -------- | ---------------------- | ------------------------------------------ |
| 14:00    | r/cybersecurity        | `channels/reddit-cybersecurity.md`         |
| 18:00    | Medium repost          | `channels/devto-medium.md`                 |

## T+3

| UTC time | Channel                | File                                       |
| -------- | ---------------------- | ------------------------------------------ |
| 14:00    | r/netsec               | `channels/reddit-netsec.md`                |
| 18:00    | OWASP GenAI Slack ping | `channels/owasp-langchain-mcp.md`          |

## T+4

| UTC time | Channel                | File                                       |
| -------- | ---------------------- | ------------------------------------------ |
| 14:00    | r/LLMDevs              | `channels/reddit-llmdevs.md`               |
| 18:00    | LangChain + MCP pings  | `channels/owasp-langchain-mcp.md`          |

## T+7 (one week post-launch)

| Action                                                                  |
| ----------------------------------------------------------------------- |
| Roll the metrics up in `metrics.md`. Decide go/no-go on the kill switch.|
| If HN cleared 200 upvotes — write the "lessons learned" follow-up post. |
| If HN flagged or <50 upvotes — see `metrics.md` kill-switch row.        |

## Why staggered

Posting the same link to five subreddits within an hour is the textbook
spam signal — AutoModerator on each sub catches it within minutes and
the founder account picks up a shadow-ban. A 24-hour stagger with
copy variants (already in `channels/`) clears every sub's
duplicate-content heuristic.
