# Dev.to + Medium repost

**Target time:** T+1 (Dev.to) and T+2 (Medium). Stagger by 24 h to
avoid the "duplicate content" filter on both platforms.
**Source:** the launch blog at `docs/blog/introducing-agentguardian.mdx`
(owned by GTM-007). This file specifies the repost wrapper and
metadata only — the body comes verbatim from the canonical blog.

## Dev.to

**URL:** https://dev.to/new

### Title

```
Introducing AgentGuardian: open-source red teaming for AI agents
```

### Tags (Dev.to allows 4)

```
opensource, security, ai, python
```

### Canonical URL (mandatory — protects SEO)

```
https://agentguardian.io/blog/introducing-agentguardian
```

### Cover image

`docs/_assets/blog/introducing-agentguardian-cover.png` (1000 × 420,
provided by GTM-007).

### Body

Paste verbatim from `docs/blog/introducing-agentguardian.mdx`
(skipping the MDX frontmatter). Add this footer:

```
---

> This post was first published on the AgentGuardian blog. If you
> spot anything wrong — a broken link, a scan command that no longer
> works, an ASI mapping you disagree with — open an issue at
> https://github.com/glacien-technologies/agent-guardian/issues.
>
> Live testbench: https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app
> Walkthrough video: {{ YOUTUBE_DEMO_URL }}
```

## Medium

**URL:** https://medium.com/new-story

### Title

```
Introducing AgentGuardian: open-source red teaming for AI agents
```

### Tags (Medium allows 5)

```
AI Security, Open Source, DevSecOps, LLM, Cybersecurity
```

### Canonical URL

```
https://agentguardian.io/blog/introducing-agentguardian
```

### Publish target

The Glacien Medium publication, not the founder's personal Medium.
Publications get ~2x more "Member" reads than personal blogs.

### Body

Same body as Dev.to. Medium strips MDX components, so swap any
`<Card>` / `<CardGroup>` blocks for the equivalent plain Markdown
table (the GTM-007 blog ships both renderings).

## Important: do NOT post the same body to both before the canonical
URL is live on agentguardian.io

If `https://agentguardian.io/blog/introducing-agentguardian` 404s when
you post, Dev.to and Medium will index the repost itself as canonical
and the agentguardian.io blog will lose all the SEO juice forever.
Verify the canonical URL responds 200 before posting either repost.
