# v1.0 Operator Pre-Flight Checklist

The M15 release-candidate (`1.0.0rc1`) is shippable from an engineering
standpoint — tests pass, CI is green, the wheel builds, docs publish.
What follows is the list of **manual** actions only a human operator
can take, in the order that minimises blast radius.

Each item has a status box. Tick it as you go.

---

## 1. Repository hardening

- [ ] **Branch protection on `main`.** GitHub → Settings → Branches.
      Require PR review, DCO check, CI green, linear history.
      Restrict force-pushes.
- [ ] **DCO App.** Install at <https://github.com/apps/dco> against
      `glacien-technologies/agent-guardian`. The `dco.yml` workflow
      already exists; the app makes sign-off mandatory on every PR.
- [ ] **GitHub Pages.** Verify deployment from `gh-pages` (M14's
      `docs.yml` already configured this) — visit
      <https://glacien-technologies.github.io/agent-guardian/>.

## 2. PyPI publishing

- [ ] **Trusted Publisher.** <https://pypi.org/manage/account/publishing/>.
      Add a pending publisher for `agent-guardian` linked to
      `glacien-technologies/agent-guardian`, workflow `publish.yml`,
      environment `pypi`.
- [ ] **Name reservation.** After the first `1.0.0` wheel uploads,
      reserve **both** `agent-guardian` and `agent_guardian` defensively
      — PyPI normalises both forms but typosquatters might not.
- [ ] **Push the tag.** `git push origin v1.0.0rc1` will fire
      `publish.yml`. **Only do this after** Trusted Publisher is
      configured, otherwise the upload step will fail.

## 3. Release engineering

- [ ] **GitHub Release.** `gh release create v1.0.0rc1 \
        --title "agent-guardian 1.0.0rc1" \
        --notes-file CHANGELOG.md \
        --prerelease \
        dist/agent_guardian-1.0.0rc1-py3-none-any.whl \
        dist/agent_guardian-1.0.0rc1.tar.gz`
- [ ] **Signed artefacts.** Confirm both wheel and sdist were attached
      and that the `publish.yml` Sigstore step produced a `.sigstore`
      transparency log entry per build.

## 4. Soft-beta cohort

- [ ] **Invite the 10 researchers** identified in PRD §17.3 W-2. Send
      them: a fresh PyPI install link, a "scan one of your agents,
      send us the JSON" prompt, and the disclosure template.
- [ ] **Track findings.** Create a private GitHub project board for
      W-2 beta intake. Triage and bin findings by ASI category.
- [ ] **Refresh probe corpus.** Anything novel from the cohort goes
      into `src/agent_guardian/probes/asiNN/…` for `1.0.1`.

## 5. Research artefact

- [ ] **arXiv submission.** Once the beta cohort produces 30+ findings
      across at least three different targets, fill in §6 of
      `docs/arxiv-preprint.md`, regenerate figures, and submit to
      arXiv `cs.CR`. Cross-list `cs.LG`.
- [ ] **Citation file.** Verify `CITATION.cff` matches the arXiv DOI
      once issued.

## 6. Public infrastructure (Glacien edge)

- [ ] **`agentguardian.ai/leaderboard`** endpoint deploy. Once live,
      replace the placeholder in `cli.publish` with a real POST.
- [ ] **`badge.agentguardian.ai`** shield endpoint deploy. The
      `agent-guardian badge --svg` output is the canonical artefact;
      the edge endpoint just caches it per scan ID.

## 7. Legal / brand

- [ ] **Singapore trademark filing** (Class 9 + 42) per PRD §12.4.
      Engage IP counsel; cite the public release as priority date.
- [ ] **`agentguardian.ai`** domain — DNS, TLS, redirect from
      `agent-guardian.ai` and `agentguardian.io`.

## 8. Promotion of `1.0.0rc1` → `1.0.0`

Once the soft-beta wave concludes (target: 2026-08-01) and no critical
findings remain open:

- [ ] Bump `src/agent_guardian/_version.py` to `1.0.0`.
- [ ] Bump `CITATION.cff` version + `date-released`.
- [ ] Append a `[1.0.0]` section to `CHANGELOG.md` summarising any
      `rc1 → 1.0.0` changes (probably just probe-corpus updates from
      the beta intake).
- [ ] Tag `v1.0.0` and push. `publish.yml` will upload to PyPI for
      real.

---

*If something on this list slips, it's a release-blocker, not a v1.x
follow-up. Don't paper over.*
