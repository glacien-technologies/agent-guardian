# Metrics + kill-switch criteria

## Success metrics (locked at T-0)

| Metric                              | Floor   | Target  | Stretch |
| ----------------------------------- | ------- | ------- | ------- |
| HN upvotes @ 24 h                   | 100     | 200     | 500     |
| Reddit combined upvotes @ 7 d       | 50      | 100     | 300     |
| Product Hunt upvotes @ 24 h         | 200     | 500     | 1 000   |
| Product Hunt rank @ 24 h            | top 10  | top 5   | #1      |
| GitHub stars delta @ 48 h           | 25      | 50      | 200     |
| PyPI downloads delta @ 7 d          | 200     | 500     | 2 000   |
| Newsletter inclusions @ 14 d        | 1       | 3       | 5       |
| LinkedIn impressions @ 7 d          | 5 000   | 20 000  | 100 000 |
| X thread retweets @ 7 d             | 20      | 50      | 200     |

"Floor" = launch did not embarrass the project. "Target" = the
research-brief-locked success criteria. "Stretch" = unusually good
outcome that justifies follow-up content (lessons-learned blog,
"what we learned" thread, conference submission).

## Kill-switch criteria (decide before launching, not during)

If any of the following hits, **pause the next scheduled channel
post** and reconvene before continuing:

1. **HN post is flagged within 1 h.** Do not resubmit the HN post.
   Move the HN narrative to a Show HN attempt 6 weeks later with a
   different angle (a specific deep-dive finding, not the launch
   itself).

2. **Reddit shadow-ban detected.** Symptom: post shows 0 views in
   the sub feed after 30 min, while logged into another account.
   Stop posting to other subs from the same account for 7 days. Use
   a co-maintainer's account for the remaining subs.

3. **Product Hunt removed from the daily list.** PH moderators
   occasionally pull posts they decide are off-mission. If this
   happens, the founder emails PH staff with the testbench link and
   a 100-word explanation of why the tool is genuinely Apache-2.0
   OSS; do not resubmit.

4. **A critical bug surfaces in a comment.** Stop replying to non-
   bug comments. File the issue, ship the fix in v1.0.1 within 48 h,
   reply to the original commenter with the issue link. Resume
   normal engagement after the fix is tagged.

5. **A security-critical CVE surfaces.** Stop all launch activity.
   Trigger the SECURITY.md disclosure process. Do not resume
   marketing until the CVE has a CVE-ID and a fix.

## What to do after T+7

Roll the metrics up in `launch-posts.md`. Decide:

- If **target hit on >= 3 metrics**: write the "lessons learned"
  follow-up. Submit AIVSS methodology to arXiv (the pre-print is
  already drafted at `docs/site/arxiv-preprint.html`). Begin the
  GTM-006 awesome-list PRs.

- If **floor missed on >= 3 metrics**: do not run a second launch
  cycle. Write a private retrospective. Focus the next 30 days on
  product quality (more frameworks, sharper testbench, faster scan)
  rather than distribution. Re-launch on a milestone (v1.1, a major
  framework adapter, a notable finding) rather than a calendar date.

- If **mixed**: ship the lessons-learned post and the awesome-list
  PRs but do not run a second paid attention cycle.

## Data sources

- HN upvote count: `https://hn.algolia.com/api/v1/items/{{ story_id }}`
- Reddit upvote count: `praw` or the `.json` endpoint on the post URL
- Product Hunt rank: PH GraphQL API
  (https://api.producthunt.com/v2/api/graphql)
- GitHub stars: `gh api repos/glacien-technologies/agent-guardian
  --jq .stargazers_count`
- PyPI downloads: `pypistats overall agent-guardian --json`
- LinkedIn impressions: LinkedIn Analytics on the founder post
- X retweets: X API or the thread URL's reply count
