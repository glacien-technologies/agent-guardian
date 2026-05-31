# Launch posts — live tracking sheet

Append one row per channel post. Update the metrics column at T+24 h
and again at T+7 d. Never delete a row, even if a post gets flagged
or removed — record the outcome in the notes column instead.

## Schema

| Channel | URL | Posted (UTC) | Variant | Status | Upvotes @ 24h | Upvotes @ 7d | Notes |

## Posts

| Channel | URL | Posted (UTC) | Variant | Status | Upvotes @ 24h | Upvotes @ 7d | Notes |
| ------- | --- | ------------ | ------- | ------ | ------------- | ------------ | ----- |
|         |     |              |         |        |               |              |       |

## Aggregate metrics

| Metric                            | Target  | T+24h | T+7d | T+30d |
| --------------------------------- | ------- | ----- | ---- | ----- |
| HN upvotes                        | > 200   |       |      |       |
| Reddit combined upvotes (5 subs)  | > 100   |       |      |       |
| Product Hunt upvotes              | > 500   |       |      |       |
| Product Hunt rank                 | top 5   |       |      |       |
| GitHub stars (delta from T-0)     | > 50    |       |      |       |
| PyPI downloads (delta from T-0)   | > 500   |       |      |       |
| Newsletter inclusions (confirmed) | > 3     |       |      |       |

## Notes for whoever fills this

- "Status" is one of `live`, `flagged`, `removed`, `archived`.
- "Variant" is the file under `channels/` you used.
- If a post is flagged on HN, log it as `flagged` and do not repost.
  HN moderators reject reposted content; the second submission gets
  the account flagged too. Lessons learned go in `metrics.md`.
- Star and download counts are taken from
  `gh api repos/glacien-technologies/agent-guardian --jq .stargazers_count`
  and `pypistats overall agent-guardian --json` respectively.
