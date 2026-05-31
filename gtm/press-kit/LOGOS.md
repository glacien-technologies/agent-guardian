# Logo assets

The canonical logo files live in the docs directory so the Mintlify
site and the press kit share a single source of truth. Do not copy
them into `gtm/press-kit/` — link to them from here.

## Files

| Variant            | Path                                  | Use                                      |
| ------------------ | ------------------------------------- | ---------------------------------------- |
| Logomark, light    | `docs/images/logo-light.svg`          | Dark backgrounds                         |
| Logomark, dark     | `docs/images/logo-dark.svg`           | Light backgrounds                        |
| Favicon            | `docs/images/favicon.svg`             | Browser tabs, PWA icons                  |

## Public URLs (stable, suitable for embed)

- Light: https://raw.githubusercontent.com/glacien-technologies/agent-guardian/main/docs/images/logo-light.svg
- Dark: https://raw.githubusercontent.com/glacien-technologies/agent-guardian/main/docs/images/logo-dark.svg
- Favicon: https://raw.githubusercontent.com/glacien-technologies/agent-guardian/main/docs/images/favicon.svg

## Brand rules

- The logomark may be reproduced at any size at or above 24 px.
- Do not recolour. The mark is purple (#8B5CF6, matching the Mintlify
  theme `primary`); the docs theme owns the colour spec.
- Do not stretch, distort, rotate, or add effects (drop shadows,
  glows, gradients).
- Minimum clear space around the mark equals the height of the "A"
  in "AgentGuardian".
- For newsletter inclusions, the dark variant on a white background
  is the default.

## Logo licence

The AgentGuardian wordmark and logomark are licensed under
[CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/) for
editorial use (newsletter inclusions, conference programmes, news
coverage). Commercial reuse requires written permission —
trademarks@glacien.ai. The full trademark policy is at TRADEMARKS.md
in the repository root.

## Embedding example

```html
<img
  src="https://raw.githubusercontent.com/glacien-technologies/agent-guardian/main/docs/images/logo-dark.svg"
  alt="AgentGuardian"
  width="200"
  height="40"
/>
```
