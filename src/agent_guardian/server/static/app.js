/* AgentGuardian dashboard entrypoint — vanilla ES2022 module.
 *
 * Pages that need live state attach via `data-` attributes:
 *
 *   - `[data-scan-id]` — the scan view subscribes to SSE.
 *   - `[data-radar]`   — the AIVSS page renders the radar chart.
 *
 * The two component modules are loaded lazily so pages without them
 * never pay the parse cost.
 */

import { mountScanView } from "./swarm.js";
import { mountRadar } from "./charts.js";

const scanRoot = document.querySelector("[data-scan-id]");
if (scanRoot instanceof HTMLElement) {
  const scanId = scanRoot.dataset.scanId;
  if (scanId) {
    mountScanView({ root: scanRoot, scanId });
  }
}

const radarRoots = document.querySelectorAll("[data-radar]");
for (const node of radarRoots) {
  if (node instanceof HTMLElement) {
    mountRadar(node);
  }
}
