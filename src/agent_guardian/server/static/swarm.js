/* Swarm view — SSE subscription + SVG topology updates.
 *
 * Exports `mountScanView({ root, scanId })`. The function:
 *
 *   - Positions the eleven satellite nodes radially around a fixed
 *     centre using a deterministic angle slot (slot index 0..10).
 *   - Opens an EventSource against `/scan/{scanId}/events`.
 *   - Dispatches each event kind to a small handler that updates the
 *     score, event log, and per-satellite state.
 */

const CENTER_X = 400;
const CENTER_Y = 400;
const SATELLITE_RADIUS = 280;

/**
 * Mount the live scan view on a root element.
 * @param {{ root: HTMLElement, scanId: string }} params
 */
export function mountScanView({ root, scanId }) {
  // Wire up the SVG topology if one is present on this page.
  positionSatellites();

  const aivssLabel = document.querySelector(".aivss-live");
  const aivssTargetLabel = document.querySelector(".target-aivss");
  const findingsCounter = document.querySelector(".findings-counter");
  const statusMessage = document.querySelector(".status-message");
  const eventLog = document.querySelector(".event-log");
  const progressBar = document.querySelector(".progress-bar");

  // Map of agent slug → SVG <g> node.
  const satellites = new Map();
  document.querySelectorAll(".satellite[data-agent]").forEach((node) => {
    if (node instanceof SVGElement) {
      const agent = node.getAttribute("data-agent");
      if (agent) satellites.set(agent, node);
    }
  });

  // Findings accumulator (scan-wide).
  let totalFindings = 0;

  const sourceUrl = `/scan/${encodeURIComponent(scanId)}/events`;
  const source = new EventSource(sourceUrl);

  // SSE Phase 1, Step 5 — share this EventSource with the global
  // freshness dot. The dot reads ``readyState`` on every rAF tick and
  // routes ``heartbeat`` / ``scan_done`` / ``deadline_approaching`` to
  // the four-state LIVE / STALE / RECONNECTING / DEAD machine. The
  // previously CLOSED-only ``error`` handler below is retained ONLY to
  // surface the local Swarm-view status message; freshness state lives
  // on the dot.
  if (
    typeof window !== "undefined" &&
    window.AGFreshnessDot &&
    typeof window.AGFreshnessDot.attach === "function"
  ) {
    window.AGFreshnessDot.attach(source, { url: sourceUrl });
  }

  const appendEvent = (kind, agent, detail) => {
    if (!eventLog) return;
    const li = document.createElement("li");
    const kindSpan = document.createElement("span");
    kindSpan.className = "ev-kind";
    kindSpan.textContent = kind;
    const agentSpan = document.createElement("span");
    agentSpan.className = "ev-agent";
    agentSpan.textContent = agent || "—";
    const detailSpan = document.createElement("span");
    detailSpan.className = "ev-detail";
    detailSpan.textContent = detail || "";
    li.append(kindSpan, agentSpan, detailSpan);
    eventLog.prepend(li);
    // Cap the log at 200 entries — runaway scans shouldn't grow the DOM.
    while (eventLog.children.length > 200) {
      eventLog.removeChild(eventLog.lastChild);
    }
  };

  const setSatelliteState = (slug, state) => {
    const node = satellites.get(slug);
    if (node) node.setAttribute("data-state", state);
  };

  const bumpFinding = (slug) => {
    const node = satellites.get(slug);
    if (!node) return;
    node.classList.add("pulse");
    setTimeout(() => node.classList.remove("pulse"), 1000);
    const counter = node.querySelector(".finding-count");
    if (counter instanceof SVGElement) {
      const current = Number(counter.dataset.count || "0") + 1;
      counter.dataset.count = String(current);
      counter.textContent = String(current);
      node.setAttribute("data-finding", "true");
    }
  };

  const safeParse = (raw) => {
    try {
      return JSON.parse(raw);
    } catch (err) {
      return null;
    }
  };

  source.addEventListener("recon_start", (e) => {
    const data = safeParse(e.data) || {};
    setSatelliteState(data.agent || "recon-agent", "running");
    appendEvent("recon_start", data.agent, "");
  });

  source.addEventListener("recon_done", (e) => {
    const data = safeParse(e.data) || {};
    setSatelliteState(data.agent || "recon-agent", "done");
    appendEvent("recon_done", data.agent, "");
  });

  source.addEventListener("agent_start", (e) => {
    const data = safeParse(e.data) || {};
    setSatelliteState(data.agent, "running");
    appendEvent("agent_start", data.agent, data.asi || "");
  });

  source.addEventListener("agent_progress", (e) => {
    const data = safeParse(e.data) || {};
    appendEvent("agent_progress", data.agent, "");
  });

  source.addEventListener("agent_done", (e) => {
    const data = safeParse(e.data) || {};
    setSatelliteState(data.agent, "done");
    const payload = data.payload || {};
    const summary = `findings=${payload.findings_count ?? 0} turns=${payload.turns ?? 0}`;
    appendEvent("agent_done", data.agent, summary);
  });

  source.addEventListener("agent_skipped", (e) => {
    const data = safeParse(e.data) || {};
    setSatelliteState(data.agent, "skipped");
    appendEvent("agent_skipped", data.agent, "");
  });

  source.addEventListener("finding", (e) => {
    const data = safeParse(e.data) || {};
    bumpFinding(data.agent);
    totalFindings += 1;
    if (findingsCounter) findingsCounter.textContent = String(totalFindings);
    appendEvent("finding", data.agent, data.asi || "");
  });

  source.addEventListener("aivss_update", (e) => {
    const data = safeParse(e.data) || {};
    const score = data.score ?? data.provisional_aivss;
    const band = data.band;
    if (score !== undefined && aivssLabel) {
      aivssLabel.textContent = String(score);
      if (band) aivssLabel.setAttribute("data-band", band);
    }
    if (score !== undefined && aivssTargetLabel) {
      aivssTargetLabel.textContent = String(score);
    }
    appendEvent("aivss_update", null, `score=${score} band=${band || "?"}`);
  });

  source.addEventListener("checkpoint", (e) => {
    const data = safeParse(e.data) || {};
    if (data.provisional_aivss !== null && data.provisional_aivss !== undefined) {
      if (aivssLabel) aivssLabel.textContent = String(data.provisional_aivss);
      if (aivssTargetLabel) aivssTargetLabel.textContent = String(data.provisional_aivss);
    }
    appendEvent("checkpoint", null, `decision=${data.decision || "continue"}`);
  });

  source.addEventListener("scan_done", (e) => {
    const data = safeParse(e.data) || {};
    const payload = data.payload || {};
    if (payload.aivss !== undefined && aivssLabel) {
      aivssLabel.textContent = String(payload.aivss);
      aivssLabel.classList.add("final");
    }
    if (payload.aivss !== undefined && aivssTargetLabel) {
      aivssTargetLabel.textContent = String(payload.aivss);
    }
    if (statusMessage) statusMessage.textContent = "complete";
    if (progressBar instanceof HTMLElement) progressBar.style.animationPlayState = "paused";
    appendEvent("scan_done", null, `aivss=${payload.aivss} findings=${payload.findings ?? 0}`);
    source.close();
  });

  source.addEventListener("error", () => {
    // SSE Phase 1, Step 5 — the four-state freshness machine on
    // ``window.AGFreshnessDot`` owns the global LIVE/STALE/
    // RECONNECTING/DEAD visualisation. We keep the Swarm-view local
    // status text as a thin shim only when the freshness dot is NOT
    // mounted (eg the dashboard's standalone Swarm view sub-page),
    // otherwise the dot+banner are the single source of operator
    // truth and this handler is a no-op.
    if (
      typeof window !== "undefined" &&
      window.AGFreshnessDot &&
      typeof window.AGFreshnessDot.attach === "function"
    ) {
      return;
    }
    if (source.readyState === EventSource.CLOSED) {
      if (statusMessage) statusMessage.textContent = "disconnected";
    }
  });
}

/**
 * Position the eleven satellite groups around the centre using radial
 * slots — deterministic, no overlap, identical layout for every scan.
 */
function positionSatellites() {
  const satellites = document.querySelectorAll(".satellite[data-slot]");
  const total = satellites.length || 11;
  satellites.forEach((node) => {
    if (!(node instanceof SVGElement)) return;
    const slot = Number(node.getAttribute("data-slot")) || 0;
    const angleDeg = -90 + (360 * slot) / total;
    const angleRad = (Math.PI * angleDeg) / 180;
    const cx = CENTER_X + SATELLITE_RADIUS * Math.cos(angleRad);
    const cy = CENTER_Y + SATELLITE_RADIUS * Math.sin(angleRad);
    node.setAttribute("transform", `translate(${cx} ${cy})`);

    const link = node.querySelector(".link");
    if (link instanceof SVGElement) {
      // Line from the satellite's local origin back to the target.
      link.setAttribute("x1", "0");
      link.setAttribute("y1", "0");
      link.setAttribute("x2", String(CENTER_X - cx));
      link.setAttribute("y2", String(CENTER_Y - cy));
    }

    const label = node.querySelector(".agent-name");
    if (label instanceof SVGElement) {
      // Place label below or above the node based on its hemisphere.
      const ty = angleDeg > 0 ? 52 : -42;
      label.setAttribute("x", "0");
      label.setAttribute("y", String(ty));
    }

    const findingCount = node.querySelector(".finding-count");
    if (findingCount instanceof SVGElement) {
      findingCount.setAttribute("x", "22");
      findingCount.setAttribute("y", "-22");
    }
  });
}
