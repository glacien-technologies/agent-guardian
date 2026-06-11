/* AgentGuardian — Executive theme charts (Theme D / QA-024).
 *
 * Mirrors narrative_charts.js: two Chart.js v4 charts plus a copy-button
 * helper. Class names + canvas IDs use the `exec-` prefix so the
 * Executive theme can be loaded side-by-side with Narrative without
 * collisions.
 *
 *   1. ASI radar — `#exec-asi-radar` — per-category Adversarial Surface
 *      Index. Reads its data from the canvas's `data-chart` JSON attr.
 *   2. Severity bar — `#exec-severity-bar` — horizontal finding counts
 *      by severity. Click on a bar scrolls smoothly to that severity's
 *      bucket inside the Findings tab. The handler bails when the
 *      anchor target isn't in the DOM (e.g. rendered on Overview),
 *      so the click is a safe no-op there.
 *
 * Helpers:
 *   - readToken(name)   — read a CSS custom property from :root.
 *   - withAlpha(hex, a) — blend a hex color with an alpha channel.
 *   - mountAsiRadar()   — instantiate the radar chart.
 *   - mountSeverityBar()— instantiate the severity bar chart.
 *   - mountCopyButtons()— copy-to-clipboard for the reproducibility
 *                         receipt's Copy button.
 *
 * Re-running `init()` after a partial DOM swap is safe — existing
 * Chart instances are destroyed before re-mount and copy-button
 * handlers are deduped via a `data-bound` flag.
 *
 * Zero dependencies beyond Chart.js v4 (loaded as a UMD script in
 * layout.html). No bundler step; ES2018 baseline.
 */
(function () {
  "use strict";

  /* ----------------------------------------------------------------- */
  /* CSS custom-property helpers                                       */
  /* ----------------------------------------------------------------- */

  function readToken(name) {
    var v = getComputedStyle(document.documentElement)
      .getPropertyValue(name);
    return (v || "").trim();
  }

  function withAlpha(hex, alpha) {
    if (!hex || hex.charAt(0) !== "#" || hex.length < 7) {
      return "rgba(139, 92, 246, " + alpha + ")";
    }
    var h = hex.replace("#", "");
    var r = parseInt(h.slice(0, 2), 16);
    var g = parseInt(h.slice(2, 4), 16);
    var b = parseInt(h.slice(4, 6), 16);
    if (isNaN(r) || isNaN(g) || isNaN(b)) {
      return "rgba(139, 92, 246, " + alpha + ")";
    }
    return "rgba(" + r + ", " + g + ", " + b + ", " + alpha + ")";
  }

  function parseChartPayload(canvas) {
    var raw = canvas.getAttribute("data-chart");
    if (!raw) { return null; }
    try {
      return JSON.parse(raw);
    } catch (_err) {
      return null;
    }
  }

  function destroyExisting(canvas) {
    if (!window.Chart || !Chart.getChart) { return; }
    var existing = Chart.getChart(canvas);
    if (existing) {
      existing.destroy();
    }
  }

  /* ----------------------------------------------------------------- */
  /* Chart: ASI radar                                                  */
  /* ----------------------------------------------------------------- */

  // QA-069 (2026-06-04) — module-scoped handle on the live radar instance so
  // the SSE snapshot subscriber can update its values in place (rather than
  // tearing the chart down and re-instantiating on every 500ms snapshot).
  var asiRadarChart = null;

  // QA-21 — map an ASI category score (0–100, higher == better defended) to a
  // vertex colour. A low score means more adversarial surface exposed, so it
  // reads in the severity palette: critical (<40), high (<70), else brand.
  function radarPointColor(v) {
    var n = typeof v === "number" ? v : parseFloat(v);
    if (isNaN(n)) { return readToken("--exec-brand") || "#8b5cf6"; }
    if (n < 40) { return readToken("--exec-sev-critical") || "#dc2626"; }
    if (n < 70) { return readToken("--exec-sev-high") || "#ea580c"; }
    return readToken("--exec-brand") || "#8b5cf6";
  }

  function mountAsiRadar() {
    if (!window.Chart) { return; }
    var canvas = document.getElementById("exec-asi-radar");
    if (!canvas) { return; }
    var payload = parseChartPayload(canvas);
    if (!payload || !Array.isArray(payload.labels) || !Array.isArray(payload.values)) {
      return;
    }
    destroyExisting(canvas);
    var brand = readToken("--exec-brand") || "#8b5cf6";
    var ink = readToken("--exec-ink") || "#1a1a1a";
    var grid = readToken("--exec-border-subtle") || "#e8e6e0";
    var bgElev = readToken("--exec-bg-elev") || "#ffffff";
    var subtle = readToken("--exec-ink-subtle") || "#8a8a8a";

    asiRadarChart = new Chart(canvas, {
      type: "radar",
      data: {
        labels: payload.labels,
        datasets: [
          {
            label: "Score",
            data: payload.values,
            fill: true,
            backgroundColor: withAlpha(brand, 0.18),
            borderColor: brand,
            // QA-21 — colour each vertex by its score band so a category in
            // the critical / high range stands out from the healthy ones
            // instead of every point reading as the same brand purple.
            pointBackgroundColor: payload.values.map(radarPointColor),
            pointBorderColor: bgElev,
            pointHoverBackgroundColor: bgElev,
            pointHoverBorderColor: brand,
            pointRadius: 4,
            pointHoverRadius: 6,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        // Drop aspectRatio:1 (was forcing a square) so the radar fills
        // the height of its grid cell — the side-by-side Overview pair
        // (FIG 1 bar + FIG 2 radar) must be visually balanced. The CSS
        // .exec-overview-twocol stretches both cards equally; this lets
        // the radar respect that stretch instead of locking itself to a
        // square.
        maintainAspectRatio: false,
        elements: { line: { borderWidth: 2 } },
        scales: {
          r: {
            suggestedMin: 0,
            suggestedMax: 100,
            ticks: {
              stepSize: 20,
              color: subtle,
              backdropColor: "transparent",
              font: { size: 11 },
            },
            angleLines: { color: grid },
            grid: { color: grid },
            pointLabels: {
              color: ink,
              /* QA-045 (2026-06-02) — extend the label gutter + bump the
                 font weight/size so the longer category strings (e.g.
                 "Privilege abuse", "Supply chain", "Cascading failure")
                 fit without truncation now that the enclosing card is
                 480 px square. Chart.js `padding` controls the gap
                 between the outermost ring and the labels — 14 px gives
                 the bottom-axis label clearance below the radial
                 envelope. */
              padding: 14,
              font: {
                family: readToken("--exec-font-sans") || "Inter, system-ui, sans-serif",
                size: 12,
                weight: "500",
              },
            },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: ink,
            titleColor: bgElev,
            bodyColor: bgElev,
            padding: 10,
            displayColors: false,
            callbacks: {
              label: function (ctx) {
                return ctx.parsed.r + " / 100";
              },
            },
          },
        },
      },
    });
  }

  // QA-069 (2026-06-04) — update the radar's values in place from a live
  // snapshot. ``values`` is aligned 1:1 with the rendered axis order
  // (``asi_radar`` in the snapshot == ``asi_rows`` order server-side). We only
  // touch the dataset data, never the labels, so the axis frame stays stable.
  function updateAsiRadar(values) {
    if (!asiRadarChart || !Array.isArray(values) || !values.length) { return; }
    var ds = asiRadarChart.data && asiRadarChart.data.datasets
      && asiRadarChart.data.datasets[0];
    if (!ds) { return; }
    // Defensive: only apply when the cardinality matches the rendered axes,
    // otherwise a mismatched array would silently distort the shape.
    if (asiRadarChart.data.labels && values.length !== asiRadarChart.data.labels.length) {
      return;
    }
    ds.data = values;
    // Keep the per-vertex severity colours (QA-21) in sync as scores move.
    ds.pointBackgroundColor = values.map(radarPointColor);
    asiRadarChart.update("none"); // no entry animation on a live tick
  }

  // QA-069 (2026-06-04) — subscribe to the per-scan ``/live`` snapshot stream
  // and repaint the radar as per-category scores arrive. Mirrors the
  // self-owned-EventSource pattern in phase-spine.js (each live widget owns its
  // own stream to the same endpoint; freshness-dot.js owns the connection
  // health UI). No-ops on terminal scans and when EventSource is unavailable.
  function attachRadarLive() {
    var body = document.body;
    if (!body) { return; }
    var scanId = body.getAttribute("data-scan-id");
    if (!scanId) { return; }
    if (body.getAttribute("data-is-terminal") === "true") { return; }
    var es = window.AGStreams && window.AGStreams.snapshot
      ? window.AGStreams.snapshot(scanId)
      : null;
    if (!es) { return; }
    es.addEventListener("snapshot", function (evt) {
      try {
        var data = JSON.parse(evt.data);
        if (data && data.asi_radar) { updateAsiRadar(data.asi_radar); }
      } catch (err) {
        try { console.error("AGRadarLive: snapshot apply failed", err); } catch (e) {}
      }
    });
  }

  /* ----------------------------------------------------------------- */
  /* Chart: severity bar                                               */
  /* ----------------------------------------------------------------- */

  function mountSeverityBar() {
    if (!window.Chart) { return; }
    /* Multi-canvas init — one Chart.js instance per `.exec-severity-bar-canvas`.
     * Overview and Findings each ship their own canvas with a tab-scoped id
     * (`exec-severity-bar-overview`, `exec-severity-bar-findings`) so both
     * panels render independently. Falls back to the legacy single-id lookup
     * for backwards compatibility with any template that hasn't been
     * migrated yet. */
    var canvases = document.querySelectorAll("canvas.exec-severity-bar-canvas");
    if (!canvases.length) {
      var legacy = document.getElementById("exec-severity-bar");
      if (!legacy) { return; }
      canvases = [legacy];
    }

    var ink = readToken("--exec-ink") || "#1a1a1a";
    var subtle = readToken("--exec-ink-subtle") || "#8a8a8a";
    var grid = readToken("--exec-border-subtle") || "#e8e6e0";
    var bgElev = readToken("--exec-bg-elev") || "#ffffff";
    var lastChart = null;

    canvases.forEach(function (canvas) {
      var payload = parseChartPayload(canvas);
      if (!payload || !Array.isArray(payload.rows)) { return; }
      /* Always tear down any prior Chart.js instance on this canvas before
       * remounting. Guards against duplicate listeners on HTMX swaps + tab
       * re-mounts (risk callout #1 in the design lock). */
      destroyExisting(canvas);

      var labels = payload.rows.map(function (r) {
        return r.label || (r.severity || "").toUpperCase();
      });
      var counts = payload.rows.map(function (r) { return r.count || 0; });
      var anchors = payload.rows.map(function (r) { return r.anchor; });
      var severities = payload.rows.map(function (r) { return r.severity; });
      // QA-13b — per-severity ASI breakdown for the hover tooltip. Each row's
      // ``asi`` is a list of {asi, count}; we pre-format the tooltip footer
      // lines once so the Chart.js callback stays a cheap lookup.
      var asiLines = payload.rows.map(function (r) {
        if (!Array.isArray(r.asi) || !r.asi.length) { return []; }
        return r.asi.map(function (e) {
          return "  " + e.asi + " · " + e.count;
        });
      });
      var colors = payload.rows.map(function (r) {
        return readToken("--exec-sev-" + r.severity) || "#8b5cf6";
      });

      var chart = new Chart(canvas, {
        type: "bar",
        data: {
          labels: labels,
          datasets: [
            {
              data: counts,
              backgroundColor: colors.map(function (c) { return withAlpha(c, 0.85); }),
              borderColor: colors,
              borderWidth: 1,
              borderRadius: 4,
              barThickness: 20,
            },
          ],
        },
        options: {
          indexAxis: "y",
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                color: subtle,
                font: { size: 11 },
                precision: 0,
              },
              grid: { color: grid },
            },
            y: {
              ticks: {
                color: ink,
                font: {
                  family: readToken("--exec-font-mono") || "monospace",
                  size: 11,
                  weight: "500",
                },
              },
              grid: { display: false },
            },
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: ink,
              titleColor: bgElev,
              bodyColor: bgElev,
              padding: 10,
              displayColors: false,
              callbacks: {
                /* Body: the count line, then one line per contributing ASI
                 * category. Lets an operator see at a glance which threat
                 * classes drive this severity without leaving Overview.
                 *
                 * #138 — read the LIVE data value (``ctx.parsed.x`` for a
                 * horizontal bar chart) instead of the ``counts`` closure
                 * captured at mount time. ``attachSeverityBarLive``
                 * updates ``chart.data.datasets[0].data`` on every live
                 * snapshot, but does NOT update the closure variables.
                 * Pre-fix the bar drew at the LIVE length while the
                 * tooltip still reported "0 findings" because the
                 * closure never advanced. */
                label: function (ctx) {
                  var idx = ctx.dataIndex;
                  var liveVal = ctx && ctx.parsed && typeof ctx.parsed.x === "number"
                    ? ctx.parsed.x
                    : (counts[idx] || 0);
                  var n = Number(liveVal) || 0;
                  var lines = [n + (n === 1 ? " finding" : " findings")];
                  var extra = asiLines[idx] || [];
                  if (extra.length) {
                    lines.push("by ASI category:");
                    lines = lines.concat(extra);
                  }
                  return lines;
                },
              },
            },
          },
          onClick: function (_evt, els) {
            if (!els.length) { return; }
            var idx = els[0].index;
            /* Open the Findings tab and apply the matching severity filter,
             * so a bar click drills straight into those findings. The tab
             * switch is idempotent when already on Findings. Previously the
             * filter was gated on an exact <option> match in the current
             * page of findings; that silently no-op'd when the clicked
             * severity wasn't in the visible page (tester report #3). The
             * unconditional set+dispatch lets the filter apply correctly
             * whenever the option exists; when it doesn't, the .value
             * assignment is a no-op and the tab switch is still helpful. */
            var sev = severities[idx];
            var findingsTab = document.getElementById("tab-findings");
            if (findingsTab) { findingsTab.click(); }
            var sevSelect = document.getElementById("exec-findings-filter-severity");
            if (sevSelect && sev) {
              sevSelect.value = sev;
              sevSelect.dispatchEvent(new Event("change", { bubbles: true }));
            }
            /* Then scroll the matching severity grouping into view. Defer
             * the scroll until after the browser computes layout for the
             * just-revealed Findings panel — without rAF the call fires
             * before the panel is painted and the scroll lands at 0. */
            var anchor = anchors[idx];
            if (!anchor) { return; }
            var target = anchor.charAt(0) === "#"
              ? document.getElementById(anchor.slice(1))
              : document.querySelector(anchor);
            if (!target) { return; }
            var prefersReduced = window.matchMedia
              && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
            window.requestAnimationFrame(function () {
              target.scrollIntoView({
                behavior: prefersReduced ? "auto" : "smooth",
                block: "start",
              });
            });
          },
        },
      });
      canvas.style.height = Math.max(160, labels.length * 36) + "px";
      lastChart = chart;
    });
    return lastChart;
  }

  /* ----------------------------------------------------------------- */
  /* Copy buttons for the reproducibility receipt                      */
  /* ----------------------------------------------------------------- */

  function mountCopyButtons() {
    var buttons = document.querySelectorAll("[data-copy-target]");
    buttons.forEach(function (btn) {
      if (btn.dataset.bound === "1") { return; }
      btn.dataset.bound = "1";
      btn.addEventListener("click", function () {
        var sel = btn.getAttribute("data-copy-target");
        if (!sel) { return; }
        var target = document.querySelector(sel);
        if (!target) { return; }
        var text = target.textContent || "";
        var originalLabel = btn.textContent;
        function flash(ok) {
          btn.textContent = ok ? "Copied" : "Copy failed";
          setTimeout(function () { btn.textContent = originalLabel; }, 1500);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(
            function () { flash(true); },
            function () { flash(false); }
          );
        } else {
          try {
            var ta = document.createElement("textarea");
            ta.value = text;
            ta.setAttribute("readonly", "");
            ta.style.position = "absolute";
            ta.style.left = "-9999px";
            document.body.appendChild(ta);
            ta.select();
            var ok = document.execCommand("copy");
            document.body.removeChild(ta);
            flash(!!ok);
          } catch (_err) {
            flash(false);
          }
        }
      });
    });
  }

  /* ----------------------------------------------------------------- */
  /* Bootstrap                                                          */
  /* ----------------------------------------------------------------- */

  /* ----------------------------------------------------------------- */
  /* Tab-visibility observer                                            */
  /* ----------------------------------------------------------------- */

  /* Chart.js sizes its canvas to the parent's measured box at construction
   * time. Panels that start with `hidden` (Findings, Probes, Agents, Logs)
   * have zero layout at init, so their charts come back as 0-tall blank
   * boxes — visible as the original Findings-tab regression. Re-mounting
   * when the panel becomes visible gives Chart.js a real bounding box to
   * measure against and the bars animate in on first reveal. */
  function watchPanelVisibility() {
    if (typeof MutationObserver === "undefined") { return; }
    var panels = document.querySelectorAll('[role="tabpanel"]');
    panels.forEach(function (panel) {
      if (panel.dataset.execChartObserver === "1") { return; }
      panel.dataset.execChartObserver = "1";
      var obs = new MutationObserver(function (records) {
        for (var i = 0; i < records.length; i += 1) {
          if (records[i].attributeName === "hidden"
              && !panel.hasAttribute("hidden")) {
            mountSeverityBar();
            mountAsiRadar();
            break;
          }
        }
      });
      obs.observe(panel, { attributes: true, attributeFilter: ["hidden"] });
    });
  }

  /* ----------------------------------------------------------------- */
  /* Severity bar — live snapshot subscriber (#138)                    */
  /* ----------------------------------------------------------------- */

  /* Update the CRITICAL / HIGH / MEDIUM / LOW horizontal-bar counts in
   * place from a snapshot payload. Uses Chart.getChart(canvas) to find
   * every mounted instance (one per tab: overview + findings) so both
   * tab-scoped copies stay in sync without a teardown / remount.
   * No-op when Chart.js or the canvases are absent (graceful on tabs
   * that haven't booted yet). */
  function updateSeverityBar(snapshot) {
    if (!window.Chart || !Chart.getChart) { return; }
    if (!snapshot) { return; }
    var critical = Number(snapshot.critical) || 0;
    var high = Number(snapshot.high) || 0;
    var medium = Number(snapshot.medium) || 0;
    var low = Number(snapshot.low) || 0;
    var nextData = [critical, high, medium, low];
    var canvases = document.querySelectorAll("canvas.exec-severity-bar-canvas");
    canvases.forEach(function (canvas) {
      var chart = Chart.getChart(canvas);
      if (!chart || !chart.data || !chart.data.datasets || !chart.data.datasets[0]) {
        return;
      }
      var ds = chart.data.datasets[0];
      // Skip the repaint when nothing changed — avoids the per-frame
      // GPU work Chart.js does even with update("none").
      var prev = ds.data || [];
      if (prev[0] === nextData[0] && prev[1] === nextData[1]
          && prev[2] === nextData[2] && prev[3] === nextData[3]) {
        return;
      }
      // #138 diagnostic: log the value swap so a stale-data report can
      // be reconstructed from the browser console after the fact. Cheap
      // (one console.log per snapshot when the value actually changes;
      // ~500 ms cadence at most). Comment out / remove once #138 is
      // verified across a few real scans.
      try {
        console.debug(
          "AGSeverityBarLive: ds.data",
          prev.slice(),
          "->",
          nextData.slice()
        );
      } catch (e) {}
      ds.data = nextData;
      chart.update("none");
    });
  }

  function attachSeverityBarLive() {
    var body = document.body;
    if (!body) { return; }
    var scanId = body.getAttribute("data-scan-id");
    if (!scanId) { return; }
    if (body.getAttribute("data-is-terminal") === "true") { return; }
    var es = window.AGStreams && window.AGStreams.snapshot
      ? window.AGStreams.snapshot(scanId)
      : null;
    if (!es) { return; }
    es.addEventListener("snapshot", function (evt) {
      try { updateSeverityBar(JSON.parse(evt.data)); }
      catch (err) { try { console.error("AGSeverityBarLive: snapshot apply failed", err); } catch (e) {} }
    });
  }

  function init() {
    mountAsiRadar();
    mountSeverityBar();
    mountCopyButtons();
    watchPanelVisibility();
    attachRadarLive();
    attachSeverityBarLive();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* Expose helpers for tests / SSE re-renders. */
  window.AgentGuardianExecutive = {
    mountAsiRadar: mountAsiRadar,
    updateAsiRadar: updateAsiRadar,
    mountSeverityBar: mountSeverityBar,
    updateSeverityBar: updateSeverityBar,
    mountCopyButtons: mountCopyButtons,
    watchPanelVisibility: watchPanelVisibility,
    readToken: readToken,
    withAlpha: withAlpha,
  };
})();
