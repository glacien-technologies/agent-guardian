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

    new Chart(canvas, {
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
            pointBackgroundColor: brand,
            pointBorderColor: bgElev,
            pointHoverBackgroundColor: bgElev,
            pointHoverBorderColor: brand,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        aspectRatio: 1,
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
            },
          },
          onClick: function (_evt, els) {
            if (!els.length) { return; }
            var idx = els[0].index;
            var anchor = anchors[idx];
            if (!anchor) { return; }
            /* getElementById is safer than querySelector when anchor is a
             * "#id" string and avoids throwing on malformed selectors. */
            var target = anchor.charAt(0) === "#"
              ? document.getElementById(anchor.slice(1))
              : document.querySelector(anchor);
            if (!target) { return; }
            var prefersReduced = window.matchMedia
              && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
            target.scrollIntoView({
              behavior: prefersReduced ? "auto" : "smooth",
              block: "start",
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

  function init() {
    mountAsiRadar();
    mountSeverityBar();
    mountCopyButtons();
    watchPanelVisibility();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* Expose helpers for tests / SSE re-renders. */
  window.AgentGuardianExecutive = {
    mountAsiRadar: mountAsiRadar,
    mountSeverityBar: mountSeverityBar,
    mountCopyButtons: mountCopyButtons,
    watchPanelVisibility: watchPanelVisibility,
    readToken: readToken,
    withAlpha: withAlpha,
  };
})();
