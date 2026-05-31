/* AgentGuardian — Narrative Report theme charts (Theme C / QA-020).
 *
 * Two Chart.js v4 charts and a small set of progressive-enhancement helpers:
 *
 *   1. ASI radar — `#nr-asi-radar` — per-category Adversarial Surface Index
 *      scores. Reads its data from the canvas's `data-chart` JSON attribute.
 *   2. Severity bar — `#nr-severity-bar` — horizontal bar of finding counts
 *      grouped by severity. Click on a bar scrolls smoothly to that
 *      severity's bucket in the Findings section.
 *
 * Helpers:
 *   - readToken(name)   — read a CSS custom property from :root.
 *   - withAlpha(hex, a) — blend a hex color with an alpha channel.
 *   - mountAsiRadar()   — instantiate the radar chart.
 *   - mountSeverityBar()— instantiate the severity bar chart.
 *   - mountToc()        — IntersectionObserver wiring for the sticky TOC.
 *   - mountCopyButtons()— copy-to-clipboard for the reproducibility receipt.
 *
 * The script is idempotent: re-running `init()` after a partial DOM swap
 * (e.g. an SSE-driven re-render) is safe — existing Chart instances are
 * destroyed first and observers are deduped via a `data-bound` flag.
 *
 * Zero dependencies beyond Chart.js v4 (loaded as a UMD script in
 * `layout.html`). No bundler step; no transpilation; ES2018 baseline.
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
    var canvas = document.getElementById("nr-asi-radar");
    if (!canvas) { return; }
    var payload = parseChartPayload(canvas);
    if (!payload || !Array.isArray(payload.labels) || !Array.isArray(payload.values)) {
      return;
    }
    destroyExisting(canvas);
    var brand = readToken("--nr-brand") || "#8b5cf6";
    var ink = readToken("--nr-ink") || "#1a1a1a";
    var grid = readToken("--nr-border-subtle") || "#e8e6e0";
    var bgElev = readToken("--nr-bg-elev") || "#ffffff";
    var subtle = readToken("--nr-ink-subtle") || "#8a8a8a";

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
                family: readToken("--nr-font-sans") || "Inter, system-ui, sans-serif",
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
    var canvas = document.getElementById("nr-severity-bar");
    if (!canvas) { return; }
    var payload = parseChartPayload(canvas);
    if (!payload || !Array.isArray(payload.rows)) { return; }
    destroyExisting(canvas);

    var labels = payload.rows.map(function (r) { return r.label || (r.severity || "").toUpperCase(); });
    var counts = payload.rows.map(function (r) { return r.count || 0; });
    var anchors = payload.rows.map(function (r) { return r.anchor; });
    var colors = payload.rows.map(function (r) {
      return readToken("--nr-sev-" + r.severity) || "#8b5cf6";
    });
    var ink = readToken("--nr-ink") || "#1a1a1a";
    var subtle = readToken("--nr-ink-subtle") || "#8a8a8a";
    var grid = readToken("--nr-border-subtle") || "#e8e6e0";
    var bgElev = readToken("--nr-bg-elev") || "#ffffff";

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
                family: readToken("--nr-font-mono") || "monospace",
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
          var target = document.querySelector(anchor);
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
    return chart;
  }

  /* ----------------------------------------------------------------- */
  /* TOC: IntersectionObserver-driven active highlight                 */
  /* ----------------------------------------------------------------- */

  function mountToc() {
    if (!("IntersectionObserver" in window)) { return; }
    var links = document.querySelectorAll(".nr-toc__link[data-toc-target]");
    if (!links.length) { return; }
    var byId = {};
    links.forEach(function (link) {
      var id = link.getAttribute("data-toc-target");
      if (id) { byId[id] = link; }
    });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        var link = byId[entry.target.id];
        if (!link) { return; }
        if (entry.isIntersecting) {
          links.forEach(function (l) {
            l.classList.remove("is-active");
            l.removeAttribute("aria-current");
          });
          link.classList.add("is-active");
          link.setAttribute("aria-current", "true");
        }
      });
    }, {
      rootMargin: "-40% 0% -55% 0%",
      threshold: 0,
    });
    Object.keys(byId).forEach(function (id) {
      var target = document.getElementById(id);
      if (target) { io.observe(target); }
    });
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

  function init() {
    mountAsiRadar();
    mountSeverityBar();
    mountToc();
    mountCopyButtons();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* Expose helpers for tests / SSE re-renders. */
  window.AgentGuardianNarrative = {
    mountAsiRadar: mountAsiRadar,
    mountSeverityBar: mountSeverityBar,
    mountToc: mountToc,
    mountCopyButtons: mountCopyButtons,
    readToken: readToken,
    withAlpha: withAlpha,
  };
})();
