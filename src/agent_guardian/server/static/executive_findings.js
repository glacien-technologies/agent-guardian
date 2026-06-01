/* Executive Dashboard — Findings + Probes slide-over driver (QA-031 / QA-032).
 *
 * Single IIFE wires the shared slide-over component (mounted once per
 * tabpanel by ``_finding_slideover.html``) to:
 *
 *   * ``.exec-findings-table__row`` rows (Findings tab, when wave 1 lands)
 *   * ``.exec-probes-table__row``   rows (Probes tab — this wave)
 *
 * Each row carries:
 *   * ``data-source``    — ``"finding"`` | ``"probe"``  (selects renderer)
 *   * ``data-probe-id``  — present on probe rows; keys into the
 *                          ``#exec-probes-payload`` JSON island
 *   * ``data-finding-id`` — present on finding rows; keys into the
 *                          ``#exec-findings-payload`` JSON island
 *
 * The slide-over is a single DOM tree per tabpanel; opening a new row
 * overwrites the header + body slots. Esc / backdrop click / X-button
 * close it and restore focus to the originating row.
 *
 * Marker symbol: ``ag.dashboard.executive.findings.slideover``.
 */
(function () {
  "use strict";

  // ---- 1. Payload loaders ----------------------------------------------
  /**
   * Load a JSON payload from an embedded ``<script type="application/json">``
   * island. Returns ``null`` when the island is missing or unparseable so
   * a probe-only page (no findings payload yet) degrades gracefully.
   *
   * @param {string} islandId — DOM id of the JSON island
   * @returns {object|null}
   */
  function loadPayload(islandId) {
    var node = document.getElementById(islandId);
    if (!node) { return null; }
    try {
      return JSON.parse(node.textContent || "null");
    } catch (err) {
      return null;
    }
  }

  // ---- 2. Index payload lists by id ------------------------------------
  function indexBy(list, key) {
    var out = Object.create(null);
    if (!Array.isArray(list)) { return out; }
    for (var i = 0; i < list.length; i++) {
      var row = list[i];
      if (row && typeof row === "object" && row[key]) {
        out[row[key]] = row;
      }
    }
    return out;
  }

  // ---- 3. DOM helpers ---------------------------------------------------
  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) { n.className = className; }
    if (text != null) { n.textContent = String(text); }
    return n;
  }

  function setText(node, value) {
    if (node) { node.textContent = value == null ? "" : String(value); }
  }

  // ---- 4. Renderers -----------------------------------------------------
  /**
   * Map the AgentGuardian verdict enum (``fail`` / ``pass`` / ``inconclusive``
   * / empty) to operator-facing labels + the matching pill modifier class.
   */
  function verdictPresent(verdict) {
    if (verdict === "fail") {
      return { label: "EXPLOITED", cls: "exec-verdict-pill--fail" };
    }
    if (verdict === "pass") {
      return { label: "DEFENDED", cls: "exec-verdict-pill--pass" };
    }
    if (verdict === "inconclusive") {
      return { label: "INCONCLUSIVE", cls: "exec-verdict-pill--inconclusive" };
    }
    return { label: "PENDING", cls: "exec-verdict-pill--unknown" };
  }

  function renderProbeHeader(root, p) {
    var pill = root.querySelector("[data-slideover-verdict-pill]");
    if (pill) {
      var v = verdictPresent(p.verdict);
      pill.className = "exec-verdict-pill " + v.cls;
      pill.setAttribute("data-slideover-verdict-pill", "");
      pill.textContent = v.label;
    }
    setText(root.querySelector("[data-slideover-id]"), p.probe_id || "—");
    setText(root.querySelector("[data-slideover-turn]"), "turn " + (p.turn != null ? p.turn : "—"));
    setText(root.querySelector("[data-slideover-time]"), p.timestamp_label || "—");
    setText(root.querySelector("[data-slideover-summary]"), p.probe_id || "Probe details");
  }

  function renderProbeBody(bodyNode, p) {
    bodyNode.textContent = "";

    bodyNode.appendChild(el("p", "exec-probe__label", "Request prompt"));
    bodyNode.appendChild(el("pre", "exec-probe__prompt", p.prompt || ""));

    bodyNode.appendChild(el("p", "exec-probe__label", "Target response"));
    bodyNode.appendChild(el("pre", "exec-probe__response", p.target_response || ""));

    var hasConfidence = typeof p.confidence === "number" && p.confidence > 0.0;
    var reasonLabel = hasConfidence
      ? "Judge reasoning (confidence " + p.confidence.toFixed(2) + ")"
      : "Judge reasoning (no judge confidence)";
    bodyNode.appendChild(el("p", "exec-probe__label", reasonLabel));

    if (p.reasoning) {
      bodyNode.appendChild(el("blockquote", "exec-probe__reason", p.reasoning));
    } else {
      bodyNode.appendChild(
        el(
          "p",
          "exec-probe__reason exec-probe__reason--empty",
          "Not graded per-turn — see the Findings tab for the rolled-up judge verdict."
        )
      );
    }
  }

  function renderFindingHeader(root, f) {
    // Finding-mode header — wave 1 will flesh this out. For now we cover
    // the same slot set so the slide-over stays usable if a finding row
    // is wired in before wave 1 ships.
    var pill = root.querySelector("[data-slideover-verdict-pill]");
    if (pill) {
      var sevClass = "exec-verdict-pill--unknown";
      var label = (f.severity_label || f.severity_class || "—").toUpperCase();
      if (f.severity_class === "critical" || f.severity_class === "high") {
        sevClass = "exec-verdict-pill--fail";
      } else if (f.severity_class === "low") {
        sevClass = "exec-verdict-pill--pass";
      } else if (f.severity_class === "medium") {
        sevClass = "exec-verdict-pill--inconclusive";
      }
      pill.className = "exec-verdict-pill " + sevClass;
      pill.setAttribute("data-slideover-verdict-pill", "");
      pill.textContent = label;
    }
    setText(root.querySelector("[data-slideover-id]"), f.id || "—");
    setText(root.querySelector("[data-slideover-turn]"), f.asi_code || "—");
    setText(root.querySelector("[data-slideover-time]"), f.created_label || "—");
    setText(root.querySelector("[data-slideover-summary]"), f.summary || "Finding details");
  }

  function renderFindingBody(bodyNode, f) {
    bodyNode.textContent = "";
    var meta = el("dl", "exec-finding__meta");
    var pairs = [
      ["ASI", f.asi_code],
      ["CSA", f.csa_code],
      ["Probe", f.probe_id],
    ];
    for (var i = 0; i < pairs.length; i++) {
      meta.appendChild(el("dt", null, pairs[i][0]));
      var dd = el("dd");
      dd.appendChild(el("code", null, pairs[i][1] || "—"));
      meta.appendChild(dd);
    }
    bodyNode.appendChild(meta);
    if (f.summary) {
      bodyNode.appendChild(el("p", "exec-probe__label", "Summary"));
      bodyNode.appendChild(el("p", null, f.summary));
    }
  }

  // ---- 5. Slide-over controller ----------------------------------------
  /**
   * Bind a single slide-over root to its surrounding tabpanel's row set.
   * Each tabpanel mounts its own slide-over instance; this function is
   * called once per instance.
   *
   * @param {HTMLElement} root      — ``.exec-slideover-root`` element
   * @param {object}      payloads  — { finding: {id->row}, probe: {id->row} }
   */
  function attach(root, payloads) {
    if (!root) { return; }

    var drawer = root.querySelector(".exec-slideover");
    var bodyNode = root.querySelector("[data-slideover-body]");
    var backdrop = root.querySelector("[data-slideover-backdrop]");
    var closeBtn = root.querySelector("[data-slideover-close]");
    if (!drawer || !bodyNode) { return; }

    var lastFocused = null;

    function open(row) {
      var source = row.getAttribute("data-source");
      var record = null;
      if (source === "probe") {
        record = payloads.probe[row.getAttribute("data-probe-id")];
        if (!record) { return; }
        renderProbeHeader(root, record);
        renderProbeBody(bodyNode, record);
      } else if (source === "finding") {
        record = payloads.finding[row.getAttribute("data-finding-id")];
        if (!record) { return; }
        renderFindingHeader(root, record);
        renderFindingBody(bodyNode, record);
      } else {
        return;
      }
      lastFocused = row;
      root.hidden = false;
      // Force a reflow so the transition runs on the very next frame.
      void root.offsetWidth;
      root.setAttribute("data-open", "true");
      // Move focus into the drawer so screen readers + keyboard
      // navigation pick up the new context.
      if (closeBtn) { closeBtn.focus(); }
    }

    function close() {
      root.setAttribute("data-open", "false");
      // Match the CSS 200ms transition before hiding so the slide-out
      // animation plays out instead of being clipped.
      window.setTimeout(function () {
        if (root.getAttribute("data-open") === "false") {
          root.hidden = true;
        }
      }, 220);
      if (lastFocused && typeof lastFocused.focus === "function") {
        lastFocused.focus();
      }
    }

    // Row activation — click + Enter/Space keyboard.
    var selectors = [
      ".exec-probes-table__row",
      ".exec-findings-table__row",
    ];
    var rows = document.querySelectorAll(selectors.join(","));
    for (var i = 0; i < rows.length; i++) {
      (function (row) {
        row.addEventListener("click", function (ev) {
          // Ignore clicks on real interactive children (links etc).
          var tag = (ev.target && ev.target.tagName) || "";
          if (tag === "A" || tag === "BUTTON") { return; }
          open(row);
        });
        row.addEventListener("keydown", function (ev) {
          if (ev.key === "Enter" || ev.key === " ") {
            ev.preventDefault();
            open(row);
          }
        });
      })(rows[i]);
    }

    if (closeBtn) {
      closeBtn.addEventListener("click", close);
    }
    if (backdrop) {
      backdrop.addEventListener("click", close);
    }
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && root.getAttribute("data-open") === "true") {
        close();
      }
    });
  }

  // ---- 6. Boot ---------------------------------------------------------
  function boot() {
    var payloads = {
      finding: indexBy(loadPayload("exec-findings-payload"), "id"),
      probe: indexBy(loadPayload("exec-probes-payload"), "probe_id"),
    };
    var roots = document.querySelectorAll(".exec-slideover-root");
    for (var i = 0; i < roots.length; i++) {
      attach(roots[i], payloads);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  // Marker for the test suite — verifies the entry-point loaded.
  if (typeof window !== "undefined") {
    window.__ag_executive_findings_slideover = "ag.dashboard.executive.findings.slideover";
  }
})();
