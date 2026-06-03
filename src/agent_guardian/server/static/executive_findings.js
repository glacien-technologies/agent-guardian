/* Executive Dashboard — Findings + Probes slide-over driver (QA-031 / QA-032 / QA-049).
 *
 * Single IIFE wires the shared slide-over component (mounted once per
 * tabpanel by ``_finding_slideover.html``) to:
 *
 *   * ``.exec-findings-table__row`` rows (Findings tab)
 *   * ``.exec-probes-table__row``   rows (Probes tab)
 *
 * Each row carries:
 *   * ``data-action``       — ``"probe-row-click"`` on probe rows (QA-049
 *                             row-click contract).
 *   * ``data-source``       — ``"finding"`` | ``"probe"``  (selects renderer).
 *   * ``data-probe-href``   — server URL the drawer ``fetch()``-es when a
 *                             probe row is opened (BUG-1: replaces the
 *                             legacy ``#exec-probes-payload`` JSON-island
 *                             wall — no per-probe payload ships in the
 *                             initial page HTML any more).
 *   * ``data-probe-id``     — present on probe rows; used for the deep-link
 *                             ``?probe=<id>`` query path.
 *   * ``data-finding-id``   — present on finding rows; keys into the
 *                             ``#exec-findings-payload`` JSON island.
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

  /**
   * Hook every "Copy" button rendered inside the freshly-loaded probe
   * detail-sheet. Each button declares its source element by id via
   * ``data-copy-source``; the writer copies that element's textContent
   * to the clipboard and surfaces a transient "Copied" label.
   *
   * @param {HTMLElement} container — the freshly-injected drawer body
   */
  function wireCopyButtons(container) {
    var buttons = container.querySelectorAll("[data-copy-source]");
    for (var i = 0; i < buttons.length; i++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          var srcId = btn.getAttribute("data-copy-source");
          var src = srcId ? document.getElementById(srcId) : null;
          var text = src ? src.textContent || "" : "";
          var original = btn.textContent;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard
              .writeText(text)
              .then(function () {
                btn.textContent = "Copied";
                window.setTimeout(function () { btn.textContent = original; }, 1500);
              })
              .catch(function () {
                btn.textContent = "Copy failed";
                window.setTimeout(function () { btn.textContent = original; }, 1500);
              });
          }
        });
      })(buttons[i]);
    }
  }

  /**
   * After the server-rendered drawer fragment is injected, hoist its
   * ``<template data-probe-header>`` into the slide-over header chips
   * (verdict pill / probe id / turn / timestamp / summary). This keeps
   * the chip state in sync with the freshly-loaded probe without
   * shipping a second copy of the metadata.
   *
   * @param {HTMLElement} root      — ``.exec-slideover-root`` element
   * @param {HTMLElement} container — the drawer body container
   */
  function syncProbeHeader(root, container) {
    var tpl = container.querySelector("[data-probe-header]");
    if (!tpl) { return; }
    var verdict = tpl.getAttribute("data-verdict") || "unknown";
    var verdictLabel = tpl.getAttribute("data-verdict-label") || "PENDING";
    var verdictCls = "exec-verdict-pill--unknown";
    if (verdict === "fail") { verdictCls = "exec-verdict-pill--fail"; }
    else if (verdict === "pass") { verdictCls = "exec-verdict-pill--pass"; }
    else if (verdict === "inconclusive") { verdictCls = "exec-verdict-pill--inconclusive"; }

    var pill = root.querySelector("[data-slideover-verdict-pill]");
    if (pill) {
      pill.className = "exec-verdict-pill " + verdictCls;
      pill.setAttribute("data-slideover-verdict-pill", "");
      pill.textContent = verdictLabel;
    }
    setText(root.querySelector("[data-slideover-id]"), tpl.getAttribute("data-probe-id") || "—");
    var turn = tpl.getAttribute("data-turn") || "—";
    setText(root.querySelector("[data-slideover-turn]"), "turn " + turn);
    setText(
      root.querySelector("[data-slideover-time]"),
      tpl.getAttribute("data-timestamp") || "—",
    );
    setText(
      root.querySelector("[data-slideover-summary]"),
      tpl.getAttribute("data-summary") || "Probe details",
    );

    // The template is one-shot; remove it once consumed so the drawer
    // body markup stays compact.
    tpl.parentNode.removeChild(tpl);
  }

  // ---- 4. Renderers (finding-mode only — probe-mode is server-rendered) -
  function renderFindingHeader(root, f) {
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

  /**
   * Safe-URL guard for the probe-detail-sheet ``fetch()``.
   *
   * Only same-origin, ``/scan/<id>/probe`` paths are accepted. This
   * blocks a future refactor (or a stray DevTools edit) from pointing
   * the drawer at an attacker-controlled origin — defence-in-depth for
   * the ``innerHTML`` swap below, even though the response itself is
   * always our own Jinja-autoescaped fragment.
   */
  function isSafeProbeHref(href) {
    if (typeof href !== "string" || href.length === 0) { return false; }
    // Reject absolute URLs (``http://...``, ``//evil.example``,
    // ``javascript:``); only allow same-origin relative paths.
    if (/^[a-z]+:/i.test(href) || href.indexOf("//") === 0) { return false; }
    if (href.charAt(0) !== "/") { return false; }
    // Lock the path shape: ``/scan/<id>/probe`` with an optional query
    // string. ``<id>`` is path-safe (no slashes) by construction.
    return /^\/scan\/[^/]+\/probe(\?.*)?$/.test(href);
  }

  /**
   * Fetch the server-rendered probe-detail-sheet for a row and inject
   * it into the drawer body. BUG-1 — initial page HTML carries no
   * per-probe payload; this ``fetch()`` is the only path the verbatim
   * prompt / response / reasoning text takes into the DOM.
   *
   * The response is a Jinja-autoescaped HTML fragment from the
   * ``/scan/<id>/probe`` route — every operator-untrusted field is
   * escaped by the template, so ``innerHTML`` is safe here. The
   * ``isSafeProbeHref`` guard above blocks any non-same-origin /
   * non-probe URL from reaching this assignment as an extra
   * defence-in-depth check.
   *
   * @param {HTMLElement} root     — ``.exec-slideover-root``
   * @param {HTMLElement} bodyNode — ``[data-slideover-body]``
   * @param {string}      href     — row's ``data-probe-href``
   */
  function loadProbeSheet(root, bodyNode, href) {
    bodyNode.textContent = "";
    var pending = el("p", "exec-probe__reason exec-probe__reason--empty", "Loading…");
    bodyNode.appendChild(pending);
    if (typeof fetch !== "function") { return; }
    if (!isSafeProbeHref(href)) {
      bodyNode.textContent = "";
      bodyNode.appendChild(
        el(
          "p",
          "exec-probe__reason exec-probe__reason--empty",
          "Cannot open this probe — invalid drawer URL.",
        ),
      );
      return;
    }
    fetch(href, { credentials: "same-origin", headers: { Accept: "text/html" } })
      .then(function (resp) {
        if (!resp.ok) { throw new Error("probe fetch failed: " + resp.status); }
        var ct = resp.headers.get("Content-Type") || "";
        // Server must return HTML; reject anything else (JSON, script,
        // attachments) so a mis-routed response can't smuggle markup
        // past the innerHTML swap.
        if (ct.indexOf("text/html") === -1) {
          throw new Error("unexpected content-type: " + ct);
        }
        return resp.text();
      })
      .then(function (html) {
        // Server-rendered, Jinja-autoescaped, same-origin HTML fragment
        // — innerHTML is the canonical pattern for this swap (matches
        // htmx hx-swap="innerHTML" semantics). See ``isSafeProbeHref``
        // above for the URL allow-list that gates this assignment.
        bodyNode.innerHTML = html;
        syncProbeHeader(root, bodyNode);
        wireCopyButtons(bodyNode);
      })
      .catch(function (err) {
        bodyNode.textContent = "";
        bodyNode.appendChild(
          el(
            "p",
            "exec-probe__reason exec-probe__reason--empty",
            "Could not load probe details (" + err.message + ").",
          ),
        );
      });
  }

  // ---- 5. Slide-over controller ----------------------------------------
  /**
   * Bind a single slide-over root to its surrounding tabpanel's row set.
   * Each tabpanel mounts its own slide-over instance; this function is
   * called once per instance.
   *
   * @param {HTMLElement} root      — ``.exec-slideover-root`` element
   * @param {object}      payloads  — { finding: {id->row} } — probe
   *                                  rows fetch their own payload from
   *                                  the server on click (BUG-1).
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
      if (source === "probe") {
        // Reset the chip header to a neutral state — the server fragment
        // populates the real values via its ``<template data-probe-header>``
        // on response.
        var pill = root.querySelector("[data-slideover-verdict-pill]");
        if (pill) {
          pill.className = "exec-verdict-pill exec-verdict-pill--unknown";
          pill.textContent = "…";
        }
        setText(root.querySelector("[data-slideover-id]"), row.getAttribute("data-probe-id") || "—");
        var verdict = row.getAttribute("data-verdict") || "unknown";
        if (pill) {
          var label = "PENDING";
          var cls = "exec-verdict-pill--unknown";
          if (verdict === "fail") { label = "EXPLOITED"; cls = "exec-verdict-pill--fail"; }
          else if (verdict === "pass") { label = "DEFENDED"; cls = "exec-verdict-pill--pass"; }
          else if (verdict === "inconclusive") { label = "INCONCLUSIVE"; cls = "exec-verdict-pill--inconclusive"; }
          pill.className = "exec-verdict-pill " + cls;
          pill.textContent = label;
        }
        loadProbeSheet(root, bodyNode, row.getAttribute("data-probe-href"));
      } else if (source === "finding") {
        var f = payloads.finding[row.getAttribute("data-finding-id")];
        if (!f) { return; }
        renderFindingHeader(root, f);
        renderFindingBody(bodyNode, f);
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

    // Row activation — click + Enter/Space keyboard. QA-049 wires the
    // ``data-action="probe-row-click"`` contract on probe rows; finding
    // rows still use the class selector for backwards compatibility.
    var selectors = [
      ".exec-probes-table__row",
      "[data-action=\"probe-row-click\"]",
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

  // ---- 6. Findings filter chips (QA-053) -------------------------------
  /**
   * Wire the sticky multi-select chip toolbar above the findings table.
   *
   * Operators click chips to compose an AND-of-OR filter:
   *   * Multiple chips in the SAME group (e.g. two severities) OR
   *     together — a row matches the group if it matches ANY selected
   *     chip in that group.
   *   * Different groups (severity / agent / asi / probe) AND together
   *     — a row must match every group that has at least one chip
   *     selected.
   *   * A group with NO chips selected is a "no-op" (all rows pass for
   *     that group).
   *
   * Pure client-side: walks the rendered ``<tr>`` rows, reads their
   * ``data-severity`` / ``data-agent`` / ``data-asi`` / ``data-probe``
   * attributes, and toggles ``.is-filtered-out``. The Showing-N-of-M
   * counter is updated on every toggle and announced via ``aria-live``.
   *
   * Marker symbol: ``ag.dashboard.executive.findings.filters``.
   */
  function bootFindingsFilters() {
    var toolbar = document.getElementById("exec-findings-filter");
    var table = document.getElementById("exec-findings-table");
    if (!toolbar || !table) { return; }
    var chips = toolbar.querySelectorAll(".exec-findings-filter__chip");
    // QA-054 — only PARENT rows count toward the Showing-N-of-M counter and
    // are subject to chip filtering. Child rows always inherit their
    // parent's visibility; we re-apply child visibility from the parent's
    // current ``aria-expanded`` state at the end of ``applyFilters``.
    var allRowNodes = table.querySelectorAll(".exec-findings-table__row");
    var rows = [];
    var childRows = [];
    for (var ri = 0; ri < allRowNodes.length; ri++) {
      if (allRowNodes[ri].classList.contains("exec-findings-table__row--child")) {
        childRows.push(allRowNodes[ri]);
      } else {
        rows.push(allRowNodes[ri]);
      }
    }
    var counter = document.getElementById("exec-findings-filter-counter");
    var visibleSlot = counter
      ? counter.querySelector("[data-counter-visible]")
      : null;
    var totalSlot = counter
      ? counter.querySelector("[data-counter-total]")
      : null;
    var groupKeys = ["severity", "agent", "asi", "probe"];

    function activeByGroup() {
      var out = { severity: [], agent: [], asi: [], probe: [] };
      for (var i = 0; i < chips.length; i++) {
        var chip = chips[i];
        if (chip.getAttribute("aria-pressed") !== "true") { continue; }
        var g = chip.getAttribute("data-filter-group");
        var v = chip.getAttribute("data-filter-value");
        if (g && v && out[g]) { out[g].push(v); }
      }
      return out;
    }

    function applyFilters() {
      var active = activeByGroup();
      var visible = 0;
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var pass = true;
        for (var gi = 0; gi < groupKeys.length; gi++) {
          var key = groupKeys[gi];
          var picks = active[key];
          if (!picks.length) { continue; }
          var rowVal = row.getAttribute("data-" + key) || "";
          if (picks.indexOf(rowVal) === -1) { pass = false; break; }
        }
        if (pass) {
          row.classList.remove("is-filtered-out");
          visible += 1;
        } else {
          row.classList.add("is-filtered-out");
        }
      }
      // QA-054 — propagate parent filter state to children. A filtered-out
      // parent always hides its children. An expanded, visible parent
      // reveals its children; a collapsed, visible parent keeps them
      // hidden. This keeps the expand/collapse state independent of the
      // filter chips — toggling a chip never collapses an already-open
      // parent.
      for (var ci = 0; ci < childRows.length; ci++) {
        var child = childRows[ci];
        var parentId = child.getAttribute("data-child-of");
        var parent = parentId
          ? table.querySelector(
            '.exec-findings-table__row[data-finding-id="' + parentId + '"]'
          )
          : null;
        if (!parent || parent.classList.contains("is-filtered-out")) {
          child.classList.add("is-filtered-out");
          child.hidden = true;
          continue;
        }
        child.classList.remove("is-filtered-out");
        var expanded = parent.getAttribute("data-expanded") === "true";
        child.hidden = !expanded;
        if (expanded) {
          child.classList.remove("is-collapsed");
        } else {
          child.classList.add("is-collapsed");
        }
      }
      if (visibleSlot) { visibleSlot.textContent = String(visible); }
      if (totalSlot) { totalSlot.textContent = String(rows.length); }
    }

    for (var i = 0; i < chips.length; i++) {
      (function (chip) {
        chip.addEventListener("click", function () {
          var pressed = chip.getAttribute("aria-pressed") === "true";
          chip.setAttribute("aria-pressed", pressed ? "false" : "true");
          applyFilters();
        });
      })(chips[i]);
    }
    // Initial render — render Showing-N-of-M as N == M (no chips active).
    applyFilters();

    if (typeof window !== "undefined") {
      window.__ag_executive_findings_filters = "ag.dashboard.executive.findings.filters";
      // Expose ``applyFilters`` for the QA-054 chevron toggle handler so a
      // child reveal triggered by chevron click re-runs the parent-visible
      // gate (otherwise the child would un-hide even when a chip filter
      // currently hides the parent).
      window.__ag_executive_findings_apply = applyFilters;
    }
  }

  // ---- 7. Multi-turn expand/collapse chevrons (QA-054) ------------------
  /**
   * Wire chevron toggles on multi-turn finding rows. Click flips
   * ``aria-expanded`` on the toggle button and ``data-expanded`` on the
   * parent ``<tr>``; child rows below the parent are revealed via the
   * filter pipeline (so a parent hidden by a chip filter never reveals
   * its children, even when previously expanded).
   *
   * Pure client-side — no server round-trip. ``stopPropagation`` on the
   * click event prevents the chevron from also opening the slide-over.
   *
   * Marker symbol: ``ag.dashboard.executive.findings.turn_toggle``.
   */
  function bootTurnToggles() {
    var table = document.getElementById("exec-findings-table");
    if (!table) { return; }
    var toggles = table.querySelectorAll('[data-action="toggle-turns"]');
    for (var i = 0; i < toggles.length; i++) {
      (function (btn) {
        btn.addEventListener("click", function (ev) {
          ev.stopPropagation();
          var parentId = btn.getAttribute("data-target");
          if (!parentId) { return; }
          var parent = table.querySelector(
            '.exec-findings-table__row[data-finding-id="' + parentId + '"]'
          );
          if (!parent) { return; }
          var isOpen = btn.getAttribute("aria-expanded") === "true";
          btn.setAttribute("aria-expanded", isOpen ? "false" : "true");
          parent.setAttribute("data-expanded", isOpen ? "false" : "true");
          // Re-run the filter pipeline; it owns child visibility so the
          // expand state composes correctly with any active chip filters.
          if (typeof window !== "undefined" &&
              typeof window.__ag_executive_findings_apply === "function") {
            window.__ag_executive_findings_apply();
          }
        });
        btn.addEventListener("keydown", function (ev) {
          // ``Enter`` / ``Space`` already trigger the native button click,
          // but we suppress propagation here too so the row's
          // Enter-to-open-slide-over handler doesn't double-fire.
          if (ev.key === "Enter" || ev.key === " ") {
            ev.stopPropagation();
          }
        });
      })(toggles[i]);
    }
    if (typeof window !== "undefined") {
      window.__ag_executive_findings_turn_toggle =
        "ag.dashboard.executive.findings.turn_toggle";
    }
  }

  // ---- 8. Boot ---------------------------------------------------------
  function boot() {
    var payloads = {
      finding: indexBy(loadPayload("exec-findings-payload"), "id"),
      // BUG-1: probe payloads are fetched on demand from
      // ``/scan/<id>/probe?index=<N>`` — no JSON-island lookup table.
    };
    var roots = document.querySelectorAll(".exec-slideover-root");
    for (var i = 0; i < roots.length; i++) {
      attach(roots[i], payloads);
    }
    bootFindingsFilters();
    bootTurnToggles();
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
