/* SSE Phase 2, Step 2.4 — Live-append across Findings / Probes / Logs.
 *
 * Subscribes (in concert with the layout-shell EventSource) to per-scan
 * SSE events and APPENDS a freshly built row into the matching tab's
 * tbody / list on every arrival. Reverses the snapshot-only contract
 * documented at ``_tab_findings.html:1`` / ``_tab_probes.html:1`` /
 * ``_tab_logs.html:1`` until 2026-06-03.
 *
 * Architecture
 * ------------
 * The module exposes one entry point: ``window.AGLiveAppend.attach(es)``.
 * ``es`` is the shared ``EventSource`` against ``/scan/<id>/events``
 * (the same stream ``swarm.js`` and ``phase-spine.js`` already consume
 * — Phase 2 multiplexer makes per-subscriber queues safe). The attach
 * call wires per-event handlers and is idempotent (a marker attribute
 * prevents double-binding when multiple themes share a layout).
 *
 * Row construction
 * ----------------
 * Per-tab ``<template data-row-template data-kind="...">`` blocks
 * carry the canonical row shape (one for each of ``finding``, ``probe``,
 * ``log``). ``buildFindingRow`` / ``buildProbeRow`` / ``buildLogRow``
 * clone the template, fill text + data-attrs via ``data-slot``
 * selectors, and return the populated ``<tr>`` / ``<li>``. Failing to
 * find a template fast-fails (returns null) — the row simply doesn't
 * append; the snapshot still loads on next F5.
 *
 * Filter integration
 * ------------------
 * The Findings dropdown filter toolbar (QA-053) and the Logs level
 * chip toolbar both run pure-client-side filters. When a filter is
 * active we still APPEND the live row (so it's counted in M of the
 * "Showing N of M" counter) but apply the same gate the existing
 * filter functions apply — adding the ``is-filtered-out`` class on
 * Findings, or setting ``hidden`` on Logs. The visible counter is
 * incremented only when the new row passes the active filter.
 *
 * Hover-freeze UX touch
 * ---------------------
 * While the operator hovers over a rows container, a row inserting
 * under their cursor causes the row they were about to click to jump
 * — a known triage frustration. We maintain a per-tab insertion queue:
 * when ``isHovering[kind]`` is true new events buffer in the queue
 * instead of inserting; on ``mouseleave`` we flush in arrival order.
 * Pure-DOM ``mouseenter`` / ``mouseleave`` on the rows container; no
 * touch-event support (the dashboard is desktop-first).
 *
 * Acceptance: new finding visible in the Findings tab within 200ms of
 * the producer emit, NO F5 needed. Same for probes and logs.
 */

(function () {
  "use strict";

  // -------------------------------------------------------------------
  // Severity vocab + label helpers (mirrors server-side _findings_page).
  // -------------------------------------------------------------------
  var SEVERITY_LABELS = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
  };

  var VERDICT_LABELS = {
    fail: "EXPLOITED",
    pass: "DEFENDED",
    inconclusive: "INCONCLUSIVE",
    pending: "PENDING",
    unknown: "PENDING",
  };

  // -------------------------------------------------------------------
  // Per-tab insertion queues (hover-freeze).
  // -------------------------------------------------------------------
  var insertQueue = { finding: [], probe: [], log: [] };
  var isHovering = { finding: false, probe: false, log: false };
  var hoverWired = { finding: false, probe: false, log: false };

  function hoverContainer(kind) {
    if (kind === "finding") {
      return document.querySelector("#tabpanel-findings .exec-findings-table-wrap");
    }
    if (kind === "probe") {
      return document.querySelector("#tabpanel-probes .exec-probes-table");
    }
    if (kind === "log") {
      return document.querySelector("#tabpanel-logs .exec-logs");
    }
    return null;
  }

  function wireHover(kind) {
    if (hoverWired[kind]) { return; }
    var container = hoverContainer(kind);
    if (!container) { return; }
    container.addEventListener("mouseenter", function () {
      isHovering[kind] = true;
    });
    container.addEventListener("mouseleave", function () {
      isHovering[kind] = false;
      flushQueue(kind);
    });
    hoverWired[kind] = true;
  }

  function flushQueue(kind) {
    var queue = insertQueue[kind];
    while (queue.length) {
      var pending = queue.shift();
      try {
        pending();
      } catch (e) { /* swallow per-row errors so the queue drains */ }
    }
  }

  function enqueueOrApply(kind, op) {
    if (isHovering[kind]) {
      insertQueue[kind].push(op);
      return;
    }
    op();
  }

  // -------------------------------------------------------------------
  // Template helpers.
  // -------------------------------------------------------------------
  function findTemplate(kind) {
    var sel =
      kind === "finding"
        ? "#tabpanel-findings template[data-row-template][data-kind='finding']"
        : kind === "probe"
        ? "#tabpanel-probes template[data-row-template][data-kind='probe']"
        : kind === "log"
        ? "#tabpanel-logs template[data-row-template][data-kind='log']"
        : null;
    if (!sel) { return null; }
    return document.querySelector(sel);
  }

  function cloneTemplate(kind) {
    var tpl = findTemplate(kind);
    if (!tpl || !tpl.content) { return null; }
    var frag = tpl.content.cloneNode(true);
    // The template wraps exactly one element (a <tr> or <li>) — return
    // the first element child of the cloned fragment.
    return frag.firstElementChild;
  }

  function fillSlot(row, slot, text) {
    var node = row.querySelector('[data-slot="' + slot + '"]');
    if (!node) { return; }
    node.textContent = text == null ? "" : String(text);
  }

  function safeStr(v) {
    return v == null ? "" : String(v);
  }

  // -------------------------------------------------------------------
  // Row builders. Each returns a populated <tr> / <li> (no append).
  // -------------------------------------------------------------------

  /**
   * Build a Findings table row from a ``finding`` event payload.
   *
   * Payload shape (mirrors the server-side ``Finding`` projection):
   *   { id, asi, severity, category, agent, probe_id, summary, turn }
   *
   * Returns a fully populated <tr>, or null if the template is missing.
   */
  function buildFindingRow(payload) {
    if (!payload) { return null; }
    var row = cloneTemplate("finding");
    if (!row) { return null; }
    var p = payload.payload || payload;
    var sev = String(p.severity || "low").toLowerCase();
    var asi = safeStr(p.asi || p.asi_code);
    var agent = safeStr(p.agent || p.agent_name);
    var probe = safeStr(p.probe_id || p.probe);
    var fid = safeStr(p.id || p.finding_id);
    var summary = safeStr(p.summary);
    var category = safeStr(p.category || p.csa_code);
    var turn = safeStr(p.turn);
    var scanId =
      document.body && document.body.getAttribute
        ? document.body.getAttribute("data-scan-id") || ""
        : "";

    row.setAttribute("data-finding-id", fid);
    row.setAttribute("data-severity", sev);
    row.setAttribute("data-asi", asi);
    row.setAttribute("data-agent", agent);
    row.setAttribute("data-probe", probe);
    if (scanId && fid) {
      row.setAttribute(
        "data-finding-href",
        "/scan/" + encodeURIComponent(scanId) + "/finding/" + encodeURIComponent(fid)
      );
    }
    var pill = row.querySelector('[data-slot="sev-pill"]');
    if (pill) {
      pill.classList.add("exec-sev-pill--" + sev);
      pill.setAttribute("aria-label", (SEVERITY_LABELS[sev] || sev) + " severity");
    }
    fillSlot(row, "sev-label", SEVERITY_LABELS[sev] || sev);
    fillSlot(row, "asi", asi || "—");
    fillSlot(row, "category", category || "—");
    fillSlot(row, "agent", agent || "—");
    fillSlot(row, "probe", probe || "—");
    fillSlot(row, "summary", summary);
    fillSlot(row, "turn", turn || "—");
    if (summary) {
      var summaryCell = row.querySelector(".exec-findings-table__cell--summary");
      if (summaryCell) { summaryCell.setAttribute("title", summary); }
    }
    row.setAttribute(
      "aria-label",
      "Open finding " +
        (fid || "(new)") +
        " (" +
        (SEVERITY_LABELS[sev] || sev) +
        " severity)"
    );
    return row;
  }

  // Verdict precedence for the per-agent rollup — mirrors the server-side
  // ``_rollup_verdict`` (worst case wins so a single exploited turn is never
  // masked behind a defended one). Higher number == worse.
  var VERDICT_RANK = { fail: 3, inconclusive: 2, pass: 1 };

  /**
   * Normalise an ``agent_*`` event payload into the fields a per-agent
   * probe row cares about.
   *
   * Payload shape:
   *   { agent, asi, turn, max_turns, probe_id, payload?: {findings_count} }
   *
   * Verdict is derived: ``agent_done`` w/ findings>0 → fail; w/
   * findings==0 → pass; ``agent_skipped`` → inconclusive; otherwise
   * pending (live progress, e.g. ``agent_start`` / ``agent_progress``).
   */
  function readProbeEvent(payload) {
    var p = payload.payload || {};
    var kind = safeStr(payload.kind || payload._kind);
    var agent = safeStr(payload.agent || p.agent);
    var asi = safeStr(payload.asi || p.asi);
    var probeId = safeStr(payload.probe_id || p.probe_id || "");
    var verdict = "pending";
    if (kind === "agent_done") {
      var n = Number(p.findings_count || 0);
      verdict = n > 0 ? "fail" : "pass";
    } else if (kind === "agent_skipped") {
      verdict = "inconclusive";
    }
    var ts = "";
    if (typeof payload.timestamp === "string") {
      ts = payload.timestamp;
    } else if (typeof payload.ts === "number") {
      try {
        ts = new Date(payload.ts * 1000).toISOString();
      } catch (e) { ts = ""; }
    }
    // ``agent_progress`` carries the live turn index; ``agent_start`` is the
    // first turn. We count distinct turn arrivals on the row rather than
    // trust the event to carry a running total.
    var isTurn = kind === "agent_start" || kind === "agent_progress";
    return {
      kind: kind,
      agent: agent,
      asi: asi,
      probeId: probeId,
      verdict: verdict,
      ts: ts,
      isTurn: isTurn,
    };
  }

  /** Set the verdict pill text + modifier class on a probe row. */
  function setProbeVerdict(row, verdict) {
    row.setAttribute("data-verdict", verdict);
    var pillNode = row.querySelector('[data-slot="verdict-pill"]');
    if (!pillNode) { return; }
    // Drop any stale modifier before re-applying.
    pillNode.className = "exec-verdict-pill exec-verdict-pill--" + verdict;
    pillNode.textContent = VERDICT_LABELS[verdict] || "PENDING";
  }

  /**
   * Build a fresh per-agent Probes table row from a normalised event.
   * One ROW PER AGENT (operator feedback 2026-06-03) — recon's many turns
   * collapse into this single row, whose turn count + verdict update in
   * place on later turns (see ``appendProbe``).
   *
   * Returns a fully populated <tr>, or null if the template is missing.
   */
  function buildProbeRow(payload) {
    if (!payload) { return null; }
    var row = cloneTemplate("probe");
    if (!row) { return null; }
    var ev = readProbeEvent(payload);
    var scanId =
      document.body && document.body.getAttribute
        ? document.body.getAttribute("data-scan-id") || ""
        : "";

    // Counted attributes (not in the template skeleton — see
    // ``_tab_probes.html`` for the rationale; set them here on every
    // clone so the live row carries the same QA-049 row-click contract
    // as the server-rendered rows).
    row.setAttribute("data-source", "probe");
    row.setAttribute("data-action", "probe-row-click");
    row.setAttribute("tabindex", "0");
    row.setAttribute("role", "button");
    row.setAttribute("data-probe-group", ev.agent);
    row.setAttribute("data-probe-id", ev.probeId);
    if (scanId && ev.agent) {
      row.setAttribute(
        "data-probe-href",
        "/scan/" + encodeURIComponent(scanId) + "/probe?group=" + encodeURIComponent(ev.agent)
      );
    }
    var turnCount = ev.isTurn ? 1 : 0;
    row.setAttribute("data-turn-count", String(turnCount));
    setProbeVerdict(row, ev.verdict);
    fillSlot(row, "asi", ev.asi || "—");
    fillSlot(row, "agent", ev.agent || "—");
    fillSlot(row, "turn", turnCount + (turnCount === 1 ? " turn" : " turns"));
    fillSlot(row, "timestamp", ev.ts);
    row.setAttribute(
      "aria-label",
      "Open conversation for " + (ev.agent || "(new agent)")
    );
    return row;
  }

  /**
   * Build a Logs <li> row from a ``reflection`` event payload.
   *
   * Payload shape (best effort — `reflection` event carries the
   * judge's verdict + reasoning):
   *   { agent, asi, turn, verdict, reasoning, timestamp? }
   *
   * Level defaults to "info"; "warn" if verdict==inconclusive;
   * "error" if verdict==fail.
   */
  function buildLogRow(payload) {
    if (!payload) { return null; }
    var row = cloneTemplate("log");
    if (!row) { return null; }
    var p = payload.payload || payload;
    var verdict = safeStr(p.verdict).toLowerCase();
    var level = "info";
    if (verdict === "inconclusive") { level = "warn"; }
    else if (verdict === "fail") { level = "error"; }
    var agent = safeStr(payload.agent || p.agent);
    var asi = safeStr(payload.asi || p.asi);
    var summary = safeStr(p.reasoning || p.summary || p.message || "");
    var ts = safeStr(p.timestamp_label || p.timestamp || payload.timestamp);
    var kind = safeStr(payload.kind || "reflection");

    row.classList.add("exec-log--" + level);
    row.setAttribute("data-level", level);
    row.setAttribute("data-agent", agent);
    row.setAttribute("data-kind", kind);
    fillSlot(row, "timestamp", ts);
    fillSlot(row, "level", level.toUpperCase());
    fillSlot(row, "kind", kind);
    fillSlot(row, "agent", agent);
    fillSlot(row, "asi", asi);
    fillSlot(row, "summary", summary);
    return row;
  }

  // -------------------------------------------------------------------
  // Filter integration.
  // -------------------------------------------------------------------

  /**
   * Test whether a Findings row passes the active dropdown filter set.
   * Mirrors the AND-of-dropdowns logic in ``executive_findings.js`` so
   * the live-append path is consistent with the dropdown behaviour:
   * each ``<select>`` with a non-empty value must match the row's
   * matching ``data-{group}`` attribute.
   */
  function passesFindingsFilter(row) {
    var toolbar = document.getElementById("exec-findings-filter");
    if (!toolbar) { return true; }
    var selects = toolbar.querySelectorAll(".exec-findings-filter__select");
    for (var i = 0; i < selects.length; i++) {
      var sel = selects[i];
      var g = sel.getAttribute("data-filter-group");
      var want = sel.value || "";
      if (!g || !want) { continue; }
      var rowVal = row.getAttribute("data-" + g) || "";
      if (rowVal !== want) { return false; }
    }
    return true;
  }

  function passesLogsFilter(row) {
    var toolbar = document.querySelector("#tabpanel-logs .exec-logs-filter");
    if (!toolbar) { return true; }
    var chips = toolbar.querySelectorAll("[data-filter-level]");
    var enabled = {};
    for (var i = 0; i < chips.length; i++) {
      if (chips[i].getAttribute("aria-pressed") === "true") {
        enabled[chips[i].getAttribute("data-filter-level")] = true;
      }
    }
    var lvl = row.getAttribute("data-level") || "info";
    if (Object.keys(enabled).length && !enabled[lvl]) { return false; }
    var input = toolbar.querySelector(".exec-logs-filter__input");
    var q = input ? (input.value || "").trim().toLowerCase() : "";
    if (q && (row.textContent || "").toLowerCase().indexOf(q) === -1) {
      return false;
    }
    return true;
  }

  // -------------------------------------------------------------------
  // Counter helpers.
  // -------------------------------------------------------------------

  function bumpFindingsCounter(visibleDelta) {
    var counter = document.getElementById("exec-findings-filter-counter");
    if (!counter) { return; }
    var visibleSlot = counter.querySelector("[data-counter-visible]");
    var totalSlot = counter.querySelector("[data-counter-total]");
    if (totalSlot) {
      var t = parseInt(totalSlot.textContent || "0", 10) || 0;
      totalSlot.textContent = String(t + 1);
    }
    if (visibleSlot && visibleDelta) {
      var v = parseInt(visibleSlot.textContent || "0", 10) || 0;
      visibleSlot.textContent = String(v + 1);
    }
    var totalLive = document.querySelector('[data-live="findings-total"]');
    if (totalLive) {
      var lv = parseInt(totalLive.textContent || "0", 10) || 0;
      totalLive.textContent = String(lv + 1);
    }
  }

  function bumpLogsCounter() {
    var liveCount = document.querySelector('[data-live="logs-count"]');
    if (liveCount) {
      var n = parseInt(liveCount.textContent || "0", 10) || 0;
      liveCount.textContent = String(n + 1);
    }
  }

  // -------------------------------------------------------------------
  // Appenders. Each is wrapped by the hover-freeze gate.
  // -------------------------------------------------------------------

  function appendFinding(payload) {
    wireHover("finding");
    enqueueOrApply("finding", function () {
      var row = buildFindingRow(payload);
      if (!row) { return; }
      var table = document.getElementById("exec-findings-table");
      if (!table) { return; }
      var sev = row.getAttribute("data-severity") || "low";
      var tbody = table.querySelector('tbody[data-severity="' + sev + '"]');
      if (!tbody) {
        tbody = document.createElement("tbody");
        tbody.id = "exec-sev-" + sev;
        tbody.className = "exec-findings-table__group";
        tbody.setAttribute("data-severity", sev);
        table.appendChild(tbody);
      }
      var pass = passesFindingsFilter(row);
      if (!pass) { row.classList.add("is-filtered-out"); }
      tbody.appendChild(row);
      bumpFindingsCounter(pass);
    });
  }

  function appendProbe(payload) {
    wireHover("probe");
    enqueueOrApply("probe", function () {
      if (!payload) { return; }
      var tbody = document.querySelector("#tabpanel-probes .exec-probes-table tbody");
      if (!tbody) { return; }
      var ev = readProbeEvent(payload);
      // One ROW PER AGENT — if this agent already has a row, UPDATE it
      // (bump the turn count + roll the verdict up) instead of appending a
      // second row. Recon's ~17 turns therefore land in a single row.
      var existing = ev.agent
        ? tbody.querySelector(
            '.exec-probes-table__row[data-probe-group="' +
              (window.CSS && CSS.escape ? CSS.escape(ev.agent) : ev.agent) +
              '"]'
          )
        : null;
      if (existing) {
        if (ev.isTurn) {
          var n = (parseInt(existing.getAttribute("data-turn-count") || "0", 10) || 0) + 1;
          existing.setAttribute("data-turn-count", String(n));
          fillSlot(existing, "turn", n + (n === 1 ? " turn" : " turns"));
        }
        // Roll the verdict up to the worst outcome seen so far.
        var current = existing.getAttribute("data-verdict") || "pending";
        if ((VERDICT_RANK[ev.verdict] || 0) > (VERDICT_RANK[current] || 0)) {
          setProbeVerdict(existing, ev.verdict);
        }
        if (ev.ts) { fillSlot(existing, "timestamp", ev.ts); }
        if (ev.probeId && !existing.getAttribute("data-probe-id")) {
          existing.setAttribute("data-probe-id", ev.probeId);
        }
        return;
      }
      var row = buildProbeRow(payload);
      if (!row) { return; }
      tbody.appendChild(row);
    });
  }

  function appendLog(payload) {
    wireHover("log");
    enqueueOrApply("log", function () {
      var row = buildLogRow(payload);
      if (!row) { return; }
      var list = document.querySelector("#tabpanel-logs .exec-logs");
      if (!list) {
        // No initial logs_tail — the snapshot rendered an empty-state
        // <p class="exec-empty">. Replace it with a fresh <ol> so we
        // have somewhere to append.
        var pane = document.getElementById("tabpanel-logs");
        if (!pane) { return; }
        list = document.createElement("ol");
        list.className = "exec-logs";
        var empty = pane.querySelector(".exec-empty");
        if (empty && empty.parentNode) {
          empty.parentNode.insertBefore(list, empty);
          empty.hidden = true;
        } else {
          pane.appendChild(list);
        }
      }
      var pass = passesLogsFilter(row);
      row.hidden = !pass;
      list.appendChild(row);
      bumpLogsCounter();
    });
  }

  // -------------------------------------------------------------------
  // Event-source wiring. Idempotent — guarded by a marker attribute.
  // -------------------------------------------------------------------

  function safeParse(raw) {
    try { return JSON.parse(raw); } catch (e) { return null; }
  }

  function attach(source) {
    if (!source || typeof source.addEventListener !== "function") { return; }
    if (source.__agLiveAppendAttached) { return; }
    source.__agLiveAppendAttached = true;

    source.addEventListener("finding", function (e) {
      var data = safeParse(e.data) || {};
      appendFinding(data);
    });

    var probeKinds = [
      "agent_start",
      "agent_progress",
      "agent_done",
      "agent_skipped",
    ];
    probeKinds.forEach(function (k) {
      source.addEventListener(k, function (e) {
        var data = safeParse(e.data) || {};
        data._kind = k;
        if (!data.kind) { data.kind = k; }
        appendProbe(data);
      });
    });

    source.addEventListener("reflection", function (e) {
      var data = safeParse(e.data) || {};
      appendLog(data);
    });
  }

  // Public API.
  window.AGLiveAppend = {
    attach: attach,
    buildFindingRow: buildFindingRow,
    buildProbeRow: buildProbeRow,
    buildLogRow: buildLogRow,
    _flushQueue: flushQueue, // exposed for tests
  };
})();
