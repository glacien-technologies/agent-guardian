/*
 * elapsed-ticker.js — drives the live ELAPSED clock for the Executive
 * dashboard (SSE Phase 1, Step 4 of designs/sse-flow-and-live-ui.md).
 *
 * The Global KPI ELAPSED tile (``.exec-kpi [data-live="elapsed"]``) is
 * keyed off the unified ``data-elapsed-anchor`` attribute, a float of
 * unix seconds. It seeds from the <body>'s ``data-started-at-unix``
 * attribute on first paint (server-render anchor) and from
 * ``started_at_unix`` on the first live snapshot — whichever lands
 * first. The four-phase Phase Spine (and its per-pill elapsed captions)
 * was retired, so the spine is no longer an anchor source; the
 * ``stampPhaseAnchor`` / ``phase_start`` handlers below are now
 * defensive no-ops (``querySelector`` returns null with no spine in the
 * DOM) but are kept so the SSE wiring stays intact if the per-phase
 * captions are ever reintroduced.
 *
 * Why a float, not an ISO string (critic patch G16/P9): Safari's
 * ``Date.parse`` returns NaN on the naive ISO timestamps produced by
 * ``_utcnow()`` (no trailing "Z"). The ticker NEVER touches an ISO
 * timestamp — it only reads ``started_at_unix`` / ``phase_start.started_at``
 * float values.
 *
 * Resync semantics (critic patch G15/P15): the server's ``elapsed``
 * snapshot value seeds the ticker on FIRST receipt only — never as a
 * periodic correction (which can rewind the tile if ``scan_dir.mtime``
 * goes stale). If the client and server diverge by >30s, freeze the
 * ticker, fall back to the server's ``elapsed_label``, and amber-pulse
 * the KPI ELAPSED tile a single time to signal the resync.
 *
 * Reduced motion (critic patch G20/P20): drives updates with
 * ``setTimeout`` (NOT ``setInterval``) so the loop self-terminates when
 * ``matchMedia('(prefers-reduced-motion: reduce)')`` matches. In
 * reduced-motion mode the existing 0.5s ``/scans/<id>/live`` snapshot
 * patcher refreshes ``elapsed_label`` server-side — no client ticking.
 *
 * Terminal scans: the layout shell short-circuits the EventSource at
 * ``layout.html`` for ``data-is-terminal === 'true'`` — this module
 * mirrors that guard and never starts the ticker on a completed scan.
 */
(function () {
  "use strict";

  var TICK_MS = 1000;
  var DIVERGENCE_THRESHOLD_S = 30;
  var AMBER_PULSE_CLASS = "exec-kpi--amber-pulse";
  var FROZEN = false;
  var SEEDED_GLOBAL = false;

  function reducedMotion() {
    try {
      return (
        typeof window.matchMedia === "function" &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches
      );
    } catch (err) {
      return false;
    }
  }

  function fmt(total) {
    if (!isFinite(total) || total < 0) {
      total = 0;
    }
    total = Math.floor(total);
    var h = Math.floor(total / 3600);
    var m = Math.floor((total % 3600) / 60);
    var s = total % 60;
    function pad(n) {
      return n < 10 ? "0" + n : String(n);
    }
    if (h > 0) {
      return h + ":" + pad(m) + ":" + pad(s);
    }
    return pad(m) + ":" + pad(s);
  }

  function anchored() {
    return document.querySelectorAll("[data-elapsed-anchor]");
  }

  function nowSec() {
    return Date.now() / 1000;
  }

  function tick() {
    if (FROZEN) {
      return;
    }
    var nodes = anchored();
    var now = nowSec();
    for (var i = 0; i < nodes.length; i += 1) {
      var node = nodes[i];
      var raw = node.getAttribute("data-elapsed-anchor");
      var anchor = parseFloat(raw);
      if (!isFinite(anchor) || anchor <= 0) {
        continue;
      }
      node.textContent = fmt(now - anchor);
    }
    // setTimeout (NOT setInterval) so the loop self-paces and respects
    // reduced-motion bailouts via the early-return at the top.
    window.setTimeout(tick, TICK_MS);
  }

  // Parse "MM:SS" or "H:MM:SS" back into seconds so we can compare the
  // server's humanised elapsed_label against the client's tick value.
  function parseLabelSeconds(label) {
    if (typeof label !== "string") {
      return NaN;
    }
    var parts = label.trim().split(":");
    if (parts.length < 2 || parts.length > 3) {
      return NaN;
    }
    var total = 0;
    for (var i = 0; i < parts.length; i += 1) {
      var n = parseInt(parts[i], 10);
      if (!isFinite(n)) {
        return NaN;
      }
      total = total * 60 + n;
    }
    return total;
  }

  function stampGlobalAnchor(startedAtUnix) {
    var anchor = parseFloat(startedAtUnix);
    if (!isFinite(anchor) || anchor <= 0) {
      return;
    }
    var tile = document.querySelector(
      '.exec-kpi[data-kpi="elapsed"] [data-live="elapsed"]'
    );
    if (tile && !tile.hasAttribute("data-elapsed-anchor")) {
      tile.setAttribute("data-elapsed-anchor", String(anchor));
    }
  }

  function stampPhaseAnchor(phase, startedAt) {
    var anchor = parseFloat(startedAt);
    if (!isFinite(anchor) || anchor <= 0) {
      return;
    }
    var caption = document.querySelector(
      '[data-phase-elapsed="' + phase + '"]'
    );
    if (caption) {
      caption.setAttribute("data-elapsed-anchor", String(anchor));
    }
  }

  function amberPulseElapsedTile() {
    var tile = document.querySelector('.exec-kpi[data-kpi="elapsed"]');
    if (!tile) {
      return;
    }
    tile.classList.add(AMBER_PULSE_CLASS);
    window.setTimeout(function () {
      tile.classList.remove(AMBER_PULSE_CLASS);
    }, 1500);
  }

  function maybeFreezeOnDivergence(serverLabel) {
    var globalNode = document.querySelector(
      '.exec-kpi[data-kpi="elapsed"] [data-live="elapsed"]'
    );
    if (!globalNode || !globalNode.hasAttribute("data-elapsed-anchor")) {
      return;
    }
    var anchor = parseFloat(globalNode.getAttribute("data-elapsed-anchor"));
    if (!isFinite(anchor) || anchor <= 0) {
      return;
    }
    var serverSec = parseLabelSeconds(serverLabel);
    if (!isFinite(serverSec)) {
      return;
    }
    var clientSec = nowSec() - anchor;
    if (Math.abs(clientSec - serverSec) > DIVERGENCE_THRESHOLD_S) {
      FROZEN = true;
      globalNode.removeAttribute("data-elapsed-anchor");
      globalNode.textContent = serverLabel;
      amberPulseElapsedTile();
    }
  }

  function onSnapshot(data) {
    if (!data || typeof data !== "object") {
      return;
    }
    // Seed the global anchor on FIRST receipt only — never as a
    // periodic correction (critic patch G15/P15). The per-phase
    // anchors are seeded by phase_start events on /scan/<id>/events.
    if (!SEEDED_GLOBAL && data.started_at_unix) {
      stampGlobalAnchor(data.started_at_unix);
      SEEDED_GLOBAL = true;
    }
    // Divergence check is cheap and runs every snapshot; the freeze
    // path is one-way so a transient stale-mtime bump cannot rewind
    // the tile mid-scan.
    maybeFreezeOnDivergence(data.elapsed);
  }

  function onPhaseStart(payload) {
    if (!payload || typeof payload !== "object") {
      return;
    }
    if (typeof payload.phase !== "string") {
      return;
    }
    stampPhaseAnchor(payload.phase, payload.started_at);
  }

  function openEventStreams(scanId) {
    if (typeof EventSource === "undefined") {
      return;
    }
    function parsePayload(evt) {
      try {
        return JSON.parse(evt.data);
      } catch (err) {
        return null;
      }
    }
    var snapUrl = "/scans/" + encodeURIComponent(scanId) + "/live";
    var snapES;
    try {
      snapES = new EventSource(snapUrl);
    } catch (err) {
      snapES = null;
    }
    if (snapES) {
      snapES.addEventListener("snapshot", function (evt) {
        var data = parsePayload(evt);
        if (data) {
          onSnapshot(data);
        }
      });
      snapES.addEventListener("scan_done", function () {
        try {
          snapES.close();
        } catch (err) {
          /* swallow */
        }
      });
      snapES.onerror = function () {
        /* browser auto-reconnects */
      };
    }
    var eventsUrl = "/scan/" + encodeURIComponent(scanId) + "/events";
    var es;
    try {
      es = new EventSource(eventsUrl);
    } catch (err) {
      es = null;
    }
    if (es) {
      es.addEventListener("phase_start", function (evt) {
        var data = parsePayload(evt);
        if (!data) {
          return;
        }
        onPhaseStart(data.payload || data);
      });
      es.addEventListener("scan_done", function () {
        try {
          es.close();
        } catch (err) {
          /* swallow */
        }
      });
      es.onerror = function () {
        /* browser auto-reconnects */
      };
    }
  }

  function seedFromBodyAttribute() {
    // Server-render path: the <body> carries ``data-started-at-unix`` (a
    // stable float of unix seconds) even before the first snapshot
    // arrives. Seed the KPI tile anchor from it so the ticker has
    // something to animate immediately on first paint — without it the
    // tile sits on the server's ``elapsed`` label, which the snapshot
    // patcher rewrites each poll and flickers between 00:00 and 00:01.
    //
    // This attribute replaced the retired Phase Spine's
    // ``data-started-at-unix`` (the four-phase strip was removed); the
    // body is now the single server-render anchor source.
    var body = document.body;
    if (!body) {
      return;
    }
    var raw = body.getAttribute("data-started-at-unix");
    if (raw) {
      stampGlobalAnchor(raw);
      SEEDED_GLOBAL = true;
    }
  }

  function init() {
    var body = document.body;
    if (!body) {
      return;
    }
    var scanId = body.getAttribute("data-scan-id");
    if (!scanId) {
      return;
    }
    seedFromBodyAttribute();
    if (body.getAttribute("data-is-terminal") === "true") {
      // Completed scan: every elapsed surface is server-rendered in
      // its final state. No ticking, no SSE.
      return;
    }
    if (!reducedMotion()) {
      window.setTimeout(tick, TICK_MS);
    }
    openEventStreams(scanId);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
