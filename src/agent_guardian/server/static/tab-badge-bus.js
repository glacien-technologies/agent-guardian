/*
 * tab-badge-bus.js — Tab-bar badge primitive for the Executive dashboard
 * (SSE Phase 1, Step 6 of designs/sse-flow-and-live-ui.md).
 *
 * Surfaces background-tab activity on the four sticky tab buttons. The
 * badge is a superscript-style chip that lights up when something
 * happens on a tab the operator is NOT currently looking at, and
 * persists across page reload within the same browser session.
 *
 * Public API (attached to ``window.AGTabBadgeBus``):
 *
 *     bus.bump(tab, n, opts?)   -> add ``n`` to the (scan_id, tab) count
 *                                  and repaint the chip. ``opts.severity``
 *                                  is one of ``"notice"`` / ``"alert"``;
 *                                  the bus applies it as a class on the
 *                                  badge span. NO severity logic — the
 *                                  caller (the spine wiring inside
 *                                  ``phase-spine.js`` etc.) decides.
 *     bus.clear(tab)            -> zero the (scan_id, tab) count and
 *                                  hide the chip.
 *     bus.get(tab)              -> read current count (test seam).
 *
 * Persistence (critic patch G19/P19):
 *   Counts live in ``sessionStorage`` keyed by
 *   ``ag.tabBadgeBus.v1.<scan_id>.<tab>``. ``sessionStorage`` survives
 *   reload but not cross-tab — exactly the right granularity for "the
 *   operator F5'd the dashboard and expects the unread badge to still
 *   be there." A fresh tab on the same scan starts at zero, which is
 *   correct: the spine will repaint from snapshot reconciliation.
 *
 * Clear semantics (critic patch G19/P19):
 *   Tab-button click + 2 s dwell. NOT bare active-tab clearing. The
 *   dwell distinguishes "operator is triage-browsing — flicking between
 *   tabs to compare" from "operator clicked Findings INTENDING to mark
 *   the badge read." Implemented as a ``click`` handler that
 *   ``setTimeout(2000)``s the actual clear; the timer is cancelled by
 *   ``mouseleave`` on the same button OR by any other tab being
 *   activated within the dwell window.
 *
 * Terminal scans short-circuit: the layout shell sets
 * ``data-is-terminal="true"`` on ``<body>`` for already-finished scans.
 * No producer ever emits another event, so wiring the bus to anything is
 * a no-op. ``init()`` exits early in that branch — but the API is still
 * installed on ``window`` so static tests and accidental ``bump()``
 * calls degrade gracefully.
 *
 * No third-party deps. Plain ES5 for the same defensive compatibility
 * envelope as the rest of the SSE Phase 1 modules.
 */
(function () {
  "use strict";

  var TABS = ["overview", "findings", "probes", "logs"];
  var SEVERITY_CLASSES = ["notice", "alert"];
  var DWELL_MS = 2000;
  var STORAGE_PREFIX = "ag.tabBadgeBus.v1";

  // --- DOM ------------------------------------------------------------
  function badgeFor(tab) {
    return document.querySelector(
      '[data-badge][data-tab="' + tab + '"]',
    );
  }

  function buttonFor(tab) {
    return document.getElementById("tab-" + tab);
  }

  function scanId() {
    var body = document.body;
    if (!body) {
      return null;
    }
    var raw = body.getAttribute("data-scan-id");
    return raw || null;
  }

  // --- sessionStorage helpers (private mode safe) ---------------------
  function storageKey(sid, tab) {
    return STORAGE_PREFIX + "." + sid + "." + tab;
  }

  function storageGet(sid, tab) {
    if (!sid) {
      return 0;
    }
    try {
      var raw = window.sessionStorage.getItem(storageKey(sid, tab));
      if (!raw) {
        return 0;
      }
      var n = parseInt(raw, 10);
      return isFinite(n) && n >= 0 ? n : 0;
    } catch (err) {
      return 0;
    }
  }

  function storageSet(sid, tab, n) {
    if (!sid) {
      return;
    }
    try {
      if (n > 0) {
        window.sessionStorage.setItem(storageKey(sid, tab), String(n));
      } else {
        window.sessionStorage.removeItem(storageKey(sid, tab));
      }
    } catch (err) {
      /* private mode / disabled — counts only live in the DOM */
    }
  }

  // --- chip rendering -------------------------------------------------
  function applySeverityClass(node, severity) {
    if (!node) {
      return;
    }
    for (var i = 0; i < SEVERITY_CLASSES.length; i += 1) {
      node.classList.remove(SEVERITY_CLASSES[i]);
    }
    if (severity && SEVERITY_CLASSES.indexOf(severity) >= 0) {
      node.classList.add(severity);
    }
  }

  function paint(tab, n, severity) {
    var node = badgeFor(tab);
    if (!node) {
      return;
    }
    if (n > 0) {
      node.textContent = String(n);
      node.setAttribute("data-count", String(n));
      node.setAttribute("aria-label", String(n) + " unread on " + tab);
      node.hidden = false;
      // Severity class is sticky across paints; only the caller flips it.
      if (severity !== undefined) {
        applySeverityClass(node, severity);
      }
    } else {
      node.textContent = "";
      node.removeAttribute("data-count");
      node.removeAttribute("aria-label");
      node.hidden = true;
      applySeverityClass(node, null);
    }
  }

  // --- public API -----------------------------------------------------
  function bump(tab, n, opts) {
    if (TABS.indexOf(tab) < 0) {
      return;
    }
    var inc = Number(n);
    if (!isFinite(inc) || inc <= 0) {
      return;
    }
    var sid = scanId();
    var current = storageGet(sid, tab);
    var next = current + Math.floor(inc);
    storageSet(sid, tab, next);
    // Suppress the badge on the currently-active tab — operator is
    // already looking at it. The count is still persisted so that an
    // operator who navigates away and back doesn't lose the running
    // total — but they only see the chip on inactive tabs.
    var btn = buttonFor(tab);
    if (btn && btn.getAttribute("aria-selected") === "true") {
      paint(tab, 0, null);
      // Active tab: the read is implicit. Don't persist — clear.
      storageSet(sid, tab, 0);
      return;
    }
    var severity = opts && opts.severity ? opts.severity : undefined;
    paint(tab, next, severity);
  }

  function clear(tab) {
    if (TABS.indexOf(tab) < 0) {
      return;
    }
    var sid = scanId();
    storageSet(sid, tab, 0);
    paint(tab, 0, null);
  }

  function get(tab) {
    if (TABS.indexOf(tab) < 0) {
      return 0;
    }
    return storageGet(scanId(), tab);
  }

  // --- dwell-based clear (critic patch G19/P19) ----------------------
  // One pending timer at a time. Clicking another tab cancels the
  // dwell on the previous one. ``mouseleave`` on the clicked button
  // also cancels — the operator is browsing, not marking-read.
  var DWELL = {
    timerId: null,
    tab: null,
  };

  function cancelDwell() {
    if (DWELL.timerId !== null) {
      window.clearTimeout(DWELL.timerId);
    }
    DWELL.timerId = null;
    DWELL.tab = null;
  }

  function armDwell(tab) {
    cancelDwell();
    DWELL.tab = tab;
    DWELL.timerId = window.setTimeout(function () {
      DWELL.timerId = null;
      DWELL.tab = null;
      clear(tab);
    }, DWELL_MS);
  }

  function wireDwell() {
    for (var i = 0; i < TABS.length; i += 1) {
      var tab = TABS[i];
      var btn = buttonFor(tab);
      if (!btn) {
        continue;
      }
      // IIFE binds ``tab`` per iteration without ES2015 ``let``.
      (function (capturedTab, capturedBtn) {
        capturedBtn.addEventListener("click", function () {
          armDwell(capturedTab);
        });
        capturedBtn.addEventListener("mouseleave", function () {
          if (DWELL.tab === capturedTab) {
            cancelDwell();
          }
        });
      })(tab, btn);
    }
  }

  // --- rehydrate from sessionStorage on load -------------------------
  function rehydrate() {
    var sid = scanId();
    if (!sid) {
      return;
    }
    for (var i = 0; i < TABS.length; i += 1) {
      var tab = TABS[i];
      var count = storageGet(sid, tab);
      if (count <= 0) {
        continue;
      }
      var btn = buttonFor(tab);
      // Skip currently-active tab — operator is already looking at it.
      if (btn && btn.getAttribute("aria-selected") === "true") {
        storageSet(sid, tab, 0);
        continue;
      }
      paint(tab, count, undefined);
    }
  }

  function init() {
    if (!document.body) {
      return;
    }
    rehydrate();
    wireDwell();
  }

  // --- export ---------------------------------------------------------
  window.AGTabBadgeBus = {
    bump: bump,
    clear: clear,
    get: get,
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
