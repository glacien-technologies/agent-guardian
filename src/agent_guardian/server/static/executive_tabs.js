/* Executive theme tab switcher.
 *
 * - WAI-ARIA manual activation tab pattern (Space/Enter activates a focused
 *   tab; arrow keys only move focus). Verbatim from
 *   https://www.w3.org/WAI/ARIA/apg/patterns/tabs/examples/tabs-manual/
 * - URL fragment sync: ``#tab=<id>`` on activation; read on load; uses
 *   ``history.replaceState`` (never ``pushState``) so internal tab clicks
 *   don't pollute browser history.
 * - localStorage persistence: the last-active tab is saved under the
 *   ``ag.dashboard.executive.tab`` key. URL fragment wins over storage on
 *   load (deep links beat preferences); storage wins over the locked
 *   default of ``overview`` when no fragment is present.
 * - Document title is updated to include the active tab name.
 * - Box-shadow on scroll for the 3-layer sticky stack.
 *
 * No external dependencies. Loaded as ``<script defer>`` from layout.html
 * so the DOM is parsed before ``init()`` runs.
 */
(function () {
  "use strict";

  var TAB_IDS = ["overview", "findings", "probes", "logs"];
  var TAB_LABELS = {
    overview: "Overview",
    findings: "Findings",
    probes: "Probes",
    logs: "Logs",
  };
  var STORAGE_KEY = "ag.dashboard.executive.tab";
  var BASE_TITLE_SUFFIX = " · Executive Dashboard · AgentGuardian";

  function safeStorageGet() {
    try {
      var raw = window.localStorage.getItem(STORAGE_KEY);
      if (raw && TAB_IDS.indexOf(raw) >= 0) {
        return raw;
      }
    } catch (err) { /* private mode / disabled */ }
    return null;
  }

  function safeStorageSet(tabId) {
    try {
      window.localStorage.setItem(STORAGE_KEY, tabId);
    } catch (err) { /* private mode / disabled */ }
  }

  function readFragment() {
    var raw = window.location.hash.replace(/^#/, "");
    if (!raw) { return null; }
    var params = new URLSearchParams(raw);
    var tab = params.get("tab");
    if (tab && TAB_IDS.indexOf(tab) >= 0) { return tab; }
    if (tab) {
      // Forensic visibility for stale bookmarks (e.g. the deleted #tab=agents)
      // — silently falls through to the locked "overview" default at the
      // pickInitialTab() / hashchange call site (QA-030).
      try {
        console.debug("[executive] unknown tab hash, defaulting to overview:", raw);
      } catch (err) { /* console disabled */ }
    }
    return null;
  }

  function writeFragment(tabId) {
    var raw = window.location.hash.replace(/^#/, "");
    var params = new URLSearchParams(raw);
    params.set("tab", tabId);
    var next = "#" + params.toString();
    if (next !== window.location.hash) {
      history.replaceState(null, "", next);
    }
  }

  function updateTitle(tabId) {
    var baseTitle = document.title.split(" · ")[0];
    var label = TAB_LABELS[tabId] || "Overview";
    document.title = baseTitle + " · " + label + BASE_TITLE_SUFFIX;
  }

  function activate(tabId, opts) {
    opts = opts || {};
    TAB_IDS.forEach(function (id) {
      var tab = document.getElementById("tab-" + id);
      var pane = document.getElementById("tabpanel-" + id);
      if (!tab || !pane) { return; }
      var on = id === tabId;
      tab.setAttribute("aria-selected", on ? "true" : "false");
      tab.setAttribute("tabindex", on ? "0" : "-1");
      if (on) {
        pane.removeAttribute("hidden");
      } else {
        pane.setAttribute("hidden", "");
      }
    });
    writeFragment(tabId);
    safeStorageSet(tabId);
    updateTitle(tabId);
    if (opts.focus) {
      var focused = document.getElementById("tab-" + tabId);
      if (focused) { focused.focus(); }
    }
  }

  function focusTab(tabId) {
    var el = document.getElementById("tab-" + tabId);
    if (el) { el.focus(); }
  }

  function wireKeyboard() {
    var tablist = document.querySelector('[role="tablist"]');
    if (!tablist) { return; }
    tablist.addEventListener("keydown", function (e) {
      var current = document.activeElement;
      if (!current || current.getAttribute("role") !== "tab") { return; }
      var idx = TAB_IDS.indexOf(current.id.replace(/^tab-/, ""));
      if (idx < 0) { return; }
      var next = null;
      switch (e.key) {
        case "ArrowRight":
          next = TAB_IDS[(idx + 1) % TAB_IDS.length];
          break;
        case "ArrowLeft":
          next = TAB_IDS[(idx - 1 + TAB_IDS.length) % TAB_IDS.length];
          break;
        case "Home":
          next = TAB_IDS[0];
          break;
        case "End":
          next = TAB_IDS[TAB_IDS.length - 1];
          break;
        case " ":
        case "Enter":
          activate(TAB_IDS[idx]);
          e.preventDefault();
          return;
        default:
          return;
      }
      e.preventDefault();
      focusTab(next);
    });
  }

  function wireClicks() {
    TAB_IDS.forEach(function (id) {
      var tab = document.getElementById("tab-" + id);
      if (!tab) { return; }
      tab.addEventListener("click", function () { activate(id); });
    });
  }

  function wireScroll() {
    var stickies = document.querySelectorAll(".exec-topbar, .exec-kpi-strip, .exec-tabbar");
    function onScroll() {
      var scrolled = window.scrollY > 0;
      stickies.forEach(function (el) {
        el.classList.toggle("is-scrolled", scrolled);
      });
    }
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }

  function pickInitialTab() {
    var fromFragment = readFragment();
    if (fromFragment) { return fromFragment; }
    var fromStorage = safeStorageGet();
    if (fromStorage) { return fromStorage; }
    return "overview";
  }

  function init() {
    wireClicks();
    wireKeyboard();
    wireScroll();
    activate(pickInitialTab());
    window.addEventListener("hashchange", function () {
      var fromFragment = readFragment();
      if (fromFragment) { activate(fromFragment); }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
