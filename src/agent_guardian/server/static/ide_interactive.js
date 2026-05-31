/*
 * ide_interactive.js — file-tree click handlers, tab management, sidebar
 * resize, breadcrumb sync, theme-switcher toggle, copy-to-clipboard helpers.
 *
 * Vanilla JS only. No framework. No bundler. The IDE theme is a single
 * self-contained HTML page; every cell is pre-rendered server-side, so this
 * script never makes a network request — it only toggles `hidden` on cells
 * and updates the tab strip / breadcrumb / status bar.
 *
 * Public side-effects on the DOM:
 *   - `[data-tree-path]` clicks open / focus tabs.
 *   - `[data-ide-tabs]` updates when tabs are opened or closed.
 *   - `[data-ide-breadcrumb]` updates to mirror the active tab.
 *   - `[data-ide-status-selection]` updates to mirror the active tab.
 *   - `[data-ide-theme-toggle]` shows / hides the theme switcher host.
 *   - `[data-ide-sidebar-sash]` resizes the sidebar.
 *   - `[data-ide-copy-scan-id]` / `[data-ide-copy-finding-id]` copy.
 *
 * Persistence keys (localStorage):
 *   - "ag.dashboard.ide.sidebar-width"
 *   - "ag.dashboard.ide.open-tabs"
 *
 * Theme preference is owned by the shared theme switcher; we do not write
 * to "ag.dashboard.theme" here.
 */

(function () {
  "use strict";

  var LS_SIDEBAR_WIDTH = "ag.dashboard.ide.sidebar-width";
  var LS_OPEN_TABS = "ag.dashboard.ide.open-tabs";
  var SIDEBAR_MIN = 200;
  var SIDEBAR_MAX = 480;

  function safeGet(key) {
    try { return window.localStorage.getItem(key); } catch (_) { return null; }
  }

  function safeSet(key, value) {
    try { window.localStorage.setItem(key, value); } catch (_) { /* private mode */ }
  }

  function qs(sel, root) {
    return (root || document).querySelector(sel);
  }

  function qsa(sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  }

  /* ----------------------------------------------------------------------
   * Sidebar width — restore + sash drag.
   * ---------------------------------------------------------------------- */

  function restoreSidebarWidth() {
    var stored = parseInt(safeGet(LS_SIDEBAR_WIDTH) || "", 10);
    if (isNaN(stored)) { return; }
    var clamped = Math.max(SIDEBAR_MIN, Math.min(SIDEBAR_MAX, stored));
    document.documentElement.style.setProperty("--ide-sidebar-width", clamped + "px");
  }

  function bindSidebarSash() {
    var sash = qs("[data-ide-sidebar-sash]");
    if (!sash) { return; }
    var dragging = false;

    function onMove(ev) {
      if (!dragging) { return; }
      var x = ev.clientX != null ? ev.clientX : (ev.touches && ev.touches[0] ? ev.touches[0].clientX : 0);
      var width = Math.max(SIDEBAR_MIN, Math.min(SIDEBAR_MAX, x - 48));
      document.documentElement.style.setProperty("--ide-sidebar-width", width + "px");
      safeSet(LS_SIDEBAR_WIDTH, String(width));
    }

    function onEnd() {
      dragging = false;
      document.body.style.cursor = "";
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onEnd);
    }

    sash.addEventListener("pointerdown", function (ev) {
      dragging = true;
      document.body.style.cursor = "col-resize";
      ev.preventDefault();
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onEnd);
    });

    sash.addEventListener("keydown", function (ev) {
      var current = parseInt(
        getComputedStyle(document.documentElement).getPropertyValue("--ide-sidebar-width"),
        10
      );
      if (isNaN(current)) { current = 256; }
      var next = current;
      if (ev.key === "ArrowLeft") { next = current - 16; }
      else if (ev.key === "ArrowRight") { next = current + 16; }
      else { return; }
      ev.preventDefault();
      next = Math.max(SIDEBAR_MIN, Math.min(SIDEBAR_MAX, next));
      document.documentElement.style.setProperty("--ide-sidebar-width", next + "px");
      safeSet(LS_SIDEBAR_WIDTH, String(next));
    });
  }

  /* ----------------------------------------------------------------------
   * Tab + cell management.
   * ---------------------------------------------------------------------- */

  function findCell(path) {
    var cells = qsa(".ide-cell");
    for (var i = 0; i < cells.length; i++) {
      if (cells[i].getAttribute("data-tree-path") === path) {
        return cells[i];
      }
    }
    return null;
  }

  function findTab(path) {
    var tabs = qsa(".ide-tab[data-tree-path]");
    for (var i = 0; i < tabs.length; i++) {
      if (tabs[i].getAttribute("data-tree-path") === path) {
        return tabs[i];
      }
    }
    return null;
  }

  function setActiveCell(path) {
    var cells = qsa(".ide-cell");
    var matched = false;
    cells.forEach(function (cell) {
      if (cell.getAttribute("data-tree-path") === path) {
        cell.classList.add("ide-cell--active");
        cell.removeAttribute("hidden");
        matched = true;
      } else {
        cell.classList.remove("ide-cell--active");
        cell.setAttribute("hidden", "");
      }
    });
    return matched;
  }

  function setActiveTab(path) {
    qsa(".ide-tab").forEach(function (tab) {
      var active = tab.getAttribute("data-tree-path") === path;
      tab.classList.toggle("ide-tab--active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
    });
  }

  function setActiveTreeRow(path) {
    qsa(".ide-tree__row").forEach(function (row) {
      row.classList.remove("ide-tree__row--active");
    });
    var row = qs('[data-tree-path="' + cssEscape(path) + '"].ide-tree__row');
    if (row) { row.classList.add("ide-tree__row--active"); }
  }

  function cssEscape(value) {
    if (window.CSS && typeof window.CSS.escape === "function") {
      return window.CSS.escape(value);
    }
    return String(value).replace(/(["\\\\])/g, "\\\\$1");
  }

  function updateBreadcrumb(path) {
    var ol = qs("[data-ide-breadcrumb]");
    if (!ol) { return; }
    var scanId = (document.body.getAttribute("data-scan-id") || "");
    var parts = String(path).split("/");
    var html = '<li class="ide-breadcrumb__item">'
      + '<a class="ide-breadcrumb__seg" href="?theme=ide&file=README.md" data-tree-path="README.md">'
      + "scan_" + escapeHtml(scanId)
      + "</a></li>";
    for (var i = 0; i < parts.length; i++) {
      html += '<li class="ide-breadcrumb__item" aria-hidden="true"><span class="ide-breadcrumb__sep">›</span></li>';
      var isLast = (i === parts.length - 1);
      if (isLast) {
        html += '<li class="ide-breadcrumb__item ide-breadcrumb__item--active" aria-current="page">'
          + '<span class="ide-breadcrumb__seg ide-breadcrumb__seg--active" data-ide-breadcrumb-last>'
          + escapeHtml(parts[i])
          + "</span></li>";
      } else {
        html += '<li class="ide-breadcrumb__item">'
          + '<span class="ide-breadcrumb__seg">' + escapeHtml(parts[i]) + "</span></li>";
      }
    }
    ol.innerHTML = html;
  }

  function updateStatusSelection(path) {
    var node = qs("[data-ide-status-selection]");
    if (node) { node.textContent = path; }
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (ch) {
      switch (ch) {
        case "&": return "&amp;";
        case "<": return "&lt;";
        case ">": return "&gt;";
        case '"': return "&quot;";
        case "'": return "&#39;";
      }
      return ch;
    });
  }

  function openOrFocusTab(path, kind, severity) {
    var existing = findTab(path);
    var strip = qs("[data-ide-tabs]");
    if (!existing && strip) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "ide-tab";
      btn.setAttribute("role", "tab");
      btn.setAttribute("aria-selected", "false");
      btn.setAttribute("data-tree-path", path);
      if (kind) { btn.setAttribute("data-tree-kind", kind); }
      var icon = document.createElement("span");
      if (kind === "diff" && severity) {
        icon.className = "ide-tab__sev-dot ide-tab__sev-dot--" + severity;
      } else if (kind === "readme") {
        icon.className = "ide-tab__icon ide-tab__icon--md";
      } else {
        icon.className = "ide-tab__icon";
      }
      icon.setAttribute("aria-hidden", "true");
      btn.appendChild(icon);
      var label = document.createElement("span");
      label.className = "ide-tab__label";
      label.textContent = path.split("/").pop() || path;
      btn.appendChild(label);
      var closeGlyph = document.createElement("span");
      closeGlyph.className = "ide-tab__close";
      closeGlyph.textContent = "×";
      closeGlyph.setAttribute("aria-hidden", "true");
      btn.appendChild(closeGlyph);
      // Insert before the trailing "+" plus button if present.
      var plus = strip.querySelector(".ide-tab--plus");
      if (plus) { strip.insertBefore(btn, plus); } else { strip.appendChild(btn); }
    }
    activate(path);
    persistOpenTabs();
  }

  function persistOpenTabs() {
    var paths = qsa(".ide-tab[data-tree-path]").map(function (t) {
      return t.getAttribute("data-tree-path");
    });
    safeSet(LS_OPEN_TABS, JSON.stringify(paths));
  }

  function activate(path) {
    var ok = setActiveCell(path);
    if (!ok) {
      // No matching cell -- fall back to README so we never end up blank.
      setActiveCell("README.md");
      path = "README.md";
    }
    setActiveTab(path);
    setActiveTreeRow(path);
    updateBreadcrumb(path);
    updateStatusSelection(path);
  }

  function closeTab(path) {
    if (path === "README.md") { return; } // README is permanent.
    var tab = findTab(path);
    if (!tab) { return; }
    var wasActive = tab.classList.contains("ide-tab--active");
    tab.parentNode.removeChild(tab);
    if (wasActive) {
      // Focus README.
      activate("README.md");
    }
    persistOpenTabs();
  }

  /* ----------------------------------------------------------------------
   * Click + keyboard binding.
   * ---------------------------------------------------------------------- */

  function bindTreeClicks() {
    document.addEventListener("click", function (ev) {
      var row = ev.target && ev.target.closest && ev.target.closest("[data-tree-path]");
      if (!row) { return; }
      var inTree = row.closest && row.closest(".ide-tree");
      var inBreadcrumb = row.closest && row.closest(".ide-breadcrumb");
      var inAsi = row.closest && row.closest(".ide-asi-grid");
      if (!inTree && !inBreadcrumb && !inAsi) { return; }
      // Allow modifier-clicks to default (new tab etc.).
      if (ev.metaKey || ev.ctrlKey || ev.shiftKey) { return; }
      ev.preventDefault();
      var path = row.getAttribute("data-tree-path");
      var kind = row.getAttribute("data-tree-kind") || "";
      var severity = row.getAttribute("data-finding-severity") || "";
      openOrFocusTab(path, kind, severity);
    });
  }

  function bindTabClicks() {
    var strip = qs("[data-ide-tabs]");
    if (!strip) { return; }
    strip.addEventListener("click", function (ev) {
      var closeBtn = ev.target && ev.target.classList && ev.target.classList.contains("ide-tab__close");
      if (closeBtn) {
        var owner = ev.target.closest("[data-tree-path]");
        if (owner) {
          ev.preventDefault();
          ev.stopPropagation();
          closeTab(owner.getAttribute("data-tree-path"));
          return;
        }
      }
      var tab = ev.target && ev.target.closest && ev.target.closest(".ide-tab[data-tree-path]");
      if (!tab) { return; }
      activate(tab.getAttribute("data-tree-path"));
    });
    // Middle-click closes a tab.
    strip.addEventListener("auxclick", function (ev) {
      if (ev.button !== 1) { return; }
      var tab = ev.target && ev.target.closest && ev.target.closest(".ide-tab[data-tree-path]");
      if (!tab) { return; }
      ev.preventDefault();
      closeTab(tab.getAttribute("data-tree-path"));
    });
  }

  function bindThemeToggle() {
    var host = qs("[data-ide-switcher-host]");
    if (!host) { return; }
    qsa("[data-ide-theme-toggle]").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        var open = host.hasAttribute("hidden");
        if (open) {
          host.removeAttribute("hidden");
          var sel = qs("#ag-theme-switcher-select", host)
            || qs("select", host);
          if (sel) { sel.focus(); }
        } else {
          host.setAttribute("hidden", "");
        }
      });
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && !host.hasAttribute("hidden")) {
        host.setAttribute("hidden", "");
      }
    });
  }

  function bindCopyButtons() {
    var copyScan = qs("[data-ide-copy-scan-id]");
    if (copyScan) {
      copyScan.addEventListener("click", function (ev) {
        ev.preventDefault();
        var id = document.body.getAttribute("data-scan-id") || "";
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(id).catch(function () { /* swallow */ });
        }
      });
    }
    qsa("[data-ide-copy-finding-id]").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        var fid = btn.getAttribute("data-finding-id") || "";
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(fid).catch(function () { /* swallow */ });
        }
      });
    });
  }

  function bindActivityBar() {
    qsa(".ide-act-btn[data-act]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        qsa(".ide-act-btn[data-act]").forEach(function (other) {
          other.removeAttribute("data-active");
        });
        btn.setAttribute("data-active", "true");
        var act = btn.getAttribute("data-act");
        if (act === "findings") {
          var firstFinding = qs(".ide-tree__row--finding[data-tree-path]");
          if (firstFinding) {
            activate(firstFinding.getAttribute("data-tree-path"));
          }
        } else if (act === "trace") {
          activate("trace/timeline.json");
        }
      });
    });
  }

  function bindKeyboardShortcuts() {
    document.addEventListener("keydown", function (ev) {
      if (!ev.metaKey && !ev.ctrlKey) { return; }
      // Cmd/Ctrl+B → toggle sidebar.
      if (ev.key === "b" || ev.key === "B") {
        ev.preventDefault();
        var body = document.body;
        var current = parseInt(
          getComputedStyle(document.documentElement).getPropertyValue("--ide-sidebar-width"),
          10
        );
        if (isNaN(current) || current > 0) {
          body.setAttribute("data-sidebar-collapsed", "true");
          document.documentElement.style.setProperty("--ide-sidebar-width", "0px");
        } else {
          body.removeAttribute("data-sidebar-collapsed");
          var restored = parseInt(safeGet(LS_SIDEBAR_WIDTH) || "256", 10);
          document.documentElement.style.setProperty("--ide-sidebar-width", restored + "px");
        }
      }
      // Cmd/Ctrl+W → close active tab.
      if (ev.key === "w" || ev.key === "W") {
        var active = qs(".ide-tab--active[data-tree-path]");
        if (active) {
          ev.preventDefault();
          closeTab(active.getAttribute("data-tree-path"));
        }
      }
    });
  }

  /* ----------------------------------------------------------------------
   * URL bootstrap — honour ?file= so direct links land on the right tab.
   * ---------------------------------------------------------------------- */

  function bootstrapFromUrl() {
    var url;
    try { url = new URL(window.location.href); } catch (_) { return; }
    var file = url.searchParams.get("file");
    if (!file) { return; }
    var cell = findCell(file);
    if (!cell) { return; }
    var kind = cell.getAttribute("data-tree-kind") || "";
    var sevAttr = cell.getAttribute("data-finding-id");
    var severity = "";
    if (sevAttr) {
      var sevRow = qs('[data-finding-id="' + cssEscape(sevAttr) + '"][data-finding-severity]');
      if (sevRow) { severity = sevRow.getAttribute("data-finding-severity") || ""; }
    }
    openOrFocusTab(file, kind, severity);
  }

  /* ----------------------------------------------------------------------
   * Boot.
   * ---------------------------------------------------------------------- */

  function init() {
    restoreSidebarWidth();
    bindSidebarSash();
    bindTreeClicks();
    bindTabClicks();
    bindThemeToggle();
    bindCopyButtons();
    bindActivityBar();
    bindKeyboardShortcuts();
    bootstrapFromUrl();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
