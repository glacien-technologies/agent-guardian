/* Executive — KPI tile interactions (QA-039 + QA-044, 2026-06-02).
 *
 *   - Click on the ⓘ button toggles the prose info popover for that tile.
 *   - Clicking outside / pressing Escape closes any open info popover.
 *   - Only one info popover is open at a time.
 *   - The hover data-table is pure CSS (.exec-kpi:hover) — JS only owns the
 *     ⓘ-click affordance and the open/close state class on the tile.
 *
 * Vanilla JS only — no dependencies, mounts at DOMContentLoaded, defensive
 * about missing nodes so a future template restructure does not break the
 * page.
 */
(function () {
  "use strict";

  function closeAll(except) {
    var open = document.querySelectorAll(".exec-kpi.is-info-open");
    for (var i = 0; i < open.length; i += 1) {
      var tile = open[i];
      if (tile === except) { continue; }
      tile.classList.remove("is-info-open");
      var btn = tile.querySelector(".kpi-info-icon");
      if (btn) { btn.setAttribute("aria-expanded", "false"); }
      var pop = tile.querySelector(".kpi-info-popover");
      if (pop) { pop.setAttribute("hidden", ""); }
    }
  }

  function toggle(btn) {
    var tile = btn.closest(".exec-kpi");
    if (!tile) { return; }
    var pop = tile.querySelector(".kpi-info-popover");
    if (!pop) { return; }
    var isOpen = tile.classList.contains("is-info-open");
    closeAll(isOpen ? null : tile);
    if (isOpen) {
      tile.classList.remove("is-info-open");
      btn.setAttribute("aria-expanded", "false");
      pop.setAttribute("hidden", "");
    } else {
      tile.classList.add("is-info-open");
      btn.setAttribute("aria-expanded", "true");
      pop.removeAttribute("hidden");
    }
  }

  function boot() {
    var buttons = document.querySelectorAll(".kpi-info-icon");
    for (var i = 0; i < buttons.length; i += 1) {
      (function (btn) {
        btn.addEventListener("click", function (ev) {
          ev.preventDefault();
          ev.stopPropagation();
          toggle(btn);
        });
        btn.addEventListener("keydown", function (ev) {
          if (ev.key === "Enter" || ev.key === " ") {
            ev.preventDefault();
            toggle(btn);
          }
        });
      })(buttons[i]);
    }
    document.addEventListener("click", function (ev) {
      // Clicking outside any tile closes the open popover.
      if (!ev.target || !ev.target.closest) { closeAll(null); return; }
      var tile = ev.target.closest(".exec-kpi.is-info-open");
      if (!tile) { closeAll(null); }
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") { closeAll(null); }
    });

    // QA — the FINDINGS and PROBES tiles open their corresponding tab.
    var navTiles = document.querySelectorAll(
      '.exec-kpi[data-kpi="findings"], .exec-kpi[data-kpi="probes"]',
    );
    for (var j = 0; j < navTiles.length; j += 1) {
      (function (tile) {
        var tabId = tile.getAttribute("data-kpi");
        tile.classList.add("exec-kpi--clickable");
        tile.setAttribute("role", "link");
        tile.setAttribute("tabindex", "0");
        function go() {
          var tab = document.getElementById("tab-" + tabId);
          if (tab) { tab.click(); }
        }
        tile.addEventListener("click", function (ev) {
          // Leave the ⓘ info button (and any inner control) to its own handler.
          if (ev.target && ev.target.closest && ev.target.closest("button, a")) { return; }
          go();
        });
        tile.addEventListener("keydown", function (ev) {
          if (ev.key === "Enter") { ev.preventDefault(); go(); }
        });
      })(navTiles[j]);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
