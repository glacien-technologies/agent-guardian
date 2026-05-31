/* AgentGuardian dashboard theme switcher (QA-020).
 *
 * Persists the operator's preferred theme to localStorage and applies it on
 * first paint when the current URL does not already pin a theme via ?theme=.
 *
 * Behaviour matrix:
 *
 *   URL has ?theme=...     | localStorage has value | Action
 *   -----------------------+------------------------+----------------------------
 *   yes                    | -                      | respect URL, write to LS
 *   no                     | yes, differs from page | redirect to ?theme=<stored>
 *   no                     | yes, matches page      | no-op
 *   no                     | no                     | no-op (server default wins)
 *
 * On dropdown change: write the new slug to localStorage AND navigate to
 * ?theme=<new>. Falls back to a plain reload when localStorage throws
 * (private-mode Safari, disabled storage) so the operator still gets the
 * theme change, just without the persistence.
 *
 * No dependencies; no framework; safe to load with `defer`.
 */
(function () {
  "use strict";

  var STORAGE_KEY = "ag.dashboard.theme";
  var VALID_THEMES = ["editorial", "mission", "narrative", "ide"];

  function safeRead() {
    try {
      var v = window.localStorage.getItem(STORAGE_KEY);
      if (v && VALID_THEMES.indexOf(v) !== -1) {
        return v;
      }
      return null;
    } catch (err) {
      return null;
    }
  }

  function safeWrite(value) {
    try {
      window.localStorage.setItem(STORAGE_KEY, value);
    } catch (err) {
      /* private mode, quota exceeded — silently ignore */
    }
  }

  function buildHref(slug) {
    try {
      var url = new URL(window.location.href);
      url.searchParams.set("theme", slug);
      return url.toString();
    } catch (err) {
      return "?theme=" + encodeURIComponent(slug);
    }
  }

  function init() {
    var sel = document.getElementById("ag-theme-switcher-select");
    if (!sel || sel.dataset.bound === "1") {
      return;
    }
    sel.dataset.bound = "1";

    var current = sel.dataset.current || "editorial";

    // On change: persist + navigate.
    sel.addEventListener("change", function (evt) {
      var target = evt.target;
      var next = target && target.value;
      if (!next || VALID_THEMES.indexOf(next) === -1) {
        return;
      }
      safeWrite(next);
      window.location.assign(buildHref(next));
    });

    // First-paint redirect: if no ?theme= in URL and localStorage has a value
    // different from the server-rendered theme, jump to the stored choice.
    var url;
    try {
      url = new URL(window.location.href);
    } catch (err) {
      return;
    }
    if (url.searchParams.has("theme")) {
      // URL pins the theme — sync localStorage so a future plain navigation
      // remembers this choice.
      safeWrite(current);
      return;
    }
    var stored = safeRead();
    if (stored && stored !== current) {
      url.searchParams.set("theme", stored);
      window.location.replace(url.toString());
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
