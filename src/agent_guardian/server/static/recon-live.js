/* Recon-panel live update (#138).
 *
 * Pre-#138 the "Recon findings about this agent" section was rendered
 * once at page load. If the operator opened the dashboard before the
 * recon agent finished its sweep, the panel sat on its pending stub
 * ("Recon agent has not finished its sweep yet…") until they hit F5.
 *
 * This module owns a small EventSource against the per-scan
 * ``/scan/<id>/events`` stream and listens for the ``recon_done``
 * event. On arrival it re-fetches the dashboard HTML, plucks the
 * ``#exec-recon`` section, and swaps it in. One re-render per scan
 * (recon_done fires once); the EventSource closes after the swap
 * or on ``scan_done`` so we don't leak a stale connection.
 *
 * Same conventions as ``executive_charts.js`` / ``elapsed-ticker.js``
 * / ``phase-spine.js``: self-owned EventSource against the same
 * per-scan endpoint, no-op on terminal scans, no-op when EventSource
 * is unavailable, defer-loaded.
 */
(function () {
  "use strict";

  function reloadReconPanel(scanId) {
    var url = "/scan/" + encodeURIComponent(scanId);
    return window
      .fetch(url, { credentials: "same-origin", headers: { "Accept": "text/html" } })
      .then(function (resp) {
        if (!resp.ok) { throw new Error("recon-live: refetch " + resp.status); }
        return resp.text();
      })
      .then(function (html) {
        var parser = new DOMParser();
        var doc = parser.parseFromString(html, "text/html");
        var fresh = doc.querySelector("#exec-recon");
        var current = document.querySelector("#exec-recon");
        if (!fresh || !current) { return; }
        // replaceWith preserves the surrounding layout; no need to
        // re-mount any inline scripts (recon-panel.html is static markup).
        current.replaceWith(fresh);
      });
  }

  function attach() {
    var body = document.body;
    if (!body) { return; }
    var scanId = body.getAttribute("data-scan-id");
    if (!scanId) { return; }
    if (body.getAttribute("data-is-terminal") === "true") { return; }
    var es = window.AGStreams && window.AGStreams.events
      ? window.AGStreams.events(scanId)
      : null;
    if (!es) { return; }
    var reloaded = false;
    es.addEventListener("recon_done", function () {
      if (reloaded) { return; }
      reloaded = true;
      reloadReconPanel(scanId).catch(function (err) {
        try { console.error("AGReconLive: panel refresh failed", err); } catch (e) {}
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", attach);
  } else {
    attach();
  }

  window.AGReconLive = { attach: attach, reloadReconPanel: reloadReconPanel };
})();
