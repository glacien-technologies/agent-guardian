/* AGStreams — one EventSource per URL, shared across all modules.
 *
 * Chrome's HTTP/1.1 per-origin connection cap is 6. The executive
 * dashboard has historically had each live widget open its own
 * EventSource (snapshot stream for KPIs, snapshot stream for severity
 * bar, snapshot stream for ASI radar, snapshot stream for elapsed
 * ticker, events stream for live-append rows, events stream for the
 * phase spine, events stream for the recon-panel refresh, events
 * stream for the elapsed-ticker phase anchor, etc). That adds up to
 * ~9 long-lived TCP connections per page, well above the 6-connection
 * cap — the overflow EventSources queue forever and never deliver a
 * single frame.
 *
 * This module collapses every consumer onto two cached sources:
 *
 *   window.AGStreams.events(scanId)    →  /scan/<id>/events
 *   window.AGStreams.snapshot(scanId)  →  /scans/<id>/live
 *
 * Each function returns the EventSource directly so consumers keep
 * the same `source.addEventListener(...)` ergonomics they had before;
 * they just MUST NOT call `source.close()` — the shared source closes
 * itself on the scan_done frame. The browser's native EventSource
 * auto-reconnect handles transient network errors.
 */
(function () {
  if (typeof EventSource === "undefined") { return; }

  var cache = {};

  function getOrCreate(url) {
    var existing = cache[url];
    if (existing && existing.readyState !== 2 /* CLOSED */) {
      return existing;
    }
    var source;
    try {
      source = new EventSource(url);
    } catch (err) {
      try { console.error("AGStreams: open failed for", url, err); } catch (e) {}
      return null;
    }
    cache[url] = source;
    source.addEventListener("scan_done", function () {
      try { source.close(); } catch (e) {}
    });
    source.addEventListener("error", function () {
      try { console.warn(
        "AGStreams:", url, "error (readyState=" + source.readyState + ")"
      ); } catch (e) {}
    });
    return source;
  }

  window.AGStreams = {
    events: function (scanId) {
      if (!scanId) { return null; }
      return getOrCreate("/scan/" + encodeURIComponent(scanId) + "/events");
    },
    snapshot: function (scanId) {
      if (!scanId) { return null; }
      return getOrCreate("/scans/" + encodeURIComponent(scanId) + "/live");
    },
  };
})();
