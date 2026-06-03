/*
 * freshness-dot.js — peripheral-vision SSE freshness indicator + reconnect
 * banner for the Executive dashboard (SSE Phase 1, Step 5 of
 * designs/sse-flow-and-live-ui.md).
 *
 * One shared four-state machine driven by a single EventSource's
 * ``readyState`` plus ``Date.now() - lastEventAt`` — NOT a per-handler
 * status flip. The three empty / CLOSED-only ``onerror`` handlers
 * (``layout.html:89``, ``swarm.js:176-182``, ``reflections.js:284``) all
 * funnel into this module via ``window.AGFreshnessDot.attach(source)``.
 *
 *   LIVE          readyState===1 AND fresh<20s            -> .fresh (green)
 *   STALE         readyState===1 AND fresh in [20s,60s)   -> .stale (amber)
 *   RECONNECTING  readyState===0 (CONNECTING)             -> .stale + banner
 *   DEAD          readyState===2 (CLOSED) AND !scan_done  -> .dead  + banner
 *
 * ``requestAnimationFrame`` drives the freshness check (cheap, frame-
 * aligned, naturally pauses when the tab is backgrounded — the dot does
 * NOT page operators about an inactive tab).
 *
 * Heartbeat-from-data, NOT from ``:`` comments (critic patch G14/P5):
 * the server adds ``event: heartbeat\ndata: {"now":...}\n\n`` every 10 s
 * alongside the existing ``:`` keepalive. EventSource ``onmessage`` (or
 * a typed ``heartbeat`` listener) fires on the data heartbeat and
 * refreshes ``lastEventAt`` during legitimately quiet phases. The
 * comment-only keepalive does NOT drive the dot.
 *
 * Long-scan deadline (critic patch G5 / P-ScheduledReconnect): the
 * server sends ``event: deadline_approaching`` 30 s before
 * ``_LIVE_MAX_SECONDS = 1800.0`` forces a reconnect. The client
 * suppresses the red/DEAD transition for 60 s on receipt so a healthy
 * 30-minute scan crossing does not page operators.
 *
 * Click-to-retry: the DEAD-state banner is a button. Clicking it opens
 * a new EventSource against the SAME url the original source used.
 * Phase 1 does NOT send ``Last-Event-ID`` — phantom-jump avoidance is
 * Phase 2 work (the deque has no id index, ``events.jsonl`` has no
 * per-line ``seq``). On reconnect the spine repaints from the next
 * ``/live`` snapshot; KPI tiles repaint from the same snapshot.
 *
 * Accessibility (WCAG 1.4.1 / 2.5.5): color is paired with a text
 * label (``LIVE`` / ``STALE`` / ``OFFLINE``). When interactive (DEAD
 * banner button) the target is at least 24x24 CSS px — enforced in
 * executive.css via ``min-height``/``min-width`` on
 * ``.exec-freshness-banner__retry``.
 *
 * Plain ES5; no third-party deps. Same defensive compatibility envelope
 * as the other Step 1-4 modules in this directory.
 */
(function () {
  "use strict";

  // --- timing thresholds (ms) -------------------------------------------
  var FRESH_LIMIT_MS = 20 * 1000;
  var STALE_LIMIT_MS = 60 * 1000;
  var DEADLINE_SUPPRESS_MS = 60 * 1000;
  // Initial-connect grace window. A freshly created EventSource sits in
  // CONNECTING (readyState 0), and before any stream has attached the
  // aggregate readyState reads CLOSED (2). Neither is a genuine
  // "connection lost" — it's just the normal startup handshake. We
  // suppress the red/DEAD transition for this long after boot so an
  // operator who opens the UI the instant a scan starts never sees a
  // false "Connection lost. Click to retry." banner (2026-06-03 bug).
  // Once any stream confirms OPEN once, the grace is lifted early.
  var FIRST_CONNECT_GRACE_MS = 15 * 1000;

  // --- shared state across every attached EventSource ------------------
  // ``readyState`` from EventSource: 0 CONNECTING, 1 OPEN, 2 CLOSED.
  var STATE = {
    lastEventAt: Date.now(),
    readyState: 0,
    scanDone: false,
    suppressDeadUntil: 0,
    // End of the initial-connect grace window (epoch ms). Set in
    // ``boot()``; cleared (set to 0) the first time any stream reaches
    // OPEN so a genuine later disconnect is reported promptly.
    firstConnectGraceUntil: 0,
    everConnected: false,
    // Map of attached source -> { url } for click-to-retry. We keep the
    // newest non-CLOSED source as the "primary" — the dot reflects its
    // readyState. Multiple streams (events / live / reflections) can
    // attach; any one of them firing a message refreshes the clock.
    sources: [],
  };

  function now() {
    return Date.now();
  }

  // --- DOM helpers -----------------------------------------------------
  function findOrCreateDot() {
    var existing = document.querySelector(".exec-freshness-dot");
    if (existing) {
      return existing;
    }
    var topbarRight = document.querySelector(".exec-topbar__right");
    if (!topbarRight) {
      return null;
    }
    var wrap = document.createElement("div");
    wrap.className = "exec-freshness-dot";
    wrap.setAttribute("data-state", "fresh");
    wrap.setAttribute("role", "status");
    wrap.setAttribute("aria-live", "polite");
    wrap.setAttribute("aria-atomic", "true");

    var swatch = document.createElement("span");
    swatch.className = "exec-freshness-dot__swatch";
    swatch.setAttribute("aria-hidden", "true");

    var label = document.createElement("span");
    label.className = "exec-freshness-dot__label";
    label.textContent = "LIVE";

    wrap.appendChild(swatch);
    wrap.appendChild(label);
    // Insert before the locality pill so the dot sits on the far right.
    topbarRight.insertBefore(wrap, topbarRight.firstChild);
    return wrap;
  }

  function findOrCreateBanner() {
    var existing = document.querySelector(".exec-freshness-banner");
    if (existing) {
      return existing;
    }
    var anchor = document.querySelector(".exec-spine");
    var body = document.body;
    if (!body) {
      return null;
    }
    var banner = document.createElement("div");
    banner.className = "exec-freshness-banner";
    banner.setAttribute("hidden", "");
    banner.setAttribute("role", "status");
    banner.setAttribute("aria-live", "polite");

    var msg = document.createElement("span");
    msg.className = "exec-freshness-banner__msg";
    msg.textContent = "Reconnecting to event stream...";

    var retry = document.createElement("button");
    retry.type = "button";
    retry.className = "exec-freshness-banner__retry";
    retry.textContent = "Retry";
    retry.setAttribute("hidden", "");
    retry.addEventListener("click", reconnectAll);

    banner.appendChild(msg);
    banner.appendChild(retry);

    if (anchor && anchor.parentNode) {
      anchor.parentNode.insertBefore(banner, anchor);
    } else {
      body.insertBefore(banner, body.firstChild);
    }
    return banner;
  }

  function setVisualState(state) {
    var dot = findOrCreateDot();
    var banner = findOrCreateBanner();
    if (dot) {
      dot.setAttribute("data-state", state);
      var label = dot.querySelector(".exec-freshness-dot__label");
      if (label) {
        if (state === "fresh") {
          label.textContent = "LIVE";
        } else if (state === "stale" || state === "reconnecting") {
          label.textContent = "STALE";
        } else if (state === "dead") {
          label.textContent = "OFFLINE";
        }
      }
    }
    if (banner) {
      var msg = banner.querySelector(".exec-freshness-banner__msg");
      var retry = banner.querySelector(".exec-freshness-banner__retry");
      if (state === "reconnecting") {
        banner.removeAttribute("hidden");
        banner.setAttribute("data-state", "reconnecting");
        if (msg) {
          msg.textContent = "Reconnecting to event stream...";
        }
        if (retry) {
          retry.setAttribute("hidden", "");
        }
      } else if (state === "dead") {
        banner.removeAttribute("hidden");
        banner.setAttribute("data-state", "dead");
        if (msg) {
          msg.textContent = "Connection lost. Click to retry.";
        }
        if (retry) {
          retry.removeAttribute("hidden");
        }
      } else {
        banner.setAttribute("hidden", "");
        banner.removeAttribute("data-state");
      }
    }
  }

  // --- four-state machine ----------------------------------------------
  function aggregateReadyState() {
    // Pick the "best" readyState across all attached sources:
    //   OPEN(1) wins over CONNECTING(0) wins over CLOSED(2).
    // This way one stream's hard CLOSED does not flip the dot to DEAD
    // while the others are still healthily open.
    var best = 2; // CLOSED
    for (var i = 0; i < STATE.sources.length; i += 1) {
      var src = STATE.sources[i].source;
      if (!src) {
        continue;
      }
      if (src.readyState === 1) {
        // First confirmed OPEN lifts the initial-connect grace window —
        // from here on a real CLOSED is reported as DEAD promptly.
        STATE.everConnected = true;
        STATE.firstConnectGraceUntil = 0;
        return 1;
      }
      if (src.readyState === 0 && best !== 1) {
        best = 0;
      }
    }
    return best;
  }

  // True while we're still inside the post-boot initial-connect window
  // AND no stream has ever confirmed OPEN. During this window CONNECTING
  // / not-yet-attached / CLOSED are all treated as "still connecting"
  // rather than a genuine disconnect, so the UI never flashes a false
  // "Connection lost" before the first handshake completes.
  function inFirstConnectGrace() {
    return (
      !STATE.everConnected &&
      STATE.firstConnectGraceUntil > 0 &&
      now() < STATE.firstConnectGraceUntil
    );
  }

  function computeState() {
    if (STATE.scanDone) {
      return "fresh";
    }
    var rs = aggregateReadyState();
    var sinceLast = now() - STATE.lastEventAt;
    if (rs === 1) {
      if (sinceLast < FRESH_LIMIT_MS) {
        return "fresh";
      }
      if (sinceLast < STALE_LIMIT_MS) {
        return "stale";
      }
      // Open but no events for >60s — treat as DEAD unless suppressed
      // by a recent ``deadline_approaching`` from the server.
      if (now() < STATE.suppressDeadUntil) {
        return "stale";
      }
      return "dead";
    }
    if (rs === 0) {
      // CONNECTING. During the initial-connect grace this is just the
      // normal first handshake — keep the dot in its resting ``fresh``
      // state instead of flashing the reconnecting banner on every load.
      if (inFirstConnectGrace()) {
        return "fresh";
      }
      return "reconnecting";
    }
    // rs === 2 (CLOSED) and scan still running — also the resting state
    // before any source has attached (sources is empty -> aggregate
    // reads CLOSED). During the initial-connect grace this is NOT a
    // disconnect; rest as ``fresh`` so the first paint shows a calm dot
    // rather than a false "Connection lost" banner.
    if (inFirstConnectGrace()) {
      return "fresh";
    }
    // A recent ``deadline_approaching`` suppresses the DEAD transition
    // while the long-scan reconnect happens.
    if (now() < STATE.suppressDeadUntil) {
      return "reconnecting";
    }
    return "dead";
  }

  var _lastVisualState = null;
  function tick() {
    var state = computeState();
    if (state !== _lastVisualState) {
      setVisualState(state);
      _lastVisualState = state;
    }
    if (typeof window.requestAnimationFrame === "function") {
      window.requestAnimationFrame(tick);
    } else {
      window.setTimeout(tick, 250);
    }
  }

  // --- attach to an EventSource ---------------------------------------
  function attach(source, opts) {
    if (!source) {
      return;
    }
    var url = (opts && opts.url) || source.url || null;
    // Optional caller-supplied factory that returns a FRESH, fully-wired
    // EventSource (same url, all data handlers re-bound). Used by the
    // click-to-retry path so the reopened stream keeps its snapshot /
    // live-append handlers — a bare ``new EventSource(url)`` here would
    // reconnect the socket but lose every downstream listener.
    var reconnect =
      opts && typeof opts.reconnect === "function" ? opts.reconnect : null;
    var record = { source: source, url: url, reconnect: reconnect };
    STATE.sources.push(record);

    function refresh() {
      STATE.lastEventAt = now();
    }

    // ``open`` confirms a live handshake — lift the initial-connect
    // grace window immediately so a genuine later disconnect is reported
    // without waiting out the remaining grace.
    source.addEventListener("open", function () {
      STATE.everConnected = true;
      STATE.firstConnectGraceUntil = 0;
      refresh();
    });

    // Generic onmessage covers the new ``event: heartbeat`` (which has
    // no ``addEventListener`` registration anywhere else) plus any
    // un-typed events.
    var prevOnMessage = source.onmessage;
    source.onmessage = function (evt) {
      refresh();
      if (typeof prevOnMessage === "function") {
        try {
          prevOnMessage.call(source, evt);
        } catch (err) {
          /* swallow downstream handler errors */
        }
      }
    };

    // Typed heartbeat listener for browsers that bind event-type
    // routing strictly (some EventSource polyfills do not call
    // onmessage when a typed event is dispatched).
    source.addEventListener("heartbeat", refresh);

    // Any of the existing typed events also refreshes — they all imply
    // the stream is live.
    var KNOWN_EVENTS = [
      "snapshot",
      "phase_start",
      "phase_done",
      "recon_start",
      "recon_done",
      "agent_start",
      "agent_done",
      "agent_skipped",
      "checkpoint",
      "finding",
      "aivss_update",
      "reflection",
    ];
    for (var i = 0; i < KNOWN_EVENTS.length; i += 1) {
      source.addEventListener(KNOWN_EVENTS[i], refresh);
    }

    source.addEventListener("scan_done", function () {
      STATE.scanDone = true;
    });

    source.addEventListener("deadline_approaching", function () {
      STATE.suppressDeadUntil = now() + DEADLINE_SUPPRESS_MS;
    });

    // We deliberately do not register ``source.onerror`` here — the
    // call site keeps ownership of any module-specific error logic (eg
    // swarm.js sets a status message). The freshness dot only reads
    // ``readyState`` via ``aggregateReadyState`` on every rAF tick.
  }

  // --- click-to-retry --------------------------------------------------
  // Bound to the dynamically-created banner's Retry button in
  // ``findOrCreateBanner``. Closes every attached EventSource and opens
  // a fresh one to the SAME url, then resets the freshness state. When a
  // source carries a caller-supplied ``reconnect`` factory we use it so
  // the reopened stream keeps its downstream data handlers (snapshot /
  // live-append); otherwise we fall back to a bare reopen via
  // ``attachReuse`` (freshness-only — the dot recovers but data rows
  // won't re-bind).
  function reconnectAll() {
    var reopened = [];
    for (var i = 0; i < STATE.sources.length; i += 1) {
      var rec = STATE.sources[i];
      try {
        if (rec.source && typeof rec.source.close === "function") {
          rec.source.close();
        }
      } catch (err) {
        /* swallow — best-effort close */
      }
      if (rec.reconnect) {
        try {
          var rewired = rec.reconnect();
          if (rewired) {
            rec.source = rewired;
            reopened.push(rec);
            continue;
          }
        } catch (err) {
          /* swallow — fall through to bare reopen below */
        }
      }
      if (!rec.url) {
        // No url and no factory — nothing to reopen; keep the record so
        // the source count stays stable, but it stays CLOSED.
        reopened.push(rec);
        continue;
      }
      try {
        // Phase 1 fallback: no Last-Event-ID. Resync rides on the next
        // ``/live`` snapshot.
        var fresh = new window.EventSource(rec.url);
        rec.source = fresh;
        attachReuse(fresh, rec);
        reopened.push(rec);
      } catch (err) {
        /* swallow — connection failure */
      }
    }
    STATE.sources = reopened;
    STATE.lastEventAt = now();
    STATE.scanDone = false;
    // Treat a manual retry like a fresh boot: re-open a grace window and
    // clear ``everConnected`` so a still-connecting socket doesn't snap
    // straight back to the DEAD banner before the new handshake lands.
    STATE.everConnected = false;
    STATE.firstConnectGraceUntil = now() + FIRST_CONNECT_GRACE_MS;
    STATE.suppressDeadUntil = 0;
    // Force the next ``tick`` to re-render even if the computed state
    // matches the cached one.
    _lastVisualState = null;
  }

  function attachReuse(source, record) {
    // Internal variant of ``attach()`` for the click-to-retry path:
    // does NOT push a new record (the caller already owns one).
    function refresh() {
      STATE.lastEventAt = now();
    }
    source.addEventListener("open", function () {
      STATE.everConnected = true;
      STATE.firstConnectGraceUntil = 0;
      refresh();
    });
    source.onmessage = refresh;
    source.addEventListener("heartbeat", refresh);
    source.addEventListener("scan_done", function () {
      STATE.scanDone = true;
    });
    source.addEventListener("deadline_approaching", function () {
      STATE.suppressDeadUntil = now() + DEADLINE_SUPPRESS_MS;
    });
  }

  // --- public surface --------------------------------------------------
  window.AGFreshnessDot = {
    attach: attach,
    state: function () {
      return computeState();
    },
    // Exposed for unit tests / debugging only — production code MUST go
    // through ``attach()``.
    _state: STATE,
  };

  function boot() {
    var body = document.body;
    if (!body) {
      return;
    }
    if (body.getAttribute("data-is-terminal") === "true") {
      // Terminal scans never open an EventSource (layout.html short-
      // circuits). Render the dot in a permanent ``fresh`` resting
      // state for visual consistency and exit.
      setVisualState("fresh");
      return;
    }
    // Open the initial-connect grace window so the first handshake
    // (sources not yet attached / EventSource still CONNECTING) does not
    // trip the false "Connection lost" banner.
    STATE.firstConnectGraceUntil = now() + FIRST_CONNECT_GRACE_MS;
    findOrCreateDot();
    findOrCreateBanner();
    setVisualState("fresh");
    tick();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
