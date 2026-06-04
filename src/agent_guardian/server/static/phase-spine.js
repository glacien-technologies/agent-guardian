/*
 * phase-spine.js — drives the four-pill Executive Phase Spine
 * (SSE Phase 1, Step 3 of designs/sse-flow-and-live-ui.md).
 *
 * Subscribes to two streams already opened by the dashboard:
 *
 *   1. ``/scan/<id>/events`` — per-event SSE feed. We listen to
 *      ``phase_start`` / ``phase_done`` to flip pill state, and to
 *      ``agent_start`` / ``agent_done`` / ``agent_skipped`` to advance the
 *      active phase's sub-bar. ``recon_start`` / ``recon_done`` are
 *      handled the same way for the RECON pill (the producer emits both
 *      the typed and the generic ``phase_*`` envelopes around the recon
 *      block, but we accept either as a transition).
 *
 *   2. ``/scans/<id>/live`` — periodic snapshot. We listen for the
 *      ``snapshot`` event and reconcile each pill's
 *      ``agents_completed`` / ``agents_total`` / ``state`` from
 *      ``data.phase_state``. This is how a late-joining tab paints —
 *      the per-scan ``asyncio.Queue`` at ``scan_store.py:736-750`` is
 *      destructively drained so the second tab cannot rely on the
 *      events stream alone (documented multi-tab race, critic patch
 *      G11/P11).
 *
 * Idempotence rule (critic patch G11/P11):
 *
 *     agents_completed = max(local_count, snapshot.phase_state[phase].agents_completed)
 *
 * The sub-bar never animates backward — a missed ``agent_done`` event
 * on tab 2 is healed by the next snapshot reconciliation, not by a
 * rewind.
 *
 * Terminal scans (``data-is-terminal === 'true'``) short-circuit: the
 * Jinja template already server-renders every pill in its final state
 * from ``phase_state``, and the layout shell's SSE bootstrap returns
 * early at ``layout.html:74`` so no EventSource is opened. This module
 * mirrors that guard.
 *
 * No third-party dependencies. Plain ES5 for the same defensive
 * compatibility envelope as ``layout.html``'s inline patcher.
 */
(function () {
  "use strict";

  var PHASES = ["recon", "decompose", "parallel", "finalise"];
  var TERMINAL_STATES = { done: true, skipped: true };

  function $spine() {
    return document.querySelector(".exec-spine");
  }

  function pillFor(phase) {
    return document.querySelector('.exec-spine__pill[data-phase="' + phase + '"]');
  }

  function readInt(node, attr) {
    if (!node) {
      return 0;
    }
    var raw = node.getAttribute(attr);
    var n = parseInt(raw, 10);
    return isFinite(n) && n >= 0 ? n : 0;
  }

  function setPillState(pill, state) {
    if (!pill || !state) {
      return;
    }
    var current = pill.getAttribute("data-state");
    if (current === state) {
      return;
    }
    // Don't regress a terminal state. Once a pill is ``done`` or
    // ``skipped`` it stays that way for the rest of the scan; a
    // late-arriving ``phase_start`` from a buffered replay cannot
    // un-finish a finished phase.
    if (TERMINAL_STATES[current] && !TERMINAL_STATES[state]) {
      return;
    }
    pill.setAttribute("data-state", state);
    var label = pill.querySelector("[data-phase-state-label]");
    if (label) {
      label.textContent = state;
    }
  }

  function setActivePhase(phase) {
    var spine = $spine();
    if (!spine) {
      return;
    }
    spine.setAttribute("data-current-phase", phase || "");
    var pills = document.querySelectorAll(".exec-spine__pill");
    for (var i = 0; i < pills.length; i += 1) {
      var p = pills[i];
      if (p.getAttribute("data-phase") === phase) {
        p.setAttribute("data-active", "true");
      } else {
        p.removeAttribute("data-active");
      }
    }
  }

  function advanceSubBar(phase, nextCompleted, nextTotal) {
    var pill = pillFor(phase);
    if (!pill) {
      return;
    }
    var bar = pill.querySelector(".exec-spine__sub");
    if (!bar) {
      return;
    }
    var localCompleted = readInt(bar, "data-completed");
    var localTotal = readInt(bar, "data-total");
    // Idempotent advance — never regress (critic patch G11/P11).
    var completed = Math.max(localCompleted, nextCompleted || 0);
    var total = Math.max(localTotal, nextTotal || 0);
    bar.setAttribute("data-completed", String(completed));
    bar.setAttribute("data-total", String(total));
    bar.setAttribute("aria-valuenow", String(completed));
    bar.setAttribute("aria-valuemax", String(total || 1));
    var pct;
    if (total > 0) {
      pct = Math.min(100, Math.max(0, (100 * completed) / total));
    } else {
      // No total yet — paint based on pill state. ``done`` is full,
      // anything else is empty.
      pct = pill.getAttribute("data-state") === "done" ? 100 : 0;
    }
    var fill = bar.querySelector(".exec-spine__sub-fill");
    if (fill) {
      fill.style.width = pct + "%";
    }
    var count = pill.querySelector("[data-phase-count]");
    if (count) {
      count.textContent = completed + "/" + total;
    }
  }

  function applyPhaseStart(phase, payload) {
    if (PHASES.indexOf(phase) < 0) {
      return;
    }
    var pill = pillFor(phase);
    if (!pill) {
      return;
    }
    setPillState(pill, "running");
    setActivePhase(phase);
    if (payload && typeof payload === "object") {
      advanceSubBar(
        phase,
        Number(payload.agents_completed) || 0,
        Number(payload.agents_total) || 0,
      );
    }
  }

  function applyPhaseDone(phase, payload) {
    if (PHASES.indexOf(phase) < 0) {
      return;
    }
    var pill = pillFor(phase);
    if (!pill) {
      return;
    }
    setPillState(pill, "done");
    if (payload && typeof payload === "object") {
      // On done, fill to the final total — but still idempotent so a
      // stale tab that already saw a higher count does not regress.
      var total = Number(payload.agents_total) || 0;
      var completed = Number(payload.agents_completed) || total;
      advanceSubBar(phase, completed, total);
    } else {
      // Best-effort: snap to a full bar.
      var bar = pill.querySelector(".exec-spine__sub");
      var total2 = readInt(bar, "data-total");
      advanceSubBar(phase, total2, total2);
    }
    // ``current_phase`` is left at the last-running phase by
    // dashboard_view._compute_phase_state when nothing has started yet
    // after a done. We do the same client-side — clear data-active on
    // the pill but leave data-current-phase pointing at this phase so
    // the caption can keep its anchor. The next phase_start updates it.
    var pill2 = pillFor(phase);
    if (pill2) {
      pill2.removeAttribute("data-active");
    }
  }

  function applyAgentBump(payload) {
    var spine = $spine();
    if (!spine) {
      return;
    }
    var current = spine.getAttribute("data-current-phase");
    if (!current) {
      // No active phase yet — most likely a recon_start arrived before
      // the typed phase_start. Use ``recon`` as the safe default.
      current = "recon";
    }
    if (PHASES.indexOf(current) < 0) {
      return;
    }
    var pill = pillFor(current);
    if (!pill) {
      return;
    }
    var bar = pill.querySelector(".exec-spine__sub");
    if (!bar) {
      return;
    }
    var nextCompleted = readInt(bar, "data-completed") + 1;
    var nextTotal = readInt(bar, "data-total");
    // Don't overshoot the snapshot total — the server is authoritative
    // for the denominator.
    if (nextTotal && nextCompleted > nextTotal) {
      nextCompleted = nextTotal;
    }
    advanceSubBar(current, nextCompleted, nextTotal);
  }

  // SSE Phase 2 Step 2.3 — ``agent_progress`` smoothing.
  //
  // Producer (agents/base.py) emits one ``agent_progress`` event at the
  // TOP of every turn, BEFORE the strategy LLM call. The dashboard's
  // sub-bar otherwise jumps from ``agent_done`` to ``agent_done`` with
  // long quiet stretches in between (each agent runs multi-turn). We
  // interpolate the bar BETWEEN those done-arrivals using a fractional
  // ``turn / max_turns`` ratio, so the operator sees forward motion
  // every turn rather than a stalled bar followed by a sudden hop.
  //
  // The advance is a fraction of ONE agent slot:
  //
  //     fractional = agents_completed + (turn / max_turns)
  //
  // We feed that into ``advanceSubBar`` with a per-pill flag that
  // permits fractional widths (the integer count + denominator are
  // still authoritative for the ``count`` caption — only the fill
  // width gets the smooth interpolation). The smoothing is CSS-driven
  // — ``.exec-spine__sub-fill`` carries a width transition, so each
  // width update animates over ~300ms without us scheduling rAF here.
  function applyAgentProgress(payload) {
    if (!payload || typeof payload !== "object") {
      return;
    }
    var spine = $spine();
    if (!spine) {
      return;
    }
    var current = spine.getAttribute("data-current-phase") || "recon";
    if (PHASES.indexOf(current) < 0) {
      return;
    }
    var pill = pillFor(current);
    if (!pill) {
      return;
    }
    var bar = pill.querySelector(".exec-spine__sub");
    if (!bar) {
      return;
    }
    var turn = Number(payload.turn) || 0;
    var maxTurns = Number(payload.max_turns) || 0;
    if (maxTurns <= 0 || turn <= 0) {
      return;
    }
    var localCompleted = readInt(bar, "data-completed");
    var localTotal = readInt(bar, "data-total");
    if (localTotal <= 0) {
      return;
    }
    // Fractional slot share: each agent contributes 1/localTotal to the
    // sub-bar, and within an agent the turn ratio contributes
    // (turn-1)/maxTurns (the -1 keeps the bar from already showing
    // "done" at turn 1; the agent_done arrival is what claims the full
    // slot).
    var perSlot = 1 / localTotal;
    var withinSlot = Math.max(0, Math.min(1, (turn - 1) / maxTurns));
    var fractional = localCompleted / localTotal + perSlot * withinSlot;
    // Cap at the next full slot — never pre-claim the agent_done bump
    // (which is integer-only and idempotent against this fractional
    // width via ``Math.max`` below).
    var ceiling = (localCompleted + 1) / localTotal;
    if (fractional > ceiling) {
      fractional = ceiling;
    }
    var pct = Math.min(100, Math.max(0, 100 * fractional));
    var fill = bar.querySelector(".exec-spine__sub-fill");
    if (fill) {
      // Compare against the current width so we never animate the bar
      // backward (matches the idempotence rule in advanceSubBar).
      var currentPct = parseFloat(fill.style.width) || 0;
      if (pct > currentPct) {
        fill.style.width = pct + "%";
      }
    }
    // The integer ``data-completed`` / count caption are NOT touched —
    // those remain authoritative for screen readers and the snapshot
    // reconciler (a fractional aria-valuenow would lie about agent
    // count). Only the fill width gets the smooth interpolation.
  }

  function reconcileFromSnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== "object") {
      return;
    }
    var phaseState = snapshot.phase_state;
    if (!phaseState || typeof phaseState !== "object") {
      return;
    }
    var phases = phaseState.phases || {};
    for (var i = 0; i < PHASES.length; i += 1) {
      var name = PHASES[i];
      var slot = phases[name];
      if (!slot || typeof slot !== "object") {
        continue;
      }
      var pill = pillFor(name);
      if (!pill) {
        continue;
      }
      var snapState = slot.state;
      // Apply terminal states authoritatively; never let a snapshot
      // drag a pill backward out of ``done`` / ``skipped`` either.
      if (snapState === "running" || snapState === "done" || snapState === "skipped") {
        setPillState(pill, snapState);
      }
      var snapCompleted = Number(slot.agents_completed) || 0;
      var snapTotal = Number(slot.agents_total) || 0;
      advanceSubBar(name, snapCompleted, snapTotal);
      // Live recon probe counter — while recon is running, caption the pill
      // with "N probes" (from the capability audit) instead of the 0/1 agent
      // count, so the dashboard shows recon is actively working.
      if (name === "recon" && snapState === "running") {
        var probes = Number(slot.probes) || 0;
        if (probes > 0) {
          var reconCount = pill.querySelector("[data-phase-count]");
          if (reconCount) {
            reconCount.textContent = probes + (probes === 1 ? " probe" : " probes");
          }
        }
      }
    }
    var current = phaseState.current_phase;
    if (current && PHASES.indexOf(current) >= 0) {
      var pill = pillFor(current);
      // Only promote to active if it's not already in a terminal state.
      if (pill && !TERMINAL_STATES[pill.getAttribute("data-state")]) {
        setActivePhase(current);
      }
    }
  }

  function openEventStreams(scanId) {
    if (typeof EventSource === "undefined") {
      return;
    }
    var url = "/scan/" + encodeURIComponent(scanId) + "/events";
    var es;
    try {
      es = new EventSource(url);
    } catch (err) {
      return;
    }

    function parsePayload(evt) {
      try {
        return JSON.parse(evt.data);
      } catch (err) {
        return null;
      }
    }

    // SSE Phase 1, Step 6 — tab-bar badge bus wiring.
    // The spine is the single fan-out point for ``/scan/<id>/events``,
    // so it bumps the badge bus on behalf of the tab buttons. The bus
    // is a thin chip primitive and intentionally doesn't open its own
    // EventSource. Reflection arrivals (LOGS badge) are wired
    // separately in ``reflections.js`` because the reflection stream
    // is a different endpoint (``/scans/<id>/reflections.sse``).
    function bumpBadge(tab, n, severity) {
      if (
        typeof window === "undefined" ||
        !window.AGTabBadgeBus ||
        typeof window.AGTabBadgeBus.bump !== "function"
      ) {
        return;
      }
      var opts = severity ? { severity: severity } : undefined;
      window.AGTabBadgeBus.bump(tab, n, opts);
    }

    es.addEventListener("phase_start", function (evt) {
      var data = parsePayload(evt);
      if (!data) {
        return;
      }
      var payload = data.payload || data;
      applyPhaseStart(payload && payload.phase ? payload.phase : data.phase, payload);
    });
    es.addEventListener("phase_done", function (evt) {
      var data = parsePayload(evt);
      if (!data) {
        return;
      }
      var payload = data.payload || data;
      applyPhaseDone(payload && payload.phase ? payload.phase : data.phase, payload);
    });
    es.addEventListener("recon_start", function () {
      applyPhaseStart("recon", null);
    });
    es.addEventListener("recon_done", function () {
      applyPhaseDone("recon", null);
    });
    es.addEventListener("agent_start", function () {
      // agent_start doesn't bump the spine counter — only agent_done /
      // agent_skipped do. We use it only to confirm the active phase
      // has work in flight (no-op for the spine; reserved for the
      // per-pill running-agent caption in Phase 2).
      // SSE Phase 1, Step 6 — bump the PROBES badge by 1 on each
      // agent_start arrival so an operator on a different tab sees
      // probe activity. Severity ``notice`` (informational, not alert).
      bumpBadge("probes", 1, "notice");
    });
    // SSE Phase 2 Step 2.3 — smooth sub-bar progress between
    // agent_done arrivals using per-turn ``agent_progress`` events
    // (one per turn, emitted at the top of the agent loop before the
    // strategy LLM call). See ``applyAgentProgress`` above for the
    // fractional-slot interpolation logic.
    es.addEventListener("agent_progress", function (evt) {
      var data = parsePayload(evt);
      if (!data) {
        return;
      }
      applyAgentProgress(data.payload || data);
    });
    es.addEventListener("agent_done", function (evt) {
      var data = parsePayload(evt);
      var payload = data ? data.payload || data : null;
      applyAgentBump(payload);
      // SSE Phase 1, Step 6 — PROBES badge tracks every agent arrival.
      bumpBadge("probes", 1, "notice");
      // FINDINGS badge tracks discovered findings only. Severity
      // ``alert`` because the operator-pain target is "I missed a
      // finding because the count bumped silently."
      var count = 0;
      if (payload && typeof payload === "object") {
        var raw = Number(payload.findings_count);
        if (isFinite(raw) && raw > 0) {
          count = Math.floor(raw);
        }
      }
      if (count > 0) {
        bumpBadge("findings", count, "alert");
      }
    });
    es.addEventListener("agent_skipped", function (evt) {
      var data = parsePayload(evt);
      applyAgentBump(data ? data.payload || data : null);
      // SSE Phase 1, Step 6 — a skipped agent still counts as PROBES
      // activity (the slot ran, just with no work).
      bumpBadge("probes", 1, "notice");
    });
    es.addEventListener("scan_done", function () {
      try {
        es.close();
      } catch (err) {
        /* swallow */
      }
    });
    es.onerror = function () {
      /* browser auto-reconnects; freshness-dot.js will handle visuals */
    };

    // Snapshot stream — reconciles state with the server every 500ms.
    // Critical for late-joining tabs where the events queue was already
    // drained.
    var snapUrl = "/scans/" + encodeURIComponent(scanId) + "/live";
    var snapES;
    try {
      snapES = new EventSource(snapUrl);
    } catch (err) {
      return;
    }
    snapES.addEventListener("snapshot", function (evt) {
      var data = parsePayload(evt);
      if (data) {
        reconcileFromSnapshot(data);
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

  function init() {
    var spine = $spine();
    if (!spine) {
      return;
    }
    var body = document.body;
    var scanId = body.getAttribute("data-scan-id");
    if (!scanId) {
      return;
    }
    // Terminal scans: the spine is already server-rendered in its
    // final state. Don't open SSE connections.
    if (body.getAttribute("data-is-terminal") === "true") {
      return;
    }
    openEventStreams(scanId);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
