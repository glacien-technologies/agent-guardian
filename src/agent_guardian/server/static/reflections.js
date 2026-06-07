/* QA-005 — reflection feed hydration for the live dashboard.
 *
 * Subscribes to ``/scans/<id>/reflections.sse`` and prepends a card
 * per ``reflection`` event onto the ``#reflections-list`` list. Cards
 * collapse by default to a header preview; click to expand.
 *
 * The "copy as curl" button rebuilds a ``POST /<agent>/chat`` request
 * for the same prompt against the endpoint baked into the
 * ``[data-refl-endpoint]`` meta tag (QA-003's findings-feed already
 * embeds ``target_ref`` for this).
 *
 * Pagination: list caps at the ``data-refl-page-size`` window (100 by
 * default). New events go on the head; older ones drop off the tail
 * to keep DOM bounded.
 */
(function () {
  'use strict';
  var root = document.getElementById('reflections-feed');
  if (!root) { return; }
  var scanId = root.getAttribute('data-scan-id');
  if (!scanId) { return; }
  var list = document.getElementById('reflections-list');
  if (!list) { return; }
  var pageSize = parseInt(list.getAttribute('data-refl-page-size') || '100', 10);
  if (!(pageSize > 0)) { pageSize = 100; }

  var emptyState = root.querySelector('[data-refl-empty]');
  var search = root.querySelector('[data-refl-search]');
  var verdictBtns = root.querySelectorAll('[data-refl-filter]');
  var chipBtns = root.querySelectorAll('[data-refl-chip]');
  var endpointMeta = root.querySelector('[data-refl-endpoint]');
  var endpointBase = endpointMeta
    ? (endpointMeta.getAttribute('content') || '')
    : '';

  var state = {
    verdictFilter: 'all',
    chipFilter: '',
    query: '',
    rendered: 0
  };

  function escapeHTML(value) {
    if (value === null || value === undefined) { return ''; }
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function verdictClass(verdict) {
    if (verdict === 'pass' || verdict === 'defended') { return 'dash-reflection-card--pass'; }
    if (verdict === 'fail' || verdict === 'exploited') {
      return 'dash-reflection-card--fail';
    }
    if (verdict === 'inconclusive' || verdict === 'needs_followup' ||
        verdict === 'vulnerable' || verdict === 'simulated_or_unverified') {
      return 'dash-reflection-card--inconclusive';
    }
    return 'dash-reflection-card--neutral';
  }

  function buildCurl(prompt, agent) {
    var url = (endpointBase || 'http://localhost:8000').replace(/\/+$/, '');
    if (agent && url.indexOf('/chat') === -1) {
      url = url + '/' + agent + '/chat';
    }
    var body = JSON.stringify({ input: prompt });
    var safeBody = body.replace(/'/g, "'\\''");
    return (
      "curl -sS -X POST " + url +
      " -H 'Content-Type: application/json'" +
      " -d '" + safeBody + "'"
    );
  }

  function copyCurl(card) {
    var btn = card.querySelector('[data-refl-curl]');
    var prompt = card.getAttribute('data-refl-prompt') || '';
    var agent = card.getAttribute('data-refl-agent') || '';
    var oneLiner = buildCurl(prompt, agent);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(oneLiner).then(function () {
        if (btn) {
          var originalLabel = btn.getAttribute('data-label-default') || 'Copy as curl';
          btn.textContent = 'Copied ✓';
          window.setTimeout(function () {
            btn.textContent = originalLabel;
          }, 1500);
        }
      }, function () {
        /* fall back below */
        fallbackCopy(oneLiner);
      });
      return;
    }
    fallbackCopy(oneLiner);
  }

  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'absolute';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  }

  function renderCard(event) {
    var turn = event.turn || {};
    var verdict = String(turn.verdict || '—');
    var agent = String(turn.agent || event.agent || 'agent');
    var asi = String(turn.asi_category || '—');
    var seedId = String(turn.seed_id || '');
    var prompt = String(turn.prompt || '');
    var response = String(turn.target_response || '');
    var reasoning = String(turn.reasoning || '');
    var strategy = String(turn.strategy || '—');
    var confidence = (typeof turn.confidence === 'number')
      ? turn.confidence.toFixed(2) : '';
    var atlas = Array.isArray(turn.mitre_techniques)
      ? turn.mitre_techniques.join(', ') : '';
    var csa = String(turn.csa_category || '');
    var severity = String(turn.severity || '');
    var turnNo = (typeof turn.turn === 'number') ? turn.turn : '';

    var li = document.createElement('li');
    li.className = 'dash-reflection-card ' + verdictClass(verdict);
    li.setAttribute('data-refl-verdict', verdict);
    li.setAttribute('data-refl-agent', agent);
    li.setAttribute('data-refl-asi', asi);
    li.setAttribute('data-refl-seed', seedId);
    li.setAttribute('data-refl-severity', severity);
    li.setAttribute('data-refl-prompt', prompt);

    var previewLen = 160;
    var preview = prompt.length > previewLen
      ? prompt.slice(0, previewLen) + '…'
      : prompt;

    li.innerHTML =
      '<header class="dash-reflection-card__head" data-refl-toggle>' +
        '<span class="dash-reflection-card__pill dash-reflection-card__pill--' +
          escapeHTML(verdict) + '">' + escapeHTML(verdict) + '</span>' +
        '<span class="dash-reflection-card__agent">' + escapeHTML(agent) + '</span>' +
        '<span class="dash-reflection-card__asi">' + escapeHTML(asi) + '</span>' +
        (turnNo !== '' ? '<span class="dash-reflection-card__turn">turn ' +
          escapeHTML(turnNo) + '</span>' : '') +
        (seedId ? '<span class="dash-reflection-card__seed">seed ' +
          escapeHTML(seedId) + '</span>' : '') +
        '<span class="dash-reflection-card__preview">' +
          escapeHTML(preview) + '</span>' +
      '</header>' +
      '<div class="dash-reflection-card__body" hidden>' +
        '<dl class="dash-reflection-card__grid">' +
          '<dt>Strategy</dt><dd>' + escapeHTML(strategy) + '</dd>' +
          (atlas ? '<dt>ATLAS</dt><dd>' + escapeHTML(atlas) + '</dd>' : '') +
          (csa ? '<dt>CSA</dt><dd>' + escapeHTML(csa) + '</dd>' : '') +
          '<dt>Prompt</dt>' +
            '<dd><pre class="dash-reflection-card__pre">' +
              escapeHTML(prompt) + '</pre></dd>' +
          '<dt>Target response</dt>' +
            '<dd><pre class="dash-reflection-card__pre">' +
              escapeHTML(response) + '</pre></dd>' +
          (reasoning ? '<dt>Reason</dt>' +
            '<dd><pre class="dash-reflection-card__pre">' +
              escapeHTML(reasoning) + '</pre></dd>' : '') +
          (confidence ? '<dt>Confidence</dt><dd>' +
            escapeHTML(confidence) + '</dd>' : '') +
        '</dl>' +
        '<div class="dash-reflection-card__actions">' +
          '<button type="button" class="dash-reflection-card__copy"' +
            ' data-refl-curl data-label-default="Copy as curl">Copy as curl</button>' +
        '</div>' +
      '</div>';

    var toggle = li.querySelector('[data-refl-toggle]');
    var body = li.querySelector('.dash-reflection-card__body');
    if (toggle && body) {
      toggle.addEventListener('click', function () {
        var hidden = body.hasAttribute('hidden');
        if (hidden) {
          body.removeAttribute('hidden');
          li.classList.add('dash-reflection-card--expanded');
        } else {
          body.setAttribute('hidden', '');
          li.classList.remove('dash-reflection-card--expanded');
        }
      });
    }
    var copyBtn = li.querySelector('[data-refl-curl]');
    if (copyBtn) {
      copyBtn.addEventListener('click', function (evt) {
        evt.stopPropagation();
        copyCurl(li);
      });
    }
    return li;
  }

  function applyFilters() {
    var query = state.query.toLowerCase();
    var cards = list.querySelectorAll('.dash-reflection-card');
    cards.forEach(function (card) {
      var verdict = card.getAttribute('data-refl-verdict');
      var matchesVerdict = state.verdictFilter === 'all'
        || verdict === state.verdictFilter;
      var text = card.textContent.toLowerCase();
      var matchesQuery = !query || text.indexOf(query) !== -1;
      if (matchesVerdict && matchesQuery) {
        card.removeAttribute('hidden');
      } else {
        card.setAttribute('hidden', '');
      }
    });
  }

  function trim() {
    while (list.children.length > pageSize) {
      list.removeChild(list.lastChild);
    }
  }

  function prependCard(event) {
    var card = renderCard(event);
    if (list.firstChild) {
      list.insertBefore(card, list.firstChild);
    } else {
      list.appendChild(card);
    }
    state.rendered += 1;
    if (emptyState) { emptyState.setAttribute('hidden', ''); }
    trim();
    applyFilters();
  }

  verdictBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var value = btn.getAttribute('data-refl-filter') || 'all';
      state.verdictFilter = value;
      verdictBtns.forEach(function (b) {
        b.classList.toggle(
          'dash-feed-seg__btn--active',
          b === btn
        );
      });
      applyFilters();
    });
  });
  chipBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var value = btn.getAttribute('data-refl-chip') || '';
      state.chipFilter = value;
      chipBtns.forEach(function (b) {
        b.classList.toggle(
          'dash-feed-seg__btn--active',
          b === btn
        );
      });
      applyFilters();
    });
  });
  if (search) {
    search.addEventListener('input', function (evt) {
      var t = evt.target;
      state.query = t && t.value ? t.value : '';
      applyFilters();
    });
  }

  if (typeof EventSource === 'undefined') { return; }
  var reflectionsUrl =
    '/scans/' + encodeURIComponent(scanId) + '/reflections.sse';
  var es = new EventSource(reflectionsUrl);
  // SSE Phase 1, Step 5 — wire the reflections EventSource into the
  // shared freshness dot. Replaces the previously empty ``onerror``
  // below; the four-state machine reads ``es.readyState`` on every
  // requestAnimationFrame tick.
  if (
    typeof window !== 'undefined' &&
    window.AGFreshnessDot &&
    typeof window.AGFreshnessDot.attach === 'function'
  ) {
    window.AGFreshnessDot.attach(es, { url: reflectionsUrl });
  }
  es.addEventListener('reflection', function (evt) {
    try {
      var data = JSON.parse(evt.data);
      prependCard(data);
    } catch (err) { /* swallow malformed event */ }
    // SSE Phase 1, Step 6 — bump the LOGS tab badge by 1 on each
    // reflection arrival. Count-only (no severity dial): the
    // ``reflection`` event has no severity field per
    // ``core/swarm.py:2687-2695`` (critic patch G4/P4). The bus is
    // optional — wired only when ``tab-badge-bus.js`` is on the page.
    if (
      typeof window !== 'undefined' &&
      window.AGTabBadgeBus &&
      typeof window.AGTabBadgeBus.bump === 'function'
    ) {
      window.AGTabBadgeBus.bump('logs', 1, { severity: 'notice' });
    }
  });
  es.addEventListener('scan_done', function () { es.close(); });
  // SSE Phase 1, Step 5 — no per-handler ``onerror``. The shared
  // ``window.AGFreshnessDot`` reads ``es.readyState`` directly and
  // drives LIVE / STALE / RECONNECTING / DEAD.
})();
