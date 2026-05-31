/* Mission Control — chart initialisers + interaction wiring.
 *
 * Single bundle, no module imports. Consumes the global window.Chart from the
 * UMD Chart.js v4 script tag that layout.html loads. Parses the JSON payload
 * island (#mission-chart-data) and mounts:
 *
 *   - mountTimeseries(canvas, findings)     stacked-area findings/sec
 *   - mountAsiBar(canvas, asiRows)          horizontal severity-tinted bars
 *   - mountSparkline(canvas, data, sev)     tiny no-axis line (KPI tiles +
 *                                            agent rows)
 *
 * Plus interaction handlers:
 *
 *   - Findings filter chips (severity multi-state — single-active model)
 *   - Findings row click → slide-over open
 *   - Agent row click → filter table to that ASI code
 *   - Slide-over close (button, backdrop, esc key)
 *
 * Colours are read from CSS custom properties so the prefers-color-scheme
 * light/dark variants pick up automatically on next render.
 *
 * No module exports — everything wires up via DOMContentLoaded.
 */

(function () {
  'use strict';

  /* --------------------------------------------------------------------
   * 1. CSS-var helpers + payload reader
   * -------------------------------------------------------------------- */

  function readVar(name, fallback) {
    var raw = getComputedStyle(document.documentElement).getPropertyValue(name);
    var trimmed = (raw || '').trim();
    return trimmed || fallback || '';
  }

  function readMissionVar(name, fallback) {
    var root = document.querySelector('.mission') || document.documentElement;
    var raw = getComputedStyle(root).getPropertyValue(name);
    var trimmed = (raw || '').trim();
    return trimmed || fallback || '';
  }

  function sevColor(severity) {
    return readMissionVar('--sev-' + severity, '#8B8895');
  }

  function sevBg(severity) {
    return readMissionVar('--sev-' + severity + '-bg', 'rgba(139,136,149,0.12)');
  }

  function readPayload() {
    var node = document.getElementById('mission-chart-data');
    if (!node) { return null; }
    try {
      return JSON.parse(node.textContent || '{}');
    } catch (err) {
      return null;
    }
  }

  /* --------------------------------------------------------------------
   * 2. CHART HELPERS
   * -------------------------------------------------------------------- */

  /**
   * Mount a stacked-area severity time-series chart.
   * Derives bucketed counts client-side from the findings array.
   */
  function mountTimeseries(canvas, findings) {
    if (typeof window.Chart === 'undefined' || !canvas) { return; }

    // Group findings by 5-second-bucket index — derives a synthetic
    // findings-per-bucket curve from the timestamps we already have. For a
    // completed scan we bucket by the HH:MM:SS labels we have; for an empty
    // scan we draw a single zero line so the canvas is still occupied.
    var buckets = bucketByTime(findings);

    var datasets = ['critical', 'high', 'medium', 'low'].map(function (sev) {
      return {
        label: sev,
        data: buckets.series[sev],
        borderColor: sevColor(sev),
        backgroundColor: sevBg(sev),
        borderWidth: 1.5,
        pointRadius: 0,
        pointHoverRadius: 4,
        tension: 0.25,
        fill: true,
        stack: 'findings'
      };
    });

    return new window.Chart(canvas, {
      type: 'line',
      data: { labels: buckets.labels, datasets: datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 320 },
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: readMissionVar('--m-surface-3', '#221C30'),
            borderColor: readMissionVar('--m-line-2', 'rgba(255,255,255,0.14)'),
            borderWidth: 1,
            titleColor: readMissionVar('--m-ink', '#FAFAFA'),
            bodyColor: readMissionVar('--m-ink-2', '#C8C6D0'),
            padding: 10,
            cornerRadius: 6
          }
        },
        scales: {
          x: {
            grid: { color: readMissionVar('--m-line', 'rgba(255,255,255,0.08)'), drawBorder: false },
            ticks: { color: readMissionVar('--m-ink-4', '#5C5A64'), maxRotation: 0, autoSkipPadding: 24 }
          },
          y: {
            stacked: true,
            grid: { color: readMissionVar('--m-line', 'rgba(255,255,255,0.08)'), drawBorder: false },
            ticks: { color: readMissionVar('--m-ink-4', '#5C5A64'), precision: 0 },
            title: { display: true, text: 'findings/bucket', color: readMissionVar('--m-ink-3', '#8B8895') }
          }
        }
      }
    });
  }

  /**
   * Group findings into time buckets by their HH:MM:SS label.
   * Returns { labels: [...], series: { critical: [...], ... } }.
   * For empty findings, returns a 6-step zero curve so the canvas has shape.
   */
  function bucketByTime(findings) {
    var bucketCount = 8;
    var series = { critical: [], high: [], medium: [], low: [] };
    var labels = [];

    if (!findings || findings.length === 0) {
      for (var i = 0; i < bucketCount; i++) {
        labels.push('');
        series.critical.push(0);
        series.high.push(0);
        series.medium.push(0);
        series.low.push(0);
      }
      return { labels: labels, series: series };
    }

    // Build buckets evenly spread over the findings list ordering.
    var perBucket = Math.max(1, Math.ceil(findings.length / bucketCount));
    var idx = 0;
    for (var b = 0; b < bucketCount; b++) {
      var crit = 0, high = 0, med = 0, low = 0;
      var bucketEnd = Math.min(findings.length, idx + perBucket);
      var firstLabel = '';
      for (var j = idx; j < bucketEnd; j++) {
        var f = findings[j];
        if (j === idx) { firstLabel = f.created || ''; }
        if (f.severity === 'critical') { crit++; }
        else if (f.severity === 'high') { high++; }
        else if (f.severity === 'medium') { med++; }
        else if (f.severity === 'low') { low++; }
      }
      labels.push(firstLabel);
      series.critical.push(crit);
      series.high.push(high);
      series.medium.push(med);
      series.low.push(low);
      idx = bucketEnd;
    }
    return { labels: labels, series: series };
  }

  /**
   * Mount the ASI horizontal bar chart (10 axes, severity-tinted by score).
   */
  function mountAsiBar(canvas, asiRows) {
    if (typeof window.Chart === 'undefined' || !canvas || !asiRows) { return; }

    function tintForScore(score) {
      if (score <= 30) { return sevColor('crit'); }
      if (score <= 50) { return sevColor('high'); }
      if (score <= 70) { return sevColor('med'); }
      return sevColor('pass');
    }

    var labels = asiRows.map(function (r) { return r.code + ' ' + r.name; });
    var data = asiRows.map(function (r) { return Number(r.scorePct) || 0; });
    var colors = asiRows.map(function (r) { return tintForScore(Number(r.scorePct) || 0); });

    return new window.Chart(canvas, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: colors,
          borderRadius: 3,
          barThickness: 14
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 320 },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: readMissionVar('--m-surface-3', '#221C30'),
            borderColor: readMissionVar('--m-line-2', 'rgba(255,255,255,0.14)'),
            borderWidth: 1,
            titleColor: readMissionVar('--m-ink', '#FAFAFA'),
            bodyColor: readMissionVar('--m-ink-2', '#C8C6D0'),
            padding: 10,
            cornerRadius: 6
          }
        },
        scales: {
          x: {
            min: 0,
            max: 100,
            grid: { color: readMissionVar('--m-line', 'rgba(255,255,255,0.08)'), drawBorder: false },
            ticks: { color: readMissionVar('--m-ink-4', '#5C5A64'), stepSize: 25 }
          },
          y: {
            grid: { display: false },
            ticks: { color: readMissionVar('--m-ink-2', '#C8C6D0'), autoSkip: false }
          }
        }
      }
    });
  }

  /**
   * Mount a tiny no-axis sparkline (KPI tiles + agent rows).
   */
  function mountSparkline(canvas, data, severity) {
    if (typeof window.Chart === 'undefined' || !canvas) { return; }
    var sev = severity || 'info';
    var color = sevColor(sev);
    var fill = sevBg(sev);

    return new window.Chart(canvas, {
      type: 'line',
      data: {
        labels: data.map(function (_, i) { return i; }),
        datasets: [{
          data: data,
          borderColor: color,
          backgroundColor: fill,
          borderWidth: 1.25,
          pointRadius: 0,
          tension: 0.3,
          fill: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 200 },
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: { x: { display: false }, y: { display: false, beginAtZero: true } }
      }
    });
  }

  /**
   * Compute a synthetic sparkline series for an agent row based on score +
   * finding counts. The visual is a "shape" rather than a real time-series —
   * but it conveys per-agent activity at a glance (Grafana Stat pattern).
   */
  function agentSparkSeries(score, findings) {
    var f = findings || { critical: 0, high: 0, medium: 0, low: 0 };
    var total = (f.critical || 0) + (f.high || 0) + (f.medium || 0) + (f.low || 0);
    var scale = Math.max(1, total + 1);
    var base = Math.max(1, Math.min(10, Math.round((Number(score) || 0) / 10)));
    var out = [];
    for (var i = 0; i < 10; i++) {
      var noise = ((i * 7 + total * 3) % 5) / 4; // deterministic
      var v = Math.max(0, base - 4 + noise * (scale > 1 ? 3 : 1));
      out.push(v);
    }
    return out;
  }

  function kpiSparkSeries(kind, payload) {
    var counts = (payload && payload.counts) || {};
    var f = (payload && payload.findings) || [];
    var seed = 0;
    var n = 12;
    var data = [];
    var i;
    switch (kind) {
      case 'aivss':
        for (i = 0; i < n; i++) { data.push(60 + (i * 3) % 25); }
        return data;
      case 'findings':
        seed = f.length;
        for (i = 0; i < n; i++) { data.push((i / n) * Math.max(1, seed) + (i % 3)); }
        return data;
      case 'critical':
        seed = counts.critical || 0;
        for (i = 0; i < n; i++) { data.push(seed > 0 ? (i / n) * seed : (i % 2)); }
        return data;
      case 'coverage':
        for (i = 0; i < n; i++) { data.push(Math.min(10, (i / n) * 10 + 1)); }
        return data;
      default:
        for (i = 0; i < n; i++) { data.push((i % 5) + 1); }
        return data;
    }
  }

  /* --------------------------------------------------------------------
   * 3. INTERACTION WIRING
   * -------------------------------------------------------------------- */

  /**
   * Filter chips — single-active model. Hides table rows that don't match.
   * 'all' clears the filter.
   */
  function wireFilterChips() {
    var chips = document.querySelectorAll('[data-mission-filter]');
    if (!chips.length) { return; }
    var rows = document.querySelectorAll('.mission__row[data-severity]');

    function apply(filter) {
      chips.forEach(function (c) {
        if (c.getAttribute('data-mission-filter') === filter) {
          c.classList.add('is-active');
        } else {
          c.classList.remove('is-active');
        }
      });
      rows.forEach(function (row) {
        var sev = row.getAttribute('data-severity');
        if (filter === 'all' || sev === filter) {
          row.classList.remove('is-hidden');
        } else {
          row.classList.add('is-hidden');
        }
      });
      // Reflect in URL so a shared link reproduces the filtered view.
      try {
        var url = new URL(window.location.href);
        if (filter === 'all') {
          url.searchParams.delete('sev');
        } else {
          url.searchParams.set('sev', filter);
        }
        window.history.replaceState({}, '', url.toString());
      } catch (_err) { /* private mode */ }
    }

    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        apply(chip.getAttribute('data-mission-filter'));
      });
    });

    // Honour URL ?sev= on load.
    try {
      var url = new URL(window.location.href);
      var sev = url.searchParams.get('sev');
      if (sev && ['critical', 'high', 'medium', 'low'].indexOf(sev) !== -1) {
        apply(sev);
      }
    } catch (_err) { /* private mode */ }
  }

  /**
   * Wire findings table rows + agent panel rows to the slide-over.
   */
  function wireSlideover(payload) {
    var slideover = document.getElementById('mission-slideover');
    var backdrop = document.querySelector('[data-mission-slideover-backdrop]');
    if (!slideover) { return; }
    var body = slideover.querySelector('[data-mission-slideover-body]');
    var title = slideover.querySelector('#mission-slideover-title');
    var closes = document.querySelectorAll('[data-mission-slideover-close]');

    function findingById(id) {
      if (!payload || !payload.findings) { return null; }
      for (var i = 0; i < payload.findings.length; i++) {
        if (payload.findings[i].id === id) { return payload.findings[i]; }
      }
      return null;
    }

    function renderDetail(finding) {
      if (!body || !finding) { return; }
      if (title) { title.textContent = finding.id + ' — ' + (finding.asi || ''); }
      body.innerHTML = '';
      var sections = [
        ['Severity', '<span class="mission-pill mission-pill--' + finding.severity + '">' + (finding.severity || '').toUpperCase() + '</span>'],
        ['ASI category', '<code class="mission-slideover__detail-mono">' + (finding.asi || '') + '</code>'],
        ['Probe', '<code class="mission-slideover__detail-mono">' + (finding.probe || '') + '</code>'],
        ['Captured', '<code class="mission-slideover__detail-mono">' + (finding.created || '') + '</code>'],
        ['Summary', '<p class="mission-slideover__detail-value">' + escapeHtml(finding.summary || '') + '</p>']
      ];
      sections.forEach(function (pair) {
        var div = document.createElement('div');
        div.className = 'mission-slideover__detail-section';
        var label = document.createElement('div');
        label.className = 'mission-slideover__detail-label';
        label.textContent = pair[0];
        var val = document.createElement('div');
        val.innerHTML = pair[1];
        div.appendChild(label);
        div.appendChild(val);
        body.appendChild(div);
      });
    }

    function open(finding) {
      renderDetail(finding);
      slideover.classList.add('is-open');
      slideover.setAttribute('aria-hidden', 'false');
      if (backdrop) { backdrop.classList.add('is-open'); }
    }

    function close() {
      slideover.classList.remove('is-open');
      slideover.setAttribute('aria-hidden', 'true');
      if (backdrop) { backdrop.classList.remove('is-open'); }
    }

    document.querySelectorAll('.mission__row[data-finding-id]').forEach(function (row) {
      row.addEventListener('click', function () {
        var fid = row.getAttribute('data-finding-id');
        var finding = findingById(fid);
        if (finding) { open(finding); }
      });
      row.addEventListener('keydown', function (evt) {
        if (evt.key === 'Enter' || evt.key === ' ') {
          evt.preventDefault();
          var fid = row.getAttribute('data-finding-id');
          var finding = findingById(fid);
          if (finding) { open(finding); }
        }
      });
    });

    closes.forEach(function (btn) {
      btn.addEventListener('click', close);
    });

    if (backdrop) {
      backdrop.addEventListener('click', close);
    }

    document.addEventListener('keydown', function (evt) {
      if (evt.key === 'Escape' && slideover.classList.contains('is-open')) {
        close();
      }
    });
  }

  /**
   * Agent rows filter the findings table to a specific ASI code.
   */
  function wireAgentRows() {
    var rows = document.querySelectorAll('[data-agent-asi]');
    if (!rows.length) { return; }
    var tableRows = document.querySelectorAll('.mission__row[data-asi]');

    function apply(asi) {
      rows.forEach(function (r) { r.classList.remove('is-active'); });
      if (asi) {
        document.querySelectorAll('[data-agent-asi="' + asi + '"]').forEach(function (r) {
          r.classList.add('is-active');
        });
      }
      tableRows.forEach(function (tr) {
        var rowAsi = tr.getAttribute('data-asi');
        if (!asi || rowAsi === asi) {
          tr.classList.remove('is-hidden');
        } else {
          tr.classList.add('is-hidden');
        }
      });
      try {
        var url = new URL(window.location.href);
        if (asi) { url.searchParams.set('asi', asi); } else { url.searchParams.delete('asi'); }
        window.history.replaceState({}, '', url.toString());
      } catch (_err) { /* private mode */ }
    }

    rows.forEach(function (row) {
      row.addEventListener('click', function () {
        var asi = row.getAttribute('data-agent-asi');
        if (row.classList.contains('is-active')) {
          apply(null);
        } else {
          apply(asi);
        }
      });
      row.addEventListener('keydown', function (evt) {
        if (evt.key === 'Enter' || evt.key === ' ') {
          evt.preventDefault();
          row.click();
        }
      });
    });
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /* --------------------------------------------------------------------
   * 4. BOOT
   * -------------------------------------------------------------------- */

  function boot() {
    if (!document.querySelector('.mission')) { return; }
    var payload = readPayload();
    if (!payload) { payload = { findings: [], asiRows: [], counts: {} }; }

    // Main charts
    var ts = document.getElementById('mission-timeseries');
    if (ts) { mountTimeseries(ts, payload.findings); }

    var asi = document.getElementById('mission-asi-bar');
    if (asi) { mountAsiBar(asi, payload.asiRows); }

    // KPI sparklines
    document.querySelectorAll('[data-kpi-spark]').forEach(function (canvas) {
      var kind = canvas.getAttribute('data-kpi-spark');
      var sev = (kind === 'critical') ? 'crit'
              : (kind === 'aivss') ? 'pass'
              : 'low';
      mountSparkline(canvas, kpiSparkSeries(kind, payload), sev);
    });

    // Agent row sparklines
    if (payload.asiRows && payload.asiRows.length) {
      document.querySelectorAll('[data-agent-spark]').forEach(function (canvas) {
        var code = canvas.getAttribute('data-agent-spark');
        var match = null;
        for (var i = 0; i < payload.asiRows.length; i++) {
          if (payload.asiRows[i].code === code) { match = payload.asiRows[i]; break; }
        }
        if (!match) { return; }
        var sev = canvas.getAttribute('data-agent-status') === 'done' ? 'pass'
                : canvas.getAttribute('data-agent-status') === 'queued' ? 'info'
                : 'low';
        mountSparkline(canvas, agentSparkSeries(match.scoreLabel, match.findings), sev);
      });
    }

    // Interactions
    wireFilterChips();
    wireSlideover(payload);
    wireAgentRows();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  // Expose for tests / debugging.
  window.MissionControl = {
    mountTimeseries: mountTimeseries,
    mountAsiBar: mountAsiBar,
    mountSparkline: mountSparkline,
    bucketByTime: bucketByTime,
    readPayload: readPayload
  };
})();
