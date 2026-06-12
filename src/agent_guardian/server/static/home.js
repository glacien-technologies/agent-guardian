/* Home page: per-row scan delete (issue #111).
 *
 * The scan list is server-rendered; this module just wires each "Delete"
 * button to `DELETE /scan/{id}` and removes the row on success. Auth is the
 * dashboard's loopback/token/cookie posture — the same fetch the page already
 * runs under, so no extra credentials are needed for a local dashboard.
 */
function wireDeleteButtons() {
  document.querySelectorAll(".btn-delete").forEach((btn) => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.addEventListener("click", async () => {
      const scanId = btn.dataset.scanId;
      if (!scanId) return;
      const ok = window.confirm(
        `Delete scan ${scanId}?\nThis removes its evidence bundle and cannot be undone.`,
      );
      if (!ok) return;

      btn.disabled = true;
      btn.textContent = "Deleting…";
      try {
        const res = await fetch(`/scan/${encodeURIComponent(scanId)}`, {
          method: "DELETE",
          headers: { Accept: "application/json" },
        });
        if (res.ok) {
          const row = document.querySelector(`tr[data-row-scan-id="${CSS.escape(scanId)}"]`);
          if (row) row.remove();
          return;
        }
        btn.disabled = false;
        btn.textContent = "Delete";
        window.alert(`Could not delete scan (HTTP ${res.status}).`);
      } catch (_err) {
        btn.disabled = false;
        btn.textContent = "Delete";
        window.alert("Could not delete scan (network error).");
      }
    });
  });
}

/* Render UTC timestamps in the viewer's local time (QA: timestamps were GMT only). */
function localizeTimes() {
  document.querySelectorAll("time.localtime").forEach((el) => {
    let iso = el.getAttribute("datetime");
    if (!iso) return;
    // A timestamp with no timezone suffix is stored UTC — mark it so Date() doesn't
    // misread it as local.
    if (!/[zZ]$|[+\-]\d{2}:?\d{2}$/.test(iso)) iso += "Z";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return;
    el.textContent = d.toLocaleString([], {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
    el.title = d.toString();
  });
}

/* Generic copy-to-clipboard for any [data-copy-target] button. */
function wireCopyButtons() {
  document.querySelectorAll(".btn-copy[data-copy-target]").forEach((btn) => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.addEventListener("click", async () => {
      const target = document.getElementById(btn.dataset.copyTarget);
      if (!target) return;
      try {
        await navigator.clipboard.writeText(target.textContent.trim());
        const orig = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = orig;
        }, 1200);
      } catch (_e) {
        /* clipboard unavailable (non-secure context) */
      }
    });
  });
}

/* Soft-refresh just the scan-list body so the controls + scroll survive. */
async function refreshScanList() {
  try {
    const res = await fetch(window.location.href, { headers: { "X-Requested-With": "fetch" } });
    if (!res.ok) return;
    const html = await res.text();
    const doc = new DOMParser().parseFromString(html, "text/html");
    const fresh = doc.querySelector("#scan-list-body");
    const current = document.querySelector("#scan-list-body");
    if (fresh && current) {
      current.replaceWith(fresh);
      wireDeleteButtons();
      localizeTimes();
      // Tester PDF item 28 — re-apply the band filter after the body
      // replacement. The MutationObserver hooked into the OLD body in
      // ``wireBandFilter()`` is orphaned by ``replaceWith``, so without
      // this call the dropdown still reads e.g. "Warning" but the
      // refreshed table renders every row (filter visually "resets").
      const sel = document.getElementById("band-filter");
      if (sel && sel.value) {
        const target = sel.value;
        document.querySelectorAll("tr[data-row-band]").forEach((row) => {
          const band = row.getAttribute("data-row-band") || "";
          row.hidden = band !== target;
        });
      }
    }
  } catch (_e) {
    /* ignore — a failed refresh just keeps the current view */
  }
}

const AUTO_REFRESH_KEY = "ag-home-autorefresh";
let autoRefreshTimer = null;
function setAutoRefresh(on) {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
  if (on) autoRefreshTimer = setInterval(refreshScanList, 10000);
  try {
    localStorage.setItem(AUTO_REFRESH_KEY, on ? "1" : "0");
  } catch (_e) {
    /* storage unavailable */
  }
}
function wireRefreshControls() {
  const btn = document.getElementById("refresh-scans");
  if (btn) btn.addEventListener("click", refreshScanList);
  const chk = document.getElementById("auto-refresh-scans");
  if (chk) {
    let saved = false;
    try {
      saved = localStorage.getItem(AUTO_REFRESH_KEY) === "1";
    } catch (_e) {
      /* storage unavailable */
    }
    chk.checked = saved;
    setAutoRefresh(saved);
    chk.addEventListener("change", () => setAutoRefresh(chk.checked));
  }
}

function wireBandFilter() {
  // Tester report #15 — filter the scan-history table by band. Reads the
  // dropdown's value and hides every <tr data-row-band> whose band does
  // not match (empty value = show all). The filter is applied again after
  // every refresh because the table body is replaced wholesale.
  const sel = document.getElementById("band-filter");
  if (!sel) return;
  function applyFilter() {
    const target = sel.value || "";
    const rows = document.querySelectorAll("tr[data-row-band]");
    rows.forEach((row) => {
      const band = row.getAttribute("data-row-band") || "";
      row.hidden = target !== "" && band !== target;
    });
  }
  sel.addEventListener("change", applyFilter);
  const body = document.getElementById("scan-list-body");
  if (body && typeof MutationObserver !== "undefined") {
    const obs = new MutationObserver(applyFilter);
    obs.observe(body, { childList: true, subtree: true });
  }
}

wireDeleteButtons();
wireCopyButtons();
localizeTimes();
wireRefreshControls();
wireBandFilter();
