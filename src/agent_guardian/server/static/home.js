/* Home page: per-row scan delete (issue #111).
 *
 * The scan list is server-rendered; this module just wires each "Delete"
 * button to `DELETE /scan/{id}` and removes the row on success. Auth is the
 * dashboard's loopback/token/cookie posture — the same fetch the page already
 * runs under, so no extra credentials are needed for a local dashboard.
 */
function wireDeleteButtons() {
  document.querySelectorAll(".btn-delete").forEach((btn) => {
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

wireDeleteButtons();
