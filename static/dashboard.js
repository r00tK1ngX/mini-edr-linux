/**
 * MINI EDR LINUX // CYBERPUNK HUD INTERACTION JAVASCRIPT
 * Handles real-time clock, async modal inspection, and incident actions.
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Live HUD Clock (UTC)
  function updateClock() {
    const clockEl = document.getElementById("hudClock");
    if (!clockEl) return;
    const now = new Date();
    const iso = now.toISOString().replace("T", " ").substring(0, 19);
    clockEl.textContent = `${iso} UTC`;
  }
  setInterval(updateClock, 1000);
  updateClock();

  // 2. Escape key closes modals
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeAllModals();
    }
  });
});

// Toast notification helper
function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `cyber-toast ${type}`;
  toast.innerHTML = `
    <div style="font-weight: 700; text-transform: uppercase; font-size: 0.75rem; margin-bottom: 0.2rem; color: var(--neon-cyan);">
      // SYSTEM_NOTIFICATION
    </div>
    <div>${message}</div>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = "opacity 0.4s, transform 0.4s";
    toast.style.opacity = "0";
    toast.style.transform = "translateX(50px)";
    setTimeout(() => toast.remove(), 400);
  }, 4000);
}

// Modal helper
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add("active");
  }
}

function closeAllModals() {
  document.querySelectorAll(".modal-backdrop").forEach(m => m.classList.remove("active"));
}

// -----------------------------------------------------------------------------
// Alert Actions
// -----------------------------------------------------------------------------

async function acknowledgeAlert(alertId) {
  try {
    const res = await fetch(`/alerts/${alertId}/acknowledge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: "Acknowledged via Web SOC Console" }),
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Alert #${alertId} acknowledged.`, "success");
      // Update badge if row exists
      const badge = document.getElementById(`status-badge-${alertId}`);
      if (badge) {
        badge.className = "badge badge-acknowledged";
        badge.textContent = "ACKNOWLEDGED";
      }
      // Disable ack button
      const ackBtn = document.getElementById(`btn-ack-${alertId}`);
      if (ackBtn) ackBtn.style.display = "none";
    } else {
      showToast(`Failed to acknowledge: ${data.error || "Unknown error"}`, "error");
    }
  } catch (err) {
    showToast(`Network error: ${err.message}`, "error");
  }
}

let activeResolveAlertId = null;

function promptResolveAlert(alertId, title) {
  activeResolveAlertId = alertId;
  const titleEl = document.getElementById("resolveModalAlertTitle");
  if (titleEl) titleEl.textContent = `ALERT #${alertId}: ${title}`;
  const noteInput = document.getElementById("resolveNoteInput");
  if (noteInput) noteInput.value = "";
  openModal("resolveModal");
}

async function submitResolveAlert() {
  if (!activeResolveAlertId) return;
  const noteInput = document.getElementById("resolveNoteInput");
  const note = noteInput ? noteInput.value.trim() : "";

  try {
    const res = await fetch(`/alerts/${activeResolveAlertId}/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ resolution_note: note || "Resolved via Web SOC Console" }),
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Alert #${activeResolveAlertId} marked as RESOLVED.`, "success");
      closeAllModals();
      const badge = document.getElementById(`status-badge-${activeResolveAlertId}`);
      if (badge) {
        badge.className = "badge badge-resolved";
        badge.textContent = "RESOLVED";
      }
      const actions = document.getElementById(`actions-${activeResolveAlertId}`);
      if (actions) {
        actions.innerHTML = `<span style="color: var(--text-muted); font-size: 0.75rem;">RESOLVED</span>`;
      }
    } else {
      showToast(`Failed to resolve: ${data.error || "Unknown error"}`, "error");
    }
  } catch (err) {
    showToast(`Network error: ${err.message}`, "error");
  }
}

async function dismissAlert(alertId) {
  if (!confirm(`Confirm dismissing Alert #${alertId} as False Positive / Ignored?`)) {
    return;
  }

  try {
    const res = await fetch(`/alerts/${alertId}/dismiss`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ resolution_note: "Dismissed by operator (false positive / ignored)" }),
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Alert #${alertId} dismissed.`, "info");
      const badge = document.getElementById(`status-badge-${alertId}`);
      if (badge) {
        badge.className = "badge badge-resolved";
        badge.textContent = "RESOLVED";
      }
      const actions = document.getElementById(`actions-${alertId}`);
      if (actions) {
        actions.innerHTML = `<span style="color: var(--text-muted); font-size: 0.75rem;">DISMISSED</span>`;
      }
    } else {
      showToast(`Failed to dismiss: ${data.error || "Unknown error"}`, "error");
    }
  } catch (err) {
    showToast(`Network error: ${err.message}`, "error");
  }
}

// -----------------------------------------------------------------------------
// Evidence Inspection Modal
// -----------------------------------------------------------------------------

async function viewEvidence(alertId) {
  openModal("evidenceModal");
  const body = document.getElementById("evidenceModalBody");
  if (!body) return;
  body.innerHTML = `<div style="text-align: center; color: var(--neon-cyan); padding: 2rem;">[DECRYPTING TELEMETRY EVIDENCE...]</div>`;

  try {
    const res = await fetch(`/alerts/${alertId}/detail`);
    const data = await res.json();
    if (!data.success) {
      body.innerHTML = `<div style="color: var(--neon-red);">Failed to load evidence: ${data.error}</div>`;
      return;
    }

    const alert = data.alert;
    const events = data.events || [];

    let eventsHtml = "";
    if (events.length > 0) {
      eventsHtml = events.map(ev => `
        <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(0,240,255,0.15); border-radius: 4px; padding: 0.85rem; margin-bottom: 0.75rem;">
          <div style="display: flex; justify-content: space-between; margin-bottom: 0.4rem;">
            <span style="font-weight: 700; color: var(--neon-cyan); font-size: 0.8rem;">EVENT #${ev.id}: ${ev.event_type}</span>
            <span class="badge badge-${ev.severity}">${ev.severity.toUpperCase()}</span>
          </div>
          <div style="font-size: 0.8rem; color: #fff; margin-bottom: 0.5rem;">${ev.title || "Untitled"}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.5rem;">Occurred: ${ev.occurred_at}</div>
          <pre class="json-viewer">${formatJsonString(ev.evidence_json)}</pre>
        </div>
      `).join("");
    } else {
      eventsHtml = `<div style="color: var(--text-muted); font-style: italic;">No specific security events linked to this alert.</div>`;
    }

    body.innerHTML = `
      <div style="margin-bottom: 1.25rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <h3 style="color: #fff; font-size: 1.1rem;">${alert.title}</h3>
          <span class="badge badge-${alert.severity}">${alert.severity.toUpperCase()}</span>
        </div>
        <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 0.75rem;">${alert.description || "No description provided."}</p>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; font-size: 0.75rem; background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 4px; border: 1px solid var(--border-dim);">
          <div><span style="color: var(--text-muted);">RULE ID:</span> <span class="cyber-code">${alert.rule_id}</span></div>
          <div><span style="color: var(--text-muted);">AGENT:</span> <span class="cyber-code">${alert.agent_id}</span></div>
          <div><span style="color: var(--text-muted);">FIRST SEEN:</span> <span>${alert.first_seen_at}</span></div>
          <div><span style="color: var(--text-muted);">LAST SEEN:</span> <span>${alert.last_seen_at}</span></div>
          ${alert.resolution_note ? `<div style="grid-column: 1 / -1;"><span style="color: var(--text-muted);">NOTE:</span> <span style="color: var(--neon-green);">${alert.resolution_note}</span></div>` : ""}
        </div>
      </div>
      <h4 style="color: var(--neon-cyan); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.75rem;">// LINKED SECURITY EVENTS (${events.length})</h4>
      <div>${eventsHtml}</div>
    `;
  } catch (err) {
    body.innerHTML = `<div style="color: var(--neon-red);">Error fetching telemetry: ${err.message}</div>`;
  }
}

// -----------------------------------------------------------------------------
// Endpoint Telemetry Inspection Modal
// -----------------------------------------------------------------------------

async function inspectEndpoint(agentId) {
  openModal("endpointModal");
  const body = document.getElementById("endpointModalBody");
  if (!body) return;
  body.innerHTML = `<div style="text-align: center; color: var(--neon-cyan); padding: 2rem;">[SCANNING ENDPOINT TELEMETRY DECK...]</div>`;

  try {
    const res = await fetch(`/endpoints/${agentId}/telemetry`);
    const data = await res.json();
    if (!data.success) {
      body.innerHTML = `<div style="color: var(--neon-red);">Error: ${data.error}</div>`;
      return;
    }

    const ep = data.endpoint;
    const snap = data.snapshot;
    const procs = data.processes || [];
    const baselinesCount = data.baselines_count || 0;

    // Top processes sorted by CPU desc
    const sortedProcs = [...procs].sort((a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0)).slice(0, 15);

    let procsHtml = "";
    if (sortedProcs.length > 0) {
      procsHtml = sortedProcs.map(p => `
        <tr>
          <td><span class="cyber-code">${p.pid}</span></td>
          <td style="font-weight: 600; color: #fff;">${escapeHtml(p.process_name)}</td>
          <td><span style="color: var(--text-muted); font-size: 0.75rem;">${escapeHtml(p.username || "N/A")}</span></td>
          <td style="color: ${p.cpu_percent > 70 ? 'var(--neon-red)' : 'var(--neon-cyan)'}; font-weight: 700;">${p.cpu_percent !== null ? p.cpu_percent.toFixed(1) + '%' : '0.0%'}</td>
          <td>${p.memory_percent !== null ? p.memory_percent.toFixed(1) + '%' : '0.0%'}</td>
          <td><span class="cyber-code" style="font-size: 0.7rem;">${escapeHtml(p.exe_path || 'unknown')}</span></td>
        </tr>
      `).join("");
    } else {
      procsHtml = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No process snapshot received yet.</td></tr>`;
    }

    body.innerHTML = `
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 4px; border: 1px solid var(--border-dim);">
        <div><span style="color: var(--text-muted); font-size: 0.75rem;">HOSTNAME</span><div style="font-weight: 700; color: #fff;">${escapeHtml(ep.hostname)}</div></div>
        <div><span style="color: var(--text-muted); font-size: 0.75rem;">AGENT ID</span><div class="cyber-code">${escapeHtml(ep.agent_id)}</div></div>
        <div><span style="color: var(--text-muted); font-size: 0.75rem;">IP ADDRESS</span><div>${escapeHtml(ep.ip_address)}</div></div>
        <div><span style="color: var(--text-muted); font-size: 0.75rem;">STATUS</span><div><span class="badge badge-${ep.status}">${ep.status.toUpperCase()}</span></div></div>
        <div><span style="color: var(--text-muted); font-size: 0.75rem;">CPU USAGE</span><div style="color: var(--neon-cyan); font-weight: 700;">${ep.cpu_percent ? ep.cpu_percent.toFixed(1) + '%' : 'N/A'}</div></div>
        <div><span style="color: var(--text-muted); font-size: 0.75rem;">RAM USAGE</span><div style="color: var(--neon-green); font-weight: 700;">${ep.memory_percent ? ep.memory_percent.toFixed(1) + '%' : 'N/A'}</div></div>
        <div><span style="color: var(--text-muted); font-size: 0.75rem;">MONITORED FILES (FIM)</span><div style="color: var(--neon-purple); font-weight: 700;">${baselinesCount} files</div></div>
        <div><span style="color: var(--text-muted); font-size: 0.75rem;">LAST HEARTBEAT</span><div style="font-size: 0.75rem;">${ep.last_seen || 'N/A'}</div></div>
      </div>

      <h4 style="color: var(--neon-cyan); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.75rem;">
        // ACTIVE PROCESS MATRIX (${snap ? snap.process_count : procs.length} total processes)
      </h4>
      <div class="table-responsive" style="max-height: 320px; overflow-y: auto;">
        <table class="cyber-table">
          <thead>
            <tr>
              <th>PID</th>
              <th>PROCESS</th>
              <th>USER</th>
              <th>CPU%</th>
              <th>RAM%</th>
              <th>EXECUTABLE PATH</th>
            </tr>
          </thead>
          <tbody>${procsHtml}</tbody>
        </table>
      </div>
    `;
  } catch (err) {
    body.innerHTML = `<div style="color: var(--neon-red);">Error scanning endpoint: ${err.message}</div>`;
  }
}

// Format JSON string helper
function formatJsonString(val) {
  if (!val) return "{}";
  if (typeof val === "object") return JSON.stringify(val, null, 2);
  try {
    const parsed = JSON.parse(val);
    return JSON.stringify(parsed, null, 2);
  } catch (e) {
    return val;
  }
}

// Escape HTML helper
function escapeHtml(text) {
  if (!text) return "";
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}
