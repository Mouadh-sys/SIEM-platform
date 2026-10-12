/* ── SIEM Portal – app.js ─────────────────────────────────
   Talks to portal-backend (FastAPI) via REST.
   API base auto-detects: same host, port 8000.
   Polls every 15 s; also auto-refreshes after any action.
──────────────────────────────────────────────────────────── */

const API = `${location.protocol}//${location.hostname}:8000`;
const OS  = `${location.protocol}//${location.hostname}:9200`;

let allIncidents  = [];
let currentFilter = 'all';
let pollingTimer  = null;

// ── UTC Clock ───────────────────────────────────────────────
function startClock() {
  const el = document.getElementById('nav-time');
  function tick() {
    const now = new Date();
    el.textContent = now.toUTCString().slice(17, 25) + ' UTC';
  }
  tick();
  setInterval(tick, 1000);
}

// ── Toast ───────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// ── Format helpers ──────────────────────────────────────────
function fmtTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toUTCString().slice(5, 22) + ' UTC';
  } catch { return iso; }
}

function sevBadge(n) {
  const labels = { 1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low' };
  const cls = `sev-${Math.min(n, 4)}`;
  return `<span class="sev-badge ${cls}">${labels[n] || `Sev-${n}`}</span>`;
}

function statusBadge(s) {
  const cls = `st-${s}`;
  return `<span class="status-badge ${cls}">${s.charAt(0).toUpperCase() + s.slice(1)}</span>`;
}

function actionButtons(inc) {
  const btns = [];
  if (inc.status === 'open') {
    btns.push(`<button class="btn-action btn-block"   onclick="doAction(${inc.id},'block')">Block</button>`);
    btns.push(`<button class="btn-action btn-resolve" onclick="doAction(${inc.id},'resolve')">Resolve</button>`);
  } else {
    btns.push(`<button class="btn-action btn-reopen" onclick="doAction(${inc.id},'reopen')">Re-open</button>`);
  }
  btns.push(`<button class="btn-action btn-detail" onclick="showDetail(${inc.id})">Detail</button>`);
  return btns.join('');
}

// ── Render incidents table ───────────────────────────────────
function renderTable(incidents) {
  const tbody = document.getElementById('incidents-tbody');
  const list  = currentFilter === 'all'
    ? incidents
    : incidents.filter(i => i.status === currentFilter);

  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-row">No incidents match the current filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = list.map(inc => `
    <tr id="row-${inc.id}">
      <td class="id-cell">#${inc.id}</td>
      <td><div class="ip-cell">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
          <path d="M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/>
        </svg>
        ${escHtml(inc.src_ip)}
      </div></td>
      <td>${sevBadge(inc.severity)}</td>
      <td><span class="count-cell">${inc.count}</span></td>
      <td class="time-cell">${fmtTime(inc.first_seen)}</td>
      <td class="time-cell">${fmtTime(inc.last_seen)}</td>
      <td>${statusBadge(inc.status)}</td>
      <td class="actions-cell">${actionButtons(inc)}</td>
    </tr>
  `).join('');
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Update stat cards ────────────────────────────────────────
function updateStats(incidents, docCount) {
  const open     = incidents.filter(i => i.status === 'open').length;
  const blocked  = incidents.filter(i => i.status === 'blocked').length;
  const resolved = incidents.filter(i => i.status === 'resolved').length;

  animateNum('total-count',    incidents.length);
  animateNum('open-count',     open);
  animateNum('blocked-count',  blocked);
  animateNum('resolved-count', resolved);
  if (docCount !== null) animateNum('docs-count', docCount);
}

function animateNum(id, val) {
  const el = document.getElementById(id);
  const prev = parseInt(el.textContent) || 0;
  if (prev === val) return;
  const step = (val - prev) / 12;
  let cur = prev;
  const iv = setInterval(() => {
    cur += step;
    if ((step > 0 && cur >= val) || (step < 0 && cur <= val)) { cur = val; clearInterval(iv); }
    el.textContent = Math.round(cur).toLocaleString();
  }, 20);
}

// ── Top attackers sidebar ────────────────────────────────────
function renderTopAttackers(incidents) {
  const counts = {};
  for (const inc of incidents) {
    counts[inc.src_ip] = (counts[inc.src_ip] || 0) + inc.count;
  }
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const maxVal = sorted[0]?.[1] || 1;
  const el = document.getElementById('top-attackers');

  if (sorted.length === 0) {
    el.innerHTML = '<div class="attacker-empty">No incidents yet</div>';
    return;
  }
  el.innerHTML = sorted.map(([ip, cnt]) => `
    <div class="attacker-item">
      <span class="attacker-ip">${escHtml(ip)}</span>
      <div class="attacker-meta">
        <span class="attacker-count">${cnt}</span>
        <div class="attacker-bar-wrap">
          <div class="attacker-bar" style="width:${Math.round(cnt/maxVal*100)}%"></div>
        </div>
      </div>
    </div>
  `).join('');
}

// ── Recent webhooks sidebar ──────────────────────────────────
async function renderRecentWebhooks() {
  try {
    const r = await fetch(`${API}/webhook/raw`);
    if (!r.ok) return;
    const data = await r.json();
    const el = document.getElementById('recent-webhooks');
    const list = (data.webhooks || []).slice(0, 8);

    if (list.length === 0) {
      el.innerHTML = '<div class="webhook-empty">No webhooks received yet</div>';
      return;
    }
    el.innerHTML = list.map(w => `
      <div class="webhook-item">
        <div class="webhook-time">${fmtTime(w.received_at)}</div>
        <div class="webhook-preview">${escHtml(w.payload.slice(0, 80))}${w.payload.length > 80 ? '…' : ''}</div>
      </div>
    `).join('');
  } catch { /* silent */ }
}

// ── Fetch OpenSearch doc count ───────────────────────────────
async function fetchDocCount() {
  try {
    const r = await fetch(`${OS}/security-logs/_count`);
    if (!r.ok) return null;
    const d = await r.json();
    return d.count ?? null;
  } catch { return null; }
}

// ── Main data fetch + render ─────────────────────────────────
async function fetchAndRender() {
  const btn = document.getElementById('refresh-btn');
  btn.classList.add('spinning');

  try {
    const r = await fetch(`${API}/incidents`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    allIncidents = data.incidents || [];

    renderTable(allIncidents);
    renderTopAttackers(allIncidents);

    const docCount = await fetchDocCount();
    updateStats(allIncidents, docCount);

    await renderRecentWebhooks();

    // Connection dot – green
    document.getElementById('connection-dot').className   = 'status-dot dot-green';
    document.getElementById('connection-label').textContent = 'Live';
  } catch (err) {
    console.error(err);
    document.getElementById('connection-dot').className   = 'status-dot dot-red';
    document.getElementById('connection-label').textContent = 'Offline';
    toast(`Failed to reach backend: ${err.message}`, 'error');
  } finally {
    btn.classList.remove('spinning');
  }
}

// ── Action handler (block / resolve / reopen) ────────────────
window.doAction = async function(id, action) {
  try {
    const r = await fetch(`${API}/incidents/${id}/${action}`, { method: 'POST' });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      throw new Error(e.detail || `HTTP ${r.status}`);
    }
    const data = await r.json();
    toast(`Incident #${id} marked as ${data.status}`, 'success');
    await fetchAndRender();
  } catch (err) {
    toast(`Error: ${err.message}`, 'error');
  }
};

// ── Detail modal ─────────────────────────────────────────────
window.showDetail = function(id) {
  const inc = allIncidents.find(i => i.id === id);
  if (!inc) return;
  document.getElementById('modal-json').textContent = JSON.stringify(inc, null, 2);
  document.getElementById('detail-modal').classList.remove('hidden');
};

document.getElementById('modal-close').addEventListener('click', () => {
  document.getElementById('detail-modal').classList.add('hidden');
});
document.getElementById('detail-modal').addEventListener('click', function(e) {
  if (e.target === this) this.classList.add('hidden');
});

// ── Filter ───────────────────────────────────────────────────
document.getElementById('status-filter').addEventListener('change', function() {
  currentFilter = this.value;
  renderTable(allIncidents);
});

// ── Refresh button ───────────────────────────────────────────
document.getElementById('refresh-btn').addEventListener('click', fetchAndRender);

// ── Auto-poll every 15 s ─────────────────────────────────────
function startPolling() {
  clearInterval(pollingTimer);
  pollingTimer = setInterval(fetchAndRender, 15000);
}

// ── Boot ─────────────────────────────────────────────────────
startClock();
fetchAndRender();
startPolling();
