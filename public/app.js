'use strict';

/* Sentinel SOC dashboard — vanilla JS, no build step.
 *
 * Runs in two modes:
 *  - LIVE: talks to the Sentinel SOC API (same host, or a custom host set
 *    via the API URL field or ?api=https://host deep link).
 *  - DEMO: when no backend is reachable (e.g. GitHub Pages), serves a
 *    generated snapshot (demo-data.json) so every visitor gets a fully
 *    browsable site. Write operations explain they need a live backend.
 */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const DEMO_CREDENTIALS = { admin: 'sentinel-admin-token', ingest: 'ingest-demo-token' };
const SESSION_KEY = 'sentinel_session';

// ---------------------------------------------------------------------------
// Session (login / logout)
// ---------------------------------------------------------------------------
let session = (() => {
  try {
    const s = JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null');
    if (s && typeof s === 'object') return { adminToken: s.adminToken || '', ingestToken: s.ingestToken || '', role: s.role || null, name: s.name || null };
  } catch { /* corrupt storage — start fresh */ }
  // Migrate a legacy localStorage admin token once, then move to session scope.
  const legacy = localStorage.getItem('sentinel_admin_token');
  if (legacy) return { adminToken: legacy, ingestToken: '', role: null, name: null };
  return { adminToken: '', ingestToken: '', role: null, name: null };
})();

function saveSession() {
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)); } catch { /* private mode */ }
}

function authHeaders() {
  return session.adminToken ? { Authorization: `Bearer ${session.adminToken}` } : {};
}

function isSignedIn() {
  return !!(session.adminToken || session.ingestToken);
}

// ---------------------------------------------------------------------------
// Custom API host ("API URL" field + ?api= deep link)
// ---------------------------------------------------------------------------
let apiBase = localStorage.getItem('sentinel_api_base') || '';
const urlApi = new URLSearchParams(location.search).get('api');
if (urlApi) {
  apiBase = normalizeBase(urlApi);
  localStorage.setItem('sentinel_api_base', apiBase);
}
$('#apiBaseInput').value = apiBase;

function normalizeBase(u) {
  const s = String(u || '').trim().replace(/\/+$/, '');
  if (!s) return '';
  return /^https?:\/\//i.test(s) ? s : `https://${s}`;
}

$('#apiBaseInput').addEventListener('change', (e) => {
  apiBase = normalizeBase(e.target.value);
  localStorage.setItem('sentinel_api_base', apiBase);
  backendReachable = null; // re-probe with the new base
  toast(apiBase ? `API base set: ${apiBase}` : 'API base cleared — using this host');
  initConnectivity();
});

function absUrl(p) {
  return apiBase ? `${apiBase}${p}` : p;
}

// ---------------------------------------------------------------------------
// Connectivity + demo fallback
// ---------------------------------------------------------------------------
let backendReachable = null; // null unknown · true live API · false demo
let publicMode = false;

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function toast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast';
  if (isError) el.style.borderColor = 'var(--red)';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

let DEMO = null; // undefined = not loaded yet, false = unavailable, object = snapshot
async function loadDemo() {
  if (DEMO !== null) return DEMO;
  try {
    const res = await fetch('demo-data.json', { cache: 'no-store' });
    DEMO = res.ok ? await res.json() : false;
  } catch {
    DEMO = false;
  }
  return DEMO;
}

/** Serve snapshot data when no live backend is connected. */
async function demoApi(path, opts = {}) {
  const d = await loadDemo();
  const json = (status, body) => ({ ok: status < 400, status, body });
  if (!d) return json(503, { error: 'demo snapshot unavailable and no backend connected' });

  const method = (opts.method || 'GET').toUpperCase();
  const route = path.split('?')[0];
  const hdr = (opts.headers && (opts.headers.Authorization || opts.headers.authorization)) || '';
  const tok = String(hdr).replace(/^Bearer\s+/i, '').trim();

  if (route === '/api/auth/whoami') {
    const isAdmin = !!tok && tok === DEMO_CREDENTIALS.admin;
    const isIngest = !isAdmin && !!tok && tok === DEMO_CREDENTIALS.ingest;
    return json(200, {
      role: isAdmin ? 'admin' : isIngest ? 'ingest' : 'public',
      name: isAdmin ? 'admin (demo)' : isIngest ? 'ingest (demo)' : 'visitor',
      public_mode: true,
      demo: true,
      capabilities: {
        view_incidents: true, view_reports: true, view_locations: true, run_evaluation: true,
        ingest: isAdmin || isIngest, manage_keys: isAdmin,
      },
    });
  }

  if (method !== 'GET' && route !== '/api/evaluation/run') {
    return json(403, {
      error: 'demo mode — write operations need a live backend',
      demo: true,
      hint: 'Deploy the API (Render blueprint included in the repo) and set the API URL in the header, or add ?api=https://your-host to this page URL.',
    });
  }

  switch (route) {
    case '/api':
      return json(200, {
        name: d.app.name, version: d.app.version, demo_mode: true,
        description: 'Static demo snapshot (no backend connected). Point the API URL field at a live Sentinel SOC host for real-time ingestion and key management.',
        endpoints: {},
      });
    case '/api/health':
      return json(200, { status: 'ok', uptime_sec: 0, events: d.stats.total_events, demo: true });
    case '/api/stats': return json(200, d.stats);
    case '/api/incidents': return json(200, { incidents: d.incidents });
    case '/api/reports': return json(200, { chain: d.integrity, adversarial: d.adversarial, reports: d.reports });
    case '/api/integrity/verify': return json(200, d.integrity);
    case '/api/adversarial/sweep': return json(200, d.adversarial);
    case '/api/locations': return json(200, d.locations);
    case '/api/evaluation/run': return json(200, d.eval);
    case '/api/keys': return json(200, { keys: [], demo: true, note: 'Key management needs a live backend.' });
    default: {
      let m = route.match(/^\/api\/incidents\/([^/]+)\/report$/);
      if (m) {
        const rep = d.reports.find((r) => r.incident_id === m[1]);
        return rep ? json(200, { report: rep, adversarial: d.adversarial, chain: d.integrity }) : json(404, { error: 'incident not found' });
      }
      m = route.match(/^\/api\/evidence\/([^/]+)$/);
      if (m) {
        const ev = d.events.find((e) => e.event_id === m[1]);
        return ev ? json(200, { ...ev, chain_integrity: d.integrity.ok }) : json(404, { error: 'evidence not found' });
      }
      return json(404, { error: 'not found', demo: true });
    }
  }
}

async function api(path, opts = {}) {
  const withAuth = { ...opts, headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(opts.headers || {}) } };
  if (backendReachable === false && !apiBase) return demoApi(path, withAuth);
  try {
    const res = await fetch(absUrl(path), withAuth);
    const body = await res.json().catch(() => ({}));
    if (!res.ok && !apiBase && backendReachable !== true && (res.status === 404 || res.status >= 500)) {
      // Likely a static host serving 404 pages for /api/* — switch to demo.
      backendReachable = false;
      updateModeBanner();
      return demoApi(path, withAuth);
    }
    return { ok: res.ok, status: res.status, body };
  } catch {
    if (!apiBase) {
      backendReachable = false;
      updateModeBanner();
      return demoApi(path, withAuth);
    }
    return { ok: false, status: 0, body: { error: `API host unreachable: ${apiBase}` } };
  }
}

async function detectPublicMode() {
  let probe = null;
  try {
    const res = await fetch(absUrl('/api/auth/whoami'), { headers: { 'Content-Type': 'application/json' } });
    if (res.ok) probe = await res.json().catch(() => null);
  } catch { probe = null; }
  if (!probe) {
    // Legacy backend without the whoami endpoint.
    try {
      const res = await fetch(absUrl('/api/stats'));
      probe = res.ok ? { public_mode: true } : null;
    } catch { probe = null; }
  }
  backendReachable = !!probe;
  publicMode = !!(probe && probe.public_mode);
  updateModeBanner();
  return backendReachable;
}

function updateModeBanner() {
  const banner = $('#modeBanner');
  const demoChip = $('#demoChip');
  if (!banner) return;
  if (backendReachable === false) {
    demoChip.style.display = '';
    banner.innerHTML = apiBase
      ? `<div style="background:rgba(231,76,60,0.08);border:1px solid var(--red);color:var(--text);padding:10px 16px;font-size:13px;">
           ⚠ API host <code>${esc(apiBase)}</code> is unreachable — check the API URL field. Showing the built-in demo snapshot meanwhile.</div>`
      : `<div style="background:rgba(241,196,15,0.08);border-bottom:1px solid var(--amber);color:var(--text);padding:10px 16px;font-size:13px;">
           📦 <b>Demo snapshot</b> — no backend connected, so you're browsing generated demo data. Connect a live API via the <b>API URL</b> field
           (or add <code>?api=https://your-host</code> to this URL). Free hosting: GitHub Pages for this dashboard + the included Render blueprint for the API.</div>`;
  } else {
    demoChip.style.display = 'none';
    banner.innerHTML = '';
  }
}

// ---------------------------------------------------------------------------
// Session UI (sign in / sign out)
// ---------------------------------------------------------------------------
function updateSessionUI() {
  const dot = $('#sessionDot');
  const text = $('#sessionText');
  const signedIn = isSignedIn();
  $('#btnLogin').style.display = signedIn ? 'none' : '';
  $('#btnLogout').style.display = signedIn ? '' : 'none';
  if (session.role === 'admin') {
    dot.style.background = 'var(--green)';
    dot.style.boxShadow = '0 0 6px var(--green)';
    text.textContent = `Signed in: ${session.name || 'admin'}`;
  } else if (session.role === 'ingest') {
    dot.style.background = 'var(--accent)';
    dot.style.boxShadow = '0 0 6px var(--accent)';
    text.textContent = `Signed in: ${session.name || 'ingest'}`;
  } else {
    dot.style.background = 'var(--muted)';
    dot.style.boxShadow = 'none';
    text.textContent = publicMode ? 'Visitor · read-only' : 'Visitor';
  }
  const ing = $('#ingToken');
  if (ing && document.activeElement !== ing) ing.value = session.ingestToken || DEMO_CREDENTIALS.ingest;
}

function openLogin() {
  $('#loginAdmin').value = session.adminToken || '';
  $('#loginIngest').value = session.ingestToken || '';
  $('#loginError').textContent = '';
  $('#loginModal').style.display = 'flex';
  $('#loginAdmin').focus();
}

function closeLogin() {
  $('#loginModal').style.display = 'none';
}

$('#btnLogin').addEventListener('click', openLogin);
$('#loginClose').addEventListener('click', closeLogin);
$('#loginCancel').addEventListener('click', closeLogin);
$('#btnLogout').addEventListener('click', () => {
  session = { adminToken: '', ingestToken: '', role: null, name: null };
  saveSession();
  localStorage.removeItem('sentinel_admin_token');
  updateSessionUI();
  toast('Signed out — browsing as visitor');
  refreshAll();
});

$('#loginModal').addEventListener('click', (e) => {
  if (e.target === $('#loginModal')) closeLogin();
});
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  closeLogin();
  document.querySelectorAll('#modalRoot .modal').forEach((m) => m.remove());
});
// Any element with data-open-login opens the dialog (used in auth prompts).
document.addEventListener('click', (e) => {
  if (e.target.closest('[data-open-login]')) openLogin();
});

$('#loginSubmit').addEventListener('click', async () => {
  const admin = $('#loginAdmin').value.trim();
  const ingest = $('#loginIngest').value.trim();
  const err = $('#loginError');
  err.textContent = '';
  if (!admin && !ingest) {
    err.textContent = 'Enter at least one token to sign in.';
    return;
  }
  const btn = $('#loginSubmit');
  btn.disabled = true;
  try {
    let role = null;
    let name = null;
    if (admin) {
      const r = await api('/api/auth/whoami', { headers: { Authorization: `Bearer ${admin}` } });
      if (r.ok && r.body.role === 'admin') {
        role = 'admin';
        name = r.body.name || 'admin';
      } else {
        err.textContent = r.status === 0 ? r.body.error : 'Admin token rejected by the backend.';
        return;
      }
    }
    if (ingest) {
      const r = await api('/api/auth/whoami', { headers: { Authorization: `Bearer ${ingest}` } });
      if (r.ok && (r.body.role === 'ingest' || r.body.role === 'admin')) {
        if (!role) {
          role = 'ingest';
          name = r.body.name || 'ingest';
        }
      } else {
        err.textContent = r.status === 0 ? r.body.error : 'Ingest key rejected by the backend.';
        return;
      }
    }
    session = { adminToken: admin, ingestToken: ingest, role, name };
    saveSession();
    localStorage.removeItem('sentinel_admin_token');
    closeLogin();
    updateSessionUI();
    toast(`Signed in as ${role}${name ? ` — ${name}` : ''}`);
    refreshAll();
  } finally {
    btn.disabled = false;
  }
});

/** Re-validate a restored session against the backend (downgrades stale tokens). */
async function validateSession() {
  if (!isSignedIn()) {
    updateSessionUI();
    return;
  }
  let role = null;
  let name = null;
  if (session.adminToken) {
    const r = await api('/api/auth/whoami', { headers: { Authorization: `Bearer ${session.adminToken}` } });
    if (r.ok && r.body.role === 'admin') {
      role = 'admin';
      name = r.body.name || 'admin';
    } else {
      session.adminToken = '';
    }
  }
  if (session.ingestToken) {
    const r = await api('/api/auth/whoami', { headers: { Authorization: `Bearer ${session.ingestToken}` } });
    if (r.ok && (r.body.role === 'ingest' || r.body.role === 'admin')) {
      if (!role) {
        role = 'ingest';
        name = r.body.name || 'ingest';
      }
    } else {
      session.ingestToken = '';
    }
  }
  session.role = role;
  session.name = name;
  saveSession();
  updateSessionUI();
}

function authPrompt(msg) {
  return `<div class="empty">${esc(msg)}<div style="margin-top:10px;"><button class="btn primary" data-open-login>Sign in</button></div></div>`;
}

// ---------------------------------------------------------------------------
// Ingest simulator
// ---------------------------------------------------------------------------
const ACTIONS_BY_DOMAIN = {
  endpoint: ['process_start', 'file_write', 'file_delete', 'registry_write'],
  identity: ['login_success', 'login_failure', 'logout', 'assume_role'],
  cloud: ['create', 'update', 'delete', 'policy_change'],
  network: ['connection', 'dns_query', 'data_transfer', 'tls_handshake'],
};

const FIELD_DEFS = {
  endpoint: [
    { key: 'hostname', label: 'Hostname', ph: 'FINWS-4411' },
    { key: 'user', label: 'User', ph: 'j.doe' },
    { key: 'process_name', label: 'Process', ph: 'powershell.exe' },
    { key: 'process_hash', label: 'Process hash', ph: '9f86d081...' },
  ],
  identity: [
    { key: 'user', label: 'User', ph: 'j.doe' },
    { key: 'src_ip', label: 'Source IP', ph: '185.220.101.7' },
    { key: 'geo', label: 'Geo (country)', ph: 'RU' },
    { key: 'user_agent', label: 'User agent', ph: 'curl/8.4' },
  ],
  cloud: [
    { key: 'provider', label: 'Provider', ph: 'aws' },
    { key: 'resource', label: 'Resource ARN', ph: 'arn:aws:s3:::app-prod' },
    { key: 'principal', label: 'Principal', ph: 'j.doe' },
    { key: 'src_ip', label: 'Caller IP', ph: '185.220.101.7' },
  ],
  network: [
    { key: 'src_ip', label: 'Source IP', ph: '10.4.1.44' },
    { key: 'dst_ip', label: 'Dest IP', ph: '45.33.32.156' },
    { key: 'dst_port', label: 'Dest port', ph: '443', num: true },
    { key: 'dns_domain', label: 'DNS domain', ph: 'cdn-update-top.tk' },
  ],
};

function populateActions() {
  const dom = $('#ingDomain').value;
  const sel = $('#ingAction');
  sel.innerHTML = ACTIONS_BY_DOMAIN[dom].map((a) => `<option>${a}</option>`).join('');
  $('#ingFields').innerHTML = FIELD_DEFS[dom]
    .map((f) => `<div class="form-group"><label>${esc(f.label)}</label><input data-fkey="${esc(f.key)}" data-num="${f.num ? '1' : ''}" placeholder="${esc(f.ph)}" style="width:100%;" /></div>`)
    .join('');
}
$('#ingDomain').addEventListener('change', populateActions);

$('#btnIngest').addEventListener('click', async () => {
  const payload = { domain: $('#ingDomain').value, action: $('#ingAction').value, timestamp: new Date().toISOString(), source_tool: 'dashboard-simulator' };
  document.querySelectorAll('#ingFields input').forEach((inp) => {
    if (!inp.value) return;
    payload[inp.dataset.fkey] = inp.dataset.num ? Number(inp.value) : inp.value.trim();
  });
  const token = $('#ingToken').value.trim();
  const res = await api('/api/ingest/event', {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: JSON.stringify(payload),
  });
  $('#ingResult').textContent = JSON.stringify(res.body, null, 2);
  if (res.ok) {
    toast(res.body.replay ? 'Event accepted (replay detected as duplicate)' : 'Event accepted into evidence registry');
    refreshLive();
  } else if (res.status === 401) {
    toast('Ingest rejected: unauthorized — sign in with a valid ingest key', true);
    openLogin();
  } else if (res.status === 403 && res.body.demo) {
    toast('Demo mode: run a live backend to ingest real events', true);
  } else {
    toast(`Ingest rejected: ${res.body.reason || res.body.error}`, true);
  }
});

// ---------------------------------------------------------------------------
// View switching
// ---------------------------------------------------------------------------
$$('nav button').forEach((btn) => {
  btn.addEventListener('click', () => {
    $$('nav button').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    ['live', 'incidents', 'threats', 'locations', 'eval', 'api'].forEach((v) => {
      $(`#view-${v}`).style.display = btn.dataset.view === v ? '' : 'none';
    });
    if (btn.dataset.view === 'incidents') loadIncidents();
    if (btn.dataset.view === 'threats') loadThreats();
    if (btn.dataset.view === 'locations') loadLocations();
    if (btn.dataset.view === 'eval') { /* results render on demand */ }
    if (btn.dataset.view === 'api') loadApiRef();
    if (btn.dataset.view === 'live') refreshLive();
  });
});

function refreshAll() {
  refreshLive();
  loadIncidents();
  loadKeys();
  if ($('nav button[data-view="locations"]').classList.contains('active')) loadLocations();
  if ($('nav button[data-view="threats"]').classList.contains('active')) loadThreats();
}

// ---------------------------------------------------------------------------
// Live view
// ---------------------------------------------------------------------------
async function refreshLive() {
  const stats = await api('/api/stats');
  if (stats.ok) $('#kpiEvents').textContent = stats.body.total_events ?? '—';
  const integrity = await api('/api/integrity/verify');
  if (integrity.ok) {
    const ok = integrity.body.ok;
    $('#chainText').textContent = ok ? 'CHAIN OK' : 'CHAIN BROKEN';
    $('#chainChip .dot').className = `dot ${ok ? 'ok' : 'bad'}`;
    $('#integrityBox').textContent = JSON.stringify(integrity.body, null, 2);
  } else {
    $('#chainText').textContent = 'CHAIN ?';
    $('#integrityBox').textContent = `Integrity endpoint unavailable — ${integrity.status}`;
  }
  const adv = await api('/api/adversarial/sweep');
  $('#kpiAdv').textContent = adv.ok ? adv.body.finding_count : '—';
  const inc = await api('/api/incidents');
  if (inc.ok) {
    const high = inc.body.incidents.filter((i) => i.risk_score >= 50).length;
    $('#kpiHigh').textContent = high;
  }
}

$('#btnVerify').addEventListener('click', refreshLive);
$('#btnRefreshIncidents').addEventListener('click', loadIncidents);

// ---------------------------------------------------------------------------
// Evidence inspector (report citations resolve to these raw records)
// ---------------------------------------------------------------------------
async function showEvidence(eventId) {
  const res = await api(`/api/evidence/${encodeURIComponent(eventId)}`);
  const root = $('#modalRoot');
  if (!res.ok) {
    toast(res.body.error || 'Evidence unavailable', true);
    return;
  }
  const rec = res.body;
  root.innerHTML = `
    <div class="modal">
      <div class="modal-content" style="width:min(760px,94vw);">
        <button class="close-x" data-close-modal aria-label="Close">×</button>
        <h3>Evidence ${esc(rec.event_id)}</h3>
        <div class="modal-meta">
          <span class="risk-pill ${rec.chain_integrity ? 'risk-low' : 'risk-high'}">${rec.chain_integrity ? 'chain verified' : 'CHAIN BROKEN'}</span>
          <span>domain: ${esc(rec.event?.domain)}</span>
          <span>action: ${esc(rec.event?.action)}</span>
          <span>received: ${esc(rec.received_at)}</span>
        </div>
        <pre class="code">${esc(JSON.stringify(rec, null, 2))}</pre>
        <div style="margin-top:10px;font-size:11px;color:var(--muted);">
          hash = SHA-256(prev_hash + content_hash) — this record is one link in the tamper-evident chain.
        </div>
      </div>
    </div>`;
}
document.addEventListener('click', (e) => {
  if (e.target.closest('[data-close-modal]')) e.target.closest('.modal').remove();
  const ev = e.target.closest('[data-ev]');
  if (ev) showEvidence(ev.dataset.ev);
  const rep = e.target.closest('[data-open-report]');
  if (rep) openReport(rep.dataset.openReport);
});

// ---------------------------------------------------------------------------
// Incidents view
// ---------------------------------------------------------------------------
async function loadIncidents() {
  const res = await api('/api/reports');
  const box = $('#incidentList');
  if (!res.ok) {
    box.innerHTML = authPrompt('Admin token required to view reports — sign in to continue.');
    return;
  }
  const { reports } = res.body;
  if (!reports.length) {
    box.innerHTML = `<div class="empty">No incidents correlated yet. Ingest events first.</div>`;
    return;
  }
  box.innerHTML = reports.map((r) => `
    <div class="panel" style="margin-bottom:14px;">
      <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px;">
        <div>
          <div style="font-weight:600;font-size:14px;">${esc(r.title)}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:3px;font-family:var(--mono);">
            ${esc(r.incident_id)} · ${r.event_count} events · confidence ${(r.confidence * 100).toFixed(0)}% · coverage ${(r.coverage.coverage_ratio * 100).toFixed(0)}%
          </div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;">
          ${r.adversarial_findings.length ? `<span class="risk-pill risk-high">⚠ ${r.adversarial_findings.length} adversarial</span>` : ''}
          <span class="risk-pill ${r.risk_score >= 50 ? 'risk-high' : r.risk_score >= 25 ? 'risk-med' : 'risk-low'}">RISK ${r.risk_score}</span>
          <button class="btn" data-open-report="${esc(r.incident_id)}">Open report</button>
        </div>
      </div>
      <div class="panel-body" style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;">
        ${r.domains.map((d) => `<span class="dom-tag dom-${esc(d)}">${esc(d)}</span>`).join('')}
        ${r.missing_domains.length ? `<span style="font-size:11px;color:var(--amber);">⚠ missing: ${r.missing_domains.map(esc).join(', ')}</span>` : '<span style="font-size:11px;color:var(--green);">✓ full domain coverage</span>'}
        <span style="font-size:11px;color:var(--muted);">${esc(r.verdict)}</span>
      </div>
    </div>
  `).join('');
}

async function openReport(incidentId) {
  const res = await api(`/api/incidents/${encodeURIComponent(incidentId)}/report`);
  if (!res.ok) return toast('Failed to load report', true);
  const { report, adversarial, chain } = res.body;
  const root = $('#modalRoot');
  root.innerHTML = `
    <div class="modal">
      <div class="modal-content">
        <button class="close-x" data-close-modal aria-label="Close report">×</button>
        <h3>${esc(report.title)}</h3>
        <div class="modal-meta">
          <span class="risk-pill ${report.risk_score >= 50 ? 'risk-high' : report.risk_score >= 25 ? 'risk-med' : 'risk-low'}">RISK ${report.risk_score}</span>
          <span>${esc(report.verdict)}</span>
          <span>confidence ${(report.confidence * 100).toFixed(0)}%</span>
          <span>coverage ${(report.coverage.coverage_ratio * 100).toFixed(0)}%</span>
          <span>chain: ${chain.ok ? '✓ verified' : '✗ BROKEN'}</span>
        </div>
        ${report.adversarial_findings.length ? `<div class="adv-flag"><strong>ADVERSARIAL:</strong> ${report.adversarial_findings.map((f) => `${esc(f.type)} (${esc(f.pattern)}) — ${esc(f.note)}`).join(' · ')}</div>` : ''}
        <h2 style="font-size:13px;margin:14px 0 8px;">Timeline</h2>
        ${report.timeline.map((t) => `
          <div class="timeline-item">
            <div class="tl-time">${esc(t.time)}</div>
            <div class="tl-stage"><span class="stage-tag dom-${esc(t.domain)}">${esc(t.stage)}</span></div>
            <div>
              <div>${esc(t.summary)} ${t.adversarial_flags.length ? `<span class="risk-pill risk-high">flagged: ${t.adversarial_flags.map(esc).join(',')}</span>` : ''}</div>
              <div class="ev-id" data-ev="${esc(t.evidence_id)}" title="Inspect raw evidence record">${esc(t.evidence_id)} · ${esc(t.content_hash)}</div>
            </div>
          </div>
        `).join('')}
        <h2 style="font-size:13px;margin:16px 0 8px;">Findings by Domain</h2>
        ${report.sections.map((s) => `
          <div style="margin-bottom:12px;">
            <div style="font-size:12px;font-weight:600;margin-bottom:4px;">${esc(s.title)}</div>
            ${s.claims.map((c) => `
              <div class="claim">
                ${esc(c.claim)}
                <div style="margin-top:4px;">cited: ${c.evidence.map((id) => `<span class="ev-id" data-ev="${esc(id)}" title="Inspect raw evidence record">${esc(id)}</span>`).join(', ')}</div>
              </div>
            `).join('')}
            ${s.data_gaps.map((g) => `<div class="gap-flag"><strong>DATA GAP:</strong> ${esc(g)}</div>`).join('')}
          </div>
        `).join('')}
        <div class="gap-flag" style="margin-top:6px;"><strong>COVERAGE NOTE:</strong> ${esc(report.coverage.note)}</div>
        <div style="margin-top:14px;font-size:11px;color:var(--muted);">
          Guarantees: ${Object.entries(report.anti_hallucination_guarantees).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(' · ')}
        </div>
      </div>
    </div>`;
}

// ---------------------------------------------------------------------------
// Threat origins view (projected world map)
// ---------------------------------------------------------------------------
function drawWorld() {
  const g = document.getElementById('worldShapes');
  if (!g || !window.SENTINEL_GEO) return;
  for (const c of SENTINEL_GEO.continents) {
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    p.setAttribute('d', SENTINEL_GEO.pathFor(c.pts));
    p.setAttribute('fill', '#151f2b');
    p.setAttribute('stroke', '#223042');
    p.setAttribute('stroke-width', '1');
    g.appendChild(p);
  }
}

async function loadThreats() {
  const res = await api('/api/reports');
  const map = $('#worldMap');
  const list = $('#advList');
  map.querySelectorAll('.threat-pin, .pin-label').forEach((el) => el.remove());
  $('#mapHint')?.remove();
  if (!res.ok) {
    list.innerHTML = authPrompt('Admin token required — sign in to view threat origins.');
    return;
  }
  const { reports, adversarial } = res.body;

  // Pins derive ONLY from location_intel with provenance. Unknown-origin IPs
  // are listed separately as unlocated — never guessed onto the map.
  const pins = {};
  const unlocated = new Set();
  const unmapped = new Set();
  for (const r of reports) {
    const li = r.location_intel;
    if (!li) continue;
    for (const c of li.countries) {
      pins[c.country] = pins[c.country] || { count: 0, score: 0, prov: c.provenance, ips: new Set() };
      pins[c.country].count += c.event_count;
      pins[c.country].score = Math.max(pins[c.country].score, r.risk_score);
      c.ips.forEach((ip) => pins[c.country].ips.add(ip));
    }
    li.unlocated_ips.forEach((ip) => unlocated.add(ip));
  }

  const pinEls = Object.entries(pins).map(([geo, info]) => {
    const coords = window.SENTINEL_GEO && SENTINEL_GEO.countryCoords[geo];
    if (!coords) {
      unmapped.add(geo);
      return '';
    }
    const pos = SENTINEL_GEO.project(coords[0], coords[1]);
    const color = info.prov === 'operator_intel' ? 'var(--red)' : 'var(--amber)';
    const provBadge = info.prov === 'operator_intel' ? 'intel' : 'IdP geo';
    return `<div class="threat-pin" style="left:${(pos.x / 10).toFixed(2)}%;top:${(pos.y / 5).toFixed(2)}%;background:${color};box-shadow:0 0 10px ${color};"
              title="${esc(geo)} — ${info.count} events, max risk ${info.score} (${provBadge})"></div>
            <div class="pin-label" style="left:${(pos.x / 10).toFixed(2)}%;top:${(pos.y / 5).toFixed(2)}%;color:${color};">${esc(geo)} ×${info.count} risk ${info.score} [${provBadge}]</div>`;
  }).join('');
  map.insertAdjacentHTML('beforeend', pinEls);
  if (!Object.keys(pins).length) {
    map.insertAdjacentHTML('beforeend', '<div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:12px;">No location-tagged threat evidence</div>');
  }

  const unlocatedBox = $('#unlocatedBox');
  if (unlocatedBox) {
    let html = '';
    if (unmapped.size) {
      html += `<div class="gap-flag"><strong>NO COORDINATES:</strong> ${[...unmapped].map(esc).join(', ')} — evidence exists but this map has no pin for the code; listed here rather than guessed.</div>`;
    }
    html += unlocated.size
      ? `<div class="gap-flag"><strong>UNKNOWN ORIGIN (${unlocated.size} IP):</strong> ${[...unlocated].map(esc).join(', ')} — no location evidence; NOT placed on map.</div>`
      : '<div style="font-size:11px;color:var(--green);">✓ All external IPs located with provenance.</div>';
    unlocatedBox.innerHTML = html;
  }

  list.innerHTML = adversarial.findings.length
    ? adversarial.findings.slice(0, 20).map((f) => `
      <div class="adv-flag">
        <strong>${esc(f.severity).toUpperCase()}</strong> · ${esc(f.type)}:${esc(f.pattern)} · evidence <span class="ev-id" data-ev="${esc(f.evidence_id)}">${esc(f.evidence_id)}</span><br/>
        ${esc(f.note)}
      </div>
    `).join('')
    : '<div class="empty">No adversarial findings — chain verified, no injection/replay detected.</div>';
}

// ---------------------------------------------------------------------------
// Locations view — graphs + table + keys
// ---------------------------------------------------------------------------
function activitySeries(reports) {
  const times = [];
  for (const r of reports) {
    for (const t of r.timeline || []) {
      const ts = Date.parse(t.time);
      if (!Number.isNaN(ts)) times.push(ts);
    }
  }
  if (!times.length) return [];
  times.sort((a, b) => a - b);
  const start = times[0];
  const end = Math.max(times[times.length - 1], start + 1);
  const spanH = (end - start) / 3.6e6;
  const bucketMs = spanH <= 48 ? 3.6e6 : 864e5; // hourly for 2 days, else daily
  const buckets = Math.max(1, Math.min(48, Math.ceil((end - start) / bucketMs) + 1));
  const counts = new Array(buckets).fill(0);
  for (const t of times) counts[Math.min(buckets - 1, Math.floor((t - start) / bucketMs))] += 1;
  const fmt = bucketMs < 864e5
    ? (i) => new Date(start + i * bucketMs).toISOString().slice(11, 16)
    : (i) => new Date(start + i * bucketMs).toISOString().slice(5, 10);
  return counts.map((v, i) => ({ label: fmt(i), value: v }));
}

async function loadLocations() {
  const [loc, rep] = await Promise.all([api('/api/locations'), api('/api/reports')]);
  if (!loc.ok) {
    $('#locKpis').innerHTML = '';
    $('#chartCountryBar').innerHTML = '';
    $('#chartProvDonut').innerHTML = '';
    $('#chartActivity').innerHTML = '';
    $('#locTable').innerHTML = authPrompt('Admin token required — sign in to view origin geography.');
    return;
  }
  const { countries, unlocated_ips, note } = loc.body;

  $('#locKpis').innerHTML = `
    <div class="kpi"><div class="v accent">${countries.length}</div><div class="l">Countries Tracked</div></div>
    <div class="kpi"><div class="v red">${countries.filter((c) => c.risk_max >= 50).length}</div><div class="l">High-Risk Origins</div></div>
    <div class="kpi"><div class="v amber">${unlocated_ips.length}</div><div class="l">Unlocated IPs (not guessed)</div></div>
    <div class="kpi"><div class="v green">${countries.reduce((s, c) => s + c.events, 0)}</div><div class="l">Located Events</div></div>`;

  // Bar chart — events by country, colored by max incident risk.
  const barData = countries.slice(0, 12).map((c) => ({
    label: c.country,
    value: c.events,
    color: c.risk_max >= 50 ? '#e74c3c' : c.risk_max >= 25 ? '#f1c40f' : '#2ecc71',
  }));
  Charts.bar($('#chartCountryBar'), { data: barData, title: 'Evidence events by country' });

  // Donut — provenance mix (the anti-hallucination story: geo always sourced).
  const prov = { operator_intel: 0, provider_geo: 0 };
  for (const c of countries) prov[c.provenance] = (prov[c.provenance] || 0) + c.events;
  Charts.donut($('#chartProvDonut'), {
    data: [
      { label: 'operator intel table', value: prov.operator_intel, color: '#e74c3c' },
      { label: 'identity-provider geo', value: prov.provider_geo, color: '#f1c40f' },
    ],
    centerLabel: 'located events',
    centerValue: prov.operator_intel + prov.provider_geo,
    title: 'Location provenance mix',
  });

  // Area chart — threat activity over time from evidence timelines.
  Charts.area($('#chartActivity'), {
    points: activitySeries(rep.ok ? rep.body.reports : []),
    title: 'Threat activity over time',
  });

  $('#locTable').innerHTML = countries.length ? `
    <table>
      <tr><th>Country</th><th>Incidents</th><th>Events</th><th>Max Risk</th><th>Provenance</th><th>Tags</th><th>IPs</th></tr>
      ${countries.map((c) => `
        <tr>
          <td><strong>${esc(c.country)}</strong></td>
          <td>${c.incidents}</td>
          <td>${c.events}</td>
          <td><span class="risk-pill ${c.risk_max >= 50 ? 'risk-high' : c.risk_max >= 25 ? 'risk-med' : 'risk-low'}">${c.risk_max}</span></td>
          <td style="font-size:10px;">${esc(c.provenance)}</td>
          <td style="font-size:10px;">${c.tags.map(esc).join(', ') || '—'}</td>
          <td style="font-size:10px;">${c.ips.map(esc).join('<br/>')}</td>
        </tr>
      `).join('')}
    </table>
    <div style="font-size:11px;color:var(--muted);margin-top:10px;">${esc(note)}</div>
  ` : '<div class="empty">No location-tagged evidence yet.</div>';

  loadKeys();
}

$('#btnLoadLoc').addEventListener('click', loadLocations);

// ---------------------------------------------------------------------------
// API keys management (admin)
// ---------------------------------------------------------------------------
$('#btnMintKey').addEventListener('click', async () => {
  const name = $('#keyName').value.trim() || 'unnamed';
  const res = await api('/api/keys', { method: 'POST', body: JSON.stringify({ name }) });
  if (res.status === 403 && res.body.demo) return toast('Demo mode: key management needs a live backend', true);
  if (!res.ok) return toast('Key creation failed (admin token required)', true);
  $('#keyName').value = '';
  loadKeys();
  const full = res.body.key;
  $('#keyList').insertAdjacentHTML('afterbegin', `
    <div class="gap-flag" style="border-left-color:var(--green);background:rgba(46,204,113,0.06);">
      <strong>NEW KEY (copy now — shown once):</strong><br/>
      <code style="font-family:var(--mono);font-size:11px;">${esc(full)}</code>
    </div>
  `);
  toast(`API key "${res.body.name}" created`);
});

async function loadKeys() {
  const res = await api('/api/keys');
  const box = $('#keyList');
  if (!res.ok) {
    box.innerHTML = authPrompt('Admin token required to manage keys.');
    return;
  }
  if (res.body.demo) {
    box.innerHTML = '<div class="empty">Demo mode — connect a live backend to mint and revoke ingest keys.</div>';
    return;
  }
  box.innerHTML = res.body.keys.length
    ? `<table>
        <tr><th>Name</th><th>Key</th><th>Status</th><th>Last used</th><th></th></tr>
        ${res.body.keys.map((k) => `
          <tr>
            <td>${esc(k.name)}</td>
            <td style="font-size:10px;">${esc(k.key_preview)}</td>
            <td>${k.revoked ? '<span class="risk-pill risk-high">revoked</span>' : '<span class="risk-pill risk-low">active</span>'}</td>
            <td style="font-size:10px;">${esc(k.last_used || 'never')}</td>
            <td>${k.revoked ? '' : `<button class="btn danger" data-revoke="${esc(k.id)}">Revoke</button>`}</td>
          </tr>
        `).join('')}
      </table>`
    : '<div class="empty">No managed keys — bootstrap token from INGEST_TOKENS still works.</div>';
  box.querySelectorAll('[data-revoke]').forEach((b) => {
    b.addEventListener('click', async () => {
      await api(`/api/keys/${b.dataset.revoke}`, { method: 'DELETE' });
      loadKeys();
      toast('Key revoked');
    });
  });
}

// ---------------------------------------------------------------------------
// Eval view
// ---------------------------------------------------------------------------
$('#btnRunEval').addEventListener('click', async () => {
  $('#evalResults').innerHTML = '<div class="empty">Running golden scenarios…</div>';
  const res = await api('/api/evaluation/run', { method: 'POST' });
  if (!res.ok) {
    $('#evalResults').innerHTML = authPrompt('Evaluation needs read access — sign in to run it.');
    return;
  }
  const ev = res.body;
  $('#evalResults').innerHTML = `
    <div class="kpis">
      <div class="kpi"><div class="v ${ev.all_passed ? 'green' : 'red'}">${ev.scenarios_passed}/${ev.scenarios_total}</div><div class="l">Scenarios Passed</div></div>
      <div class="kpi"><div class="v ${ev.aggregate.fabrication_rate === 0 ? 'green' : 'red'}">${ev.aggregate.fabrication_rate}</div><div class="l">Fabrication Rate (must be 0)</div></div>
      <div class="kpi"><div class="v accent">${ev.aggregate.claims_total}</div><div class="l">Claims Verified</div></div>
    </div>
    ${ev.results.map((r) => `
      <div class="panel" style="margin-bottom:12px;">
        <div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
          <div style="font-family:var(--mono);font-size:13px;">${esc(r.scenario)}</div>
          <span class="risk-pill ${r.passed ? 'risk-low' : 'risk-high'}">${r.passed ? 'PASS' : 'FAIL'}</span>
        </div>
        <div class="panel-body">
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px;">${esc(r.description)}</div>
          ${r.checks.map((c) => `<div class="eval-check"><span class="${c.passed ? 'ok' : 'fail'}">${c.passed ? '✓' : '✗'}</span> ${esc(c.name)} — <span style="color:var(--muted);">${esc(c.detail)}</span></div>`).join('')}
        </div>
      </div>
    `).join('')}
  `;
  toast(ev.all_passed ? 'All scenarios passed — fabrication rate 0' : 'Some scenarios FAILED — review before trusting reports', !ev.all_passed);
});

// ---------------------------------------------------------------------------
// API view
// ---------------------------------------------------------------------------
async function loadApiRef() {
  const res = await api('/api');
  $('#apiRef').textContent = res.ok ? JSON.stringify(res.body, null, 2) : 'Failed to load /api';
}

$('#btnTry').addEventListener('click', async () => {
  const p = $('#tryPath').value.trim();
  const res = await api(p.startsWith('/') ? p : `/${p}`);
  $('#tryResult').textContent = JSON.stringify(res.body, null, 2);
});

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
(async () => {
  populateActions();
  drawWorld();
  updateSessionUI();
  await detectPublicMode();
  await validateSession();
  refreshLive();
  loadIncidents();
  loadKeys();
})();

// Poll only when live data is available (demo snapshots are static).
setInterval(() => {
  if (backendReachable && $('#view-live').style.display !== 'none') refreshLive();
}, 15000);
