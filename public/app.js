'use strict';

/* Sentinel SOC dashboard — vanilla JS, no build step. */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let adminToken = localStorage.getItem('sentinel_admin_token') || '';
$('#tokenInput').value = adminToken || '';
$('#tokenInput').addEventListener('change', (e) => {
  adminToken = e.target.value.trim();
  localStorage.setItem('sentinel_admin_token', adminToken);
});

// ---- Custom API URL support: point the dashboard at any host ----
let apiBase = localStorage.getItem('sentinel_api_base') || '';
$('#apiBaseInput').value = apiBase;
function normalizeBase(u) {
  const s = u.trim().replace(/\/+$/, '');
  if (!s) return '';
  return /^https?:\/\//i.test(s) ? s : `https://${s}`;
}
$('#apiBaseInput').addEventListener('change', (e) => {
  apiBase = normalizeBase(e.target.value);
  localStorage.setItem('sentinel_api_base', apiBase);
  toast(apiBase ? `API base set: ${apiBase}` : 'API base cleared — using this host');
  refreshLive();
});

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
    .map((f) => `<div class="form-group"><label>${f.label}</label><input data-fkey="${f.key}" placeholder="${f.ph}" style="width:100%;" /></div>`)
    .join('');
}
$('#ingDomain').addEventListener('change', populateActions);
populateActions();

// ---- View switching ----
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
    if (btn.dataset.view === 'api') loadApiRef();
    if (btn.dataset.view === 'live') refreshLive();
  });
});

// ---- Locations view (hacker origin tracking) ----
async function loadLocations() {
  const res = await api('/api/locations');
  if (!res.ok) {
    $('#locKpis').innerHTML = '';
    $('#locTable').innerHTML = '<div class="empty">Admin token required.</div>';
    return;
  }
  const { countries, unlocated_ips, note } = res.body;
  $('#locKpis').innerHTML = `
    <div class="kpi"><div class="v accent">${countries.length}</div><div class="l">Countries Tracked</div></div>
    <div class="kpi"><div class="v red">${countries.filter((c) => c.risk_max >= 50).length}</div><div class="l">High-Risk Origins</div></div>
    <div class="kpi"><div class="v amber">${unlocated_ips.length}</div><div class="l">Unlocated IPs (not guessed)</div></div>
  `;
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
}

$('#btnLoadLoc').addEventListener('click', loadLocations);

// ---- API keys management ----
$('#btnMintKey').addEventListener('click', async () => {
  const name = $('#keyName').value.trim() || 'unnamed';
  const res = await api('/api/keys', { method: 'POST', body: JSON.stringify({ name }) });
  if (!res.ok) return toast('Key creation failed (admin token required)', true);
  $('#keyName').value = '';
  loadKeys();
  // Show the full key once — it is never displayed again.
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
  if (!res.ok) {
    $('#keyList').innerHTML = '<div class="empty">Admin token required to manage keys.</div>';
    return;
  }
  $('#keyList').innerHTML = res.body.keys.length
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
  $('#keyList').querySelectorAll('[data-revoke]').forEach((b) => {
    b.addEventListener('click', async () => {
      await api(`/api/keys/${b.dataset.revoke}`, { method: 'DELETE' });
      loadKeys();
      toast('Key revoked');
    });
  });
}
loadKeys();

function authHeaders() {
  return adminToken ? { Authorization: `Bearer ${adminToken}` } : {};
}

async function api(path, opts = {}) {
  const url = apiBase ? `${apiBase}${path}` : path;
  const res = await fetch(url, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(opts.headers || {}) },
  });
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

let publicMode = false; // set true if the server reports open read access
async function detectPublicMode() {
  const probe = await api('/api/incidents').catch(() => null);
  publicMode = !!(probe && probe.ok);
  if (publicMode) {
    document.querySelectorAll('.auth-hint').forEach((el) => el.remove());
  } else {
    // Backend unreachable (e.g. static hosting like GitHub Pages).
    const banner = document.createElement('div');
    banner.style.cssText = 'background:rgba(241,196,15,0.1);border:1px solid var(--amber);color:var(--text);padding:10px 16px;border-radius:8px;margin:0 22px 10px;font-size:13px;';
    banner.innerHTML = '⚠ Backend API not connected — this page is the static dashboard. Deploy the backend (Render → <code>sentinel-soc</code>) and enter its URL (e.g. <code>https://sentinel-soc.onrender.com</code>) in the <b>API URL</b> field in the header to bring the data live.';
    const nav = document.querySelector('nav');
    nav.parentNode.insertBefore(banner, nav.nextSibling);
  }
  return publicMode;
}

function toast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast';
  if (isError) el.style.borderColor = 'var(--red)';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---- Live view ----
async function refreshLive() {
  const stats = await api('/api/stats');
  if (stats.ok) {
    $('#kpiEvents').textContent = stats.body.total_events ?? '—';
  }
  const integrity = await api('/api/integrity/verify');
  if (integrity.ok) {
    const ok = integrity.body.ok;
    $('#chainText').textContent = ok ? 'CHAIN OK' : 'CHAIN BROKEN';
    $('#chainChip .dot').className = `dot ${ok ? 'ok' : 'bad'}`;
    $('#integrityBox').textContent = JSON.stringify(integrity.body, null, 2);
  } else {
    $('#integrityBox').textContent = `Auth required (admin token) — ${integrity.status}`;
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

$('#btnIngest').addEventListener('click', async () => {
  const payload = { domain: $('#ingDomain').value, action: $('#ingAction').value, timestamp: new Date().toISOString(), source_tool: 'dashboard-simulator' };
  document.querySelectorAll('#ingFields input').forEach((inp) => {
    if (!inp.value) return;
    payload[inp.dataset.fkey] = inp.dataset.num ? Number(inp.value) : inp.value.trim();
  });
  const res = await fetch('/api/ingest/event', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${$('#ingToken').value.trim()}` },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => ({}));
  $('#ingResult').textContent = JSON.stringify(body, null, 2);
  if (res.ok) {
    toast(body.replay ? 'Event accepted (replay detected as duplicate)' : 'Event accepted into evidence registry');
    refreshLive();
  } else {
    toast(`Ingest rejected: ${body.reason || body.error}`, true);
  }
});

// ---- Incidents view ----
async function loadIncidents() {
  const res = await api('/api/reports');
  const box = $('#incidentList');
  if (!res.ok) {
    box.innerHTML = `<div class="empty auth-hint">Admin token required to view reports (set it top-right)${publicMode ? '' : ' — or this is a public demo where data loads automatically'}.</div>`;
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
  box.querySelectorAll('[data-open-report]').forEach((b) => {
    b.addEventListener('click', () => openReport(b.dataset.openReport));
  });
}

async function openReport(incidentId) {
  const res = await api(`/api/incidents/${incidentId}/report`);
  if (!res.ok) return toast('Failed to load report', true);
  const { report, adversarial, chain } = res.body;
  const root = $('#modalRoot');
  root.innerHTML = `
    <div class="modal" id="reportModal">
      <div class="modal-content">
        <button class="close-x" onclick="document.getElementById('reportModal').remove()">×</button>
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
              <div class="ev-id" data-ev="${esc(t.evidence_id)}">${esc(t.evidence_id)} · ${esc(t.content_hash)}</div>
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
                <div style="margin-top:4px;">cited: ${c.evidence.map((id) => `<span class="ev-id" data-ev="${esc(id)}">${esc(id)}</span>`).join(', ')}</div>
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
  root.querySelectorAll('[data-ev]').forEach((el) => {
    el.addEventListener('click', () => showEvidence(el.dataset.ev));
  });
}

async function showEvidence(eventId) {
  const res = await api(`/api/stats`);
  void res;
  const integrity = await api('/api/integrity/verify');
  void integrity;
  toast(`Evidence ${eventId} — inspect via GET /api/incidents/:id/report (citations resolve to registry hashes)`);
}

// ---- Threats view ----
const GEO_PINS = {
  RU: { x: 720, y: 130 },
  CN: { x: 790, y: 165 },
  KP: { x: 815, y: 155 },
  IR: { x: 610, y: 175 },
  SG: { x: 760, y: 250 },
  US: { x: 220, y: 150 },
  BR: { x: 320, y: 330 },
  NG: { x: 470, y: 265 },
};async function loadThreats() {
  const res = await api('/api/reports');
  const map = $('#worldMap');
  const list = $('#advList');
  map.querySelectorAll('.threat-pin, .pin-label').forEach((el) => el.remove());
  $('#mapHint')?.remove();
  if (!res.ok) {
    list.innerHTML = `<div class="empty">Admin token required.</div>`;
    return;
  }
  const { reports, adversarial } = res.body;

  // Pins derive ONLY from location_intel with provenance. Unknown-origin IPs
  // are listed separately as unlocated — never guessed onto the map.
  const pins = {};
  const unlocated = new Set();
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
    const pos = GEO_PINS[geo];
    if (!pos) return '';
    const color = info.prov === 'operator_intel' ? 'var(--red)' : 'var(--amber)';
    const provBadge = info.prov === 'operator_intel' ? 'intel' : 'IdP geo';
    return `<div class="threat-pin" style="left:${pos.x / 10}%;top:${pos.y / 5}%;background:${color};box-shadow:0 0 10px ${color};"></div>
            <div class="pin-label" style="left:${pos.x / 10}%;top:${pos.y / 5}%;color:${color};">${esc(geo)} ×${info.count} risk ${info.score} [${provBadge}]</div>`;
  }).join('');
  map.insertAdjacentHTML('beforeend', pinEls);
  if (!Object.keys(pins).length) {
    map.insertAdjacentHTML('beforeend', '<div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:12px;">No location-tagged threat evidence</div>');
  }

  const unlocatedBox = document.getElementById('unlocatedBox');
  if (unlocatedBox) {
    unlocatedBox.innerHTML = unlocated.size
      ? `<div class="gap-flag"><strong>UNKNOWN ORIGIN (${unlocated.size} IP):</strong> ${[...unlocated].map(esc).join(', ')} — no location evidence; NOT placed on map.</div>`
      : '<div style="font-size:11px;color:var(--green);">✓ All external IPs located with provenance.</div>';
  }

  list.innerHTML = adversarial.findings.length
    ? adversarial.findings.slice(0, 20).map((f) => `
      <div class="adv-flag">
        <strong>${esc(f.severity).toUpperCase()}</strong> · ${esc(f.type)}:${esc(f.pattern)} · evidence <span class="ev-id">${esc(f.evidence_id)}</span><br/>
        ${esc(f.note)}
      </div>
    `).join('')
    : '<div class="empty">No adversarial findings — chain verified, no injection/replay detected.</div>';
}

// ---- Eval view ----
$('#btnRunEval').addEventListener('click', async () => {
  $('#evalResults').innerHTML = '<div class="empty">Running golden scenarios…</div>';
  const res = await api('/api/evaluation/run', { method: 'POST' });
  if (!res.ok) return;
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

// ---- API view ----
async function loadApiRef() {
  const res = await api('/api').catch(() => null);
  $('#apiRef').textContent = res && res.ok ? JSON.stringify(res.body, null, 2) : 'Failed to load /api';
}

$('#btnTry').addEventListener('click', async () => {
  const p = $('#tryPath').value.trim();
  const res = await api(p.startsWith('/') ? p : `/${p}`);
  $('#tryResult').textContent = JSON.stringify(res.body, null, 2);
});

// ---- Init ----
(async () => {
  await detectPublicMode();
  refreshLive();
  loadIncidents();
  loadKeys();
})();
setInterval(() => {
  if ($('#view-live').style.display !== 'none') refreshLive();
}, 15000);
