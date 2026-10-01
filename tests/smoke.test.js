'use strict';

/**
 * Smoke tests — boot the real server (public demo mode, isolated data dir,
 * auto-seeded) and exercise the endpoints the dashboard depends on.
 * Run: npm test
 */

const { test } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

const PORT = 3457;
const BASE = `http://127.0.0.1:${PORT}`;
const ADMIN = 'test-admin-token';
const INGEST = 'test-ingest-token';

function startServer() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-'));
  return spawn(process.execPath, [path.join(__dirname, '..', 'src', 'server.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      HOST: '127.0.0.1',
      DATA_DIR: tmp,
      AUTO_SEED: 'true',
      PUBLIC_MODE: 'true',
      ADMIN_TOKEN: ADMIN,
      INGEST_TOKENS: INGEST,
    },
    stdio: 'ignore',
  });
}

async function waitForHealth(timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/api/health`);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('server did not become healthy in time');
}

test('public mode: reads open, whoami roles correct, writes require tokens', async () => {
  const child = startServer();
  try {
    await waitForHealth();

    // whoami: anonymous visitor → public role
    let res = await fetch(`${BASE}/api/auth/whoami`);
    let body = await res.json();
    assert.strictEqual(res.status, 200);
    assert.strictEqual(body.role, 'public');
    assert.strictEqual(body.public_mode, true);
    assert.strictEqual(body.capabilities.view_incidents, true); // public mode
    assert.strictEqual(body.capabilities.manage_keys, false);

    // whoami: admin token → admin role + capabilities
    res = await fetch(`${BASE}/api/auth/whoami`, { headers: { Authorization: `Bearer ${ADMIN}` } });
    body = await res.json();
    assert.strictEqual(body.role, 'admin');
    assert.strictEqual(body.capabilities.manage_keys, true);
    assert.strictEqual(body.capabilities.ingest, true);

    // whoami: bootstrap ingest token → ingest role
    res = await fetch(`${BASE}/api/auth/whoami`, { headers: { Authorization: `Bearer ${INGEST}` } });
    body = await res.json();
    assert.strictEqual(body.role, 'ingest');
    assert.strictEqual(body.capabilities.ingest, true);
    assert.strictEqual(body.capabilities.manage_keys, false);

    // whoami: garbage token → public (never an error — it's introspection)
    res = await fetch(`${BASE}/api/auth/whoami`, { headers: { Authorization: 'Bearer nope' } });
    body = await res.json();
    assert.strictEqual(body.role, 'public');

    // Public read access (PUBLIC_MODE=true): reports + locations
    res = await fetch(`${BASE}/api/reports`);
    assert.strictEqual(res.status, 200);
    body = await res.json();
    assert.ok(body.reports.length > 0, 'seeded reports exist');
    const report = body.reports[0];
    assert.ok(report.timeline.length > 0);
    const evId = report.timeline[0].evidence_id;

    res = await fetch(`${BASE}/api/locations`);
    assert.strictEqual(res.status, 200);
    body = await res.json();
    assert.ok(Array.isArray(body.countries));
    assert.ok(body.countries.length > 0, 'seeded incidents carry geo evidence');
    for (const c of body.countries) {
      assert.ok(['operator_intel', 'provider_geo'].includes(c.provenance), 'every country has provenance');
    }

    // Evidence lookup resolves a citation to the raw chained record
    res = await fetch(`${BASE}/api/evidence/${evId}`);
    assert.strictEqual(res.status, 200);
    body = await res.json();
    assert.strictEqual(body.event_id, evId);
    assert.ok(body.hash && body.prev_hash && body.content_hash, 'record carries chain fields');
    assert.strictEqual(body.chain_integrity, true);

    res = await fetch(`${BASE}/api/evidence/evt_does_not_exist`);
    assert.strictEqual(res.status, 404);

    // Writes stay protected: ingest without token → 401
    res = await fetch(`${BASE}/api/ingest/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    assert.strictEqual(res.status, 401);

    // Ingest with valid bootstrap token → 202 accepted
    res = await fetch(`${BASE}/api/ingest/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${INGEST}` },
      body: JSON.stringify({
        domain: 'identity',
        action: 'login_failure',
        timestamp: new Date().toISOString(),
        user: 't.tester',
        src_ip: '185.220.101.7',
        geo: 'RU',
        mfa_used: false,
        source_tool: 'smoke-test',
      }),
    });
    assert.strictEqual(res.status, 202);
    body = await res.json();
    assert.strictEqual(body.accepted, true);

    // Key minting requires admin token
    res = await fetch(`${BASE}/api/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    assert.strictEqual(res.status, 401);
    res = await fetch(`${BASE}/api/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ADMIN}` },
      body: JSON.stringify({ name: 'smoke' }),
    });
    assert.strictEqual(res.status, 201);
    body = await res.json();
    assert.ok(body.key.startsWith('sk_ingest_'));

    // Dashboard HTML is served for the root path
    res = await fetch(`${BASE}/`);
    assert.strictEqual(res.status, 200);
  } finally {
    child.kill();
  }
});
