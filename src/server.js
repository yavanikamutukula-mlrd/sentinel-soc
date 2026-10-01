'use strict';

const express = require('express');
const path = require('node:path');
const crypto = require('node:crypto');
const config = require('./config');
const logger = require('./lib/logger');
const { EvidenceRegistry } = require('./lib/evidence-registry');
const { normalizeEvent, DOMAINS } = require('./lib/ingest');
const { correlate } = require('./lib/correlate');
const { sweep } = require('./lib/adversarial');
const { generateAll, generateOne } = require('./lib/report');
const { aggregateLocations } = require('./lib/locations');
const { runAll } = require('./lib/eval');
const { randomId } = require('./lib/util');
const { ApiKeyStore } = require('./lib/apikeys');

const registry = new EvidenceRegistry();
const apiKeys = new ApiKeyStore();

// Free hosts (Render etc.) wipe the disk on restart. When AUTO_SEED is on
// and the registry is empty, rebuild the demo dataset so the chain, incidents,
// and threat map are demonstrable immediately after cold start.
if (config.autoSeed && registry.order.length === 0) {
  try {
    // eslint-disable-next-line global-require
    require('../scripts/seed-lib').seedRegistry(registry);
    logger.info('auto-seeded empty registry (AUTO_SEED=true)');
  } catch (err) {
    logger.error('auto-seed failed', { error: String(err) });
  }
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // behind Render/Pages proxies: correct req.ip + protocol
app.use(express.json({ limit: '1mb' }));

// ---- Security headers (privacy & integration hardening) ----
// CSP blocks third-party script injection; HSTS/anti-clickjacking/anti-sniff
// headers protect dashboard users. connect-src restricts API calls to self +
// https so a pasted API host can't exfiltrate tokens to arbitrary origins.
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; font-src 'self'; connect-src 'self' https: http://localhost:* http://127.0.0.1:*; " +
      "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  });
  next();
});

// ---- Timing-safe secret comparison ----
function safeEqual(a, b) {
  const ab = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
  const bb = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
  if (ab.length !== bb.length) {
    // Compare against self to keep timing uniform, then fail.
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

// ---- CORS: allow browser clients on custom domains to call this API ----
app.use((req, res, next) => {
  const origin = req.get('origin');
  const allow = config.allowedOrigins.includes('*') || config.allowedOrigins.includes(origin);
  if (origin && allow) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');
    res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.set('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---- Simple in-memory rate limiter for ingest ----
const rateBuckets = new Map(); // key -> timestamps[]
function rateLimit(key, limitPerMin) {
  const nowTs = Date.now();
  const windowStart = nowTs - 60_000;
  const list = (rateBuckets.get(key) || []).filter((t) => t > windowStart);
  if (list.length >= limitPerMin) return false;
  list.push(nowTs);
  rateBuckets.set(key, list);
  return true;
}

// ---- Auth ----
function requireAdmin(req, res, next) {
  // Public demo mode: read-only access is open; mutations still need auth.
  const readOnly = req.method === 'GET' || (req.method === 'POST' && req.path === '/api/evaluation/run');
  if (config.publicMode && readOnly) return next();
  const token = req.get('authorization')?.replace(/^Bearer\s+/i, '') || req.get('x-api-key');
  if (!token || !safeEqual(token, config.adminToken)) {
    return res.status(401).json({ error: 'unauthorized', hint: 'provide admin token via Authorization: Bearer or x-api-key' });
  }
  next();
}

function requireIngest(req, res, next) {
  const token = req.get('authorization')?.replace(/^Bearer\s+/i, '') || req.get('x-api-key');
  if (!token) {
    return res.status(401).json({ error: 'unauthorized', hint: 'provide ingest API key via Authorization: Bearer or x-api-key' });
  }
  const v = apiKeys.validate(token);
  if (!v.ok) {
    return res.status(401).json({ error: 'unauthorized', hint: 'invalid or revoked API key' });
  }
  req.tokenId = v.tokenId;
  req.keyName = v.name || 'bootstrap';
  next();
}

// ---- Public meta ----
app.get('/api', (req, res) => {
  const base = config.publicBaseUrl || `${req.protocol}://${req.get('host')}`;
  res.json({
    name: config.appName,
    version: config.version,
    description: 'AI-assisted SOC investigation: evidence-backed correlation with anti-hallucination guarantees',
    domains: DOMAINS,
    endpoints: {
      health: `${base}/api/health`,
      ingest_event: `${base}/api/ingest/event  (POST, ingest token)`,
      ingest_batch: `${base}/api/ingest/batch  (POST, ingest token)`,
      incidents: `${base}/api/incidents  (GET, admin)`,
      report: `${base}/api/incidents/:id/report  (GET, admin)`,
      reports_all: `${base}/api/reports  (GET, admin)`,
      verify_chain: `${base}/api/integrity/verify  (GET, admin)`,
      adversarial_sweep: `${base}/api/adversarial/sweep  (GET, admin)`,
      evaluation: `${base}/api/evaluation/run  (POST, admin)`,
      stats: `${base}/api/stats  (GET)`,
    },
    anti_hallucination: 'reports cite evidence IDs for every claim; missing data is flagged, never invented',
    public_mode: config.publicMode ? 'read-only endpoints are open; ingest & key management require API keys' : 'all analysis endpoints require the admin token',
    access: {
      public_mode: config.publicMode,
      allowed_origins: config.allowedOrigins,
      custom_base_url: config.publicBaseUrl || null,
      note: 'for browser clients on custom domains/subdomains, set ALLOWED_ORIGINS (comma-separated list or *)',
    },
  });
});

// ---- Session introspection (login / logout support) ----
// Always open: lets the dashboard validate a presented token and learn
// what role it carries without exposing anything else.
app.get('/api/auth/whoami', (req, res) => {
  const token = req.get('authorization')?.replace(/^Bearer\s+/i, '') || req.get('x-api-key');
  let role = 'public';
  let name = 'visitor';
  if (token && safeEqual(token, config.adminToken)) {
    role = 'admin';
    name = 'admin';
  } else if (token) {
    const v = apiKeys.validate(token);
    if (v.ok) {
      role = 'ingest';
      name = v.name || 'ingest-key';
    }
  }
  res.json({
    role,
    name,
    public_mode: config.publicMode,
    capabilities: {
      view_incidents: config.publicMode || role === 'admin',
      view_reports: config.publicMode || role === 'admin',
      view_locations: config.publicMode || role === 'admin',
      run_evaluation: config.publicMode || role === 'admin',
      ingest: role === 'ingest' || role === 'admin',
      manage_keys: role === 'admin',
    },
  });
});

// ---- Single evidence record lookup (report citations resolve here) ----
app.get('/api/evidence/:id', requireAdmin, (req, res) => {
  const rec = registry.get(req.params.id);
  if (!rec) return res.status(404).json({ error: 'evidence not found', id: req.params.id });
  res.json({ ...rec, chain_integrity: registry.verifyChain().ok });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime_sec: Math.round(process.uptime()), events: registry.order.length });
});

app.get('/api/stats', (req, res) => {
  res.json(registry.stats());
});

// ---- Ingestion ----
function ingestOne(raw, req) {
  const ingestMeta = {
    channel: 'api',
    source_ip: req.ip,
    token_id: req.tokenId,
    received_at: new Date().toISOString(),
  };
  const norm = normalizeEvent(raw, ingestMeta);
  if (!norm.ok) {
    registry.reject(raw, norm.reason);
    return { accepted: false, reason: norm.reason };
  }
  const record = registry.buildRecord(norm.event, ingestMeta);
  const { record: committed, replay } = registry.commit(record);
  if (!replay) registry.persist();
  return { accepted: true, event_id: committed.event_id, hash: committed.hash, replay };
}

app.post('/api/ingest/event', requireIngest, (req, res) => {
  if (!rateLimit(req.tokenId, config.ingestRatePerMin)) {
    return res.status(429).json({ error: 'rate limit exceeded', limit_per_min: config.ingestRatePerMin });
  }
  const result = ingestOne(req.body, req);
  res.status(result.accepted ? 202 : 422).json(result);
});

app.post('/api/ingest/batch', requireIngest, (req, res) => {
  const events = req.body?.events;
  if (!Array.isArray(events)) return res.status(400).json({ error: 'body must be { "events": [...] }' });
  if (events.length > 500) return res.status(413).json({ error: 'batch too large (max 500)' });
  const results = events.map((e) => ingestOne(e, req));
  const accepted = results.filter((r) => r.accepted).length;
  res.status(207).json({ accepted, rejected: results.length - accepted, results });
});

// ---- Analysis ----
app.get('/api/incidents', requireAdmin, (req, res) => {
  res.json({ incidents: correlate(registry) });
});

app.get('/api/reports', requireAdmin, (req, res) => {
  const gen = generateAll(registry);
  if (!gen.ok) return res.status(409).json(gen);
  res.json({ chain: gen.chain, adversarial: gen.adversarial, reports: gen.reports });
});

app.get('/api/incidents/:id/report', requireAdmin, (req, res) => {
  const gen = generateOne(registry, req.params.id);
  if (!gen.ok) return res.status(404).json(gen);
  res.json(gen);
});

app.get('/api/integrity/verify', requireAdmin, (req, res) => {
  res.json(registry.verifyChain());
});

app.get('/api/adversarial/sweep', requireAdmin, (req, res) => {
  res.json(sweep(registry));
});

app.post('/api/evaluation/run', requireAdmin, (req, res) => {
  res.json(runAll());
});

// ---- API key management (admin) ----
// Privacy: only a SHA-256 hash of each key is stored server-side; the
// plaintext is returned exactly once below and can never be recovered.
app.post('/api/keys', requireAdmin, (req, res) => {
  const rec = apiKeys.create(req.body?.name);
  res.status(201).json({
    id: rec.id,
    name: rec.name,
    key: rec.key, // shown ONCE at creation; store it securely
    created_at: rec.created_at,
    usage: 'send as Authorization: Bearer <key> or x-api-key on /api/ingest/*',
  });
});

app.get('/api/keys', requireAdmin, (req, res) => {
  res.json({
    keys: apiKeys.list().map((k) => ({
      id: k.id,
      name: k.name,
      key_preview: k.preview || 'sk_ingest_…',
      created_at: k.created_at,
      revoked: k.revoked,
      last_used: k.last_used,
    })),
  });
});

app.delete('/api/keys/:id', requireAdmin, (req, res) => {
  const rec = apiKeys.revoke(req.params.id);
  if (!rec) return res.status(404).json({ error: 'key not found' });
  res.json({ revoked: true, id: rec.id, name: rec.name });
});

// ---- Threat-origin locations (aggregated across all incidents) ----
app.get('/api/locations', requireAdmin, (req, res) => {
  res.json(aggregateLocations(correlate(registry)));
});

// ---- Static frontend ----
app.use(express.static(config.publicDir));
app.get(/^\/(?!api\/).*/, (req, res) => {
  res.sendFile(path.join(config.publicDir, 'index.html'));
});

// ---- Errors ----
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error('unhandled error', { error: String(err?.stack || err) });
  res.status(500).json({ error: 'internal error' });
});

app.listen(config.port, config.host, () => {
  logger.info(`${config.appName} listening`, {
    port: config.port,
    env: config.env,
    events: registry.order.length,
    endpoints_base: config.publicBaseUrl || `http://localhost:${config.port}`,
  });
});

module.exports = app;
