'use strict';

const express = require('express');
const path = require('node:path');
const config = require('./config');
const logger = require('./lib/logger');
const { EvidenceRegistry } = require('./lib/evidence-registry');
const { normalizeEvent, DOMAINS } = require('./lib/ingest');
const { correlate, assetMap } = require('./lib/correlate');
const { sweep } = require('./lib/adversarial');
const { generateAll, generateOne } = require('./lib/report');
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
app.use(express.json({ limit: '1mb' }));

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
  if (!token || token !== config.adminToken) {
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
  });
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
      key_preview: k.key.slice(0, 14) + '…',
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
  const incidents = correlate(registry);
  const byCountry = new Map(); // country -> { incidents, events, ips:Set, provenance, risk_max, tags:Set }
  const unlocated = new Set();
  for (const inc of incidents) {
    const li = inc.location_intel || { countries: [], unlocated_ips: [] };
    for (const c of li.countries) {
      const rec = byCountry.get(c.country) || { country: c.country, incidents: 0, events: 0, ips: new Set(), provenance: c.provenance, risk_max: 0, tags: new Set() };
      rec.incidents += 1;
      rec.events += c.event_count;
      c.ips.forEach((ip) => rec.ips.add(ip));
      rec.risk_max = Math.max(rec.risk_max, inc.risk_score);
      for (const ip of c.ips) {
        const intel = assetMap.ipIntel[ip];
        if (intel?.tags) intel.tags.forEach((t) => rec.tags.add(t));
      }
      byCountry.set(c.country, rec);
    }
    li.unlocated_ips.forEach((ip) => unlocated.add(ip));
  }
  res.json({
    countries: [...byCountry.values()]
      .map((c) => ({ ...c, ips: [...c.ips], tags: [...c.tags] }))
      .sort((a, b) => b.risk_max - a.risk_max || b.events - a.events),
    unlocated_ips: [...unlocated],
    note: unlocated.size ? `${unlocated.size} external IP(s) unlocated — not guessed.` : 'All external IPs located with provenance.',
  });
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
