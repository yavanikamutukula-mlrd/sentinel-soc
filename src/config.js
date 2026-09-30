'use strict';

const path = require('node:path');
const crypto = require('node:crypto');

function env(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

function intEnv(name, fallback) {
  const n = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(n) ? n : fallback;
}

const config = {
  appName: 'Sentinel SOC',
  version: '1.0.0',
  port: intEnv('PORT', 3000),
  host: env('HOST', '0.0.0.0'),
  env: env('NODE_ENV', 'development'),
  dataDir: path.resolve(__dirname, '..', env('DATA_DIR', 'data')),
  publicDir: path.resolve(__dirname, '..', 'public'),
  // Public base URL used to render absolute API links (custom domain support).
  publicBaseUrl: env('PUBLIC_BASE_URL', ''),
  // Authentication
  adminToken: env('ADMIN_TOKEN', 'sentinel-admin-token'),
  ingestTokens: env('INGEST_TOKENS', 'ingest-demo-token')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  // Ingest guardrails
  maxEventBytes: intEnv('MAX_EVENT_BYTES', 256 * 1024),
  ingestRatePerMin: intEnv('INGEST_RATE_PER_MIN', 600),
  clockSkewToleranceSec: intEnv('CLOCK_SKEW_TOLERANCE_SEC', 900),
  // Correlation
  incidentMergeWindowSec: intEnv('INCIDENT_MERGE_WINDOW_SEC', 3600),
  // Chain-of-custody anchor interval (events between anchors)
  anchorInterval: intEnv('CHAIN_ANCHOR_INTERVAL', 50),
  // Evaluator
  evalMinCoverage: Number(env('EVAL_MIN_COVERAGE', '0.85')),
  evalMinFaithfulness: Number(env('EVAL_MIN_FAITHFULNESS', '1.0')),
};

config.apiKeyForDisplay = crypto.createHash('sha256').update(config.adminToken).digest('hex').slice(0, 8);

module.exports = config;
