'use strict';

/**
 * Ingestion & Normalization — multi-domain telemetry.
 *
 * Accepts raw events from four domains and maps them onto one canonical
 * schema. Strict validation: anything missing a required field, outside a
 * plausible time window, or failing integrity checks is REJECTED with an
 * explicit reason (never silently "fixed" — that would be inventing data).
 *
 * Domains: endpoint (EDR), identity (IdP), cloud, network
 */

const config = require('../config');
const { sha256Hex, canonicalJson, randomId } = require('./util');

const DOMAINS = ['endpoint', 'identity', 'cloud', 'network'];

// Per-domain required fields on the RAW input.
const REQUIRED = {
  endpoint: ['hostname', 'process_name'],
  identity: ['user', 'action'],
  cloud: ['provider', 'resource', 'action'],
  network: ['src_ip', 'dst_ip'],
};

const ACTIONS = new Set([
  'allow', 'deny', 'login_success', 'login_failure', 'logout',
  'process_start', 'file_write', 'file_delete', 'registry_write',
  'create', 'update', 'delete', 'assume_role', 'policy_change',
  'dns_query', 'connection', 'tls_handshake', 'data_transfer',
]);

function toIsoOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function str(v) {
  return typeof v === 'string' ? v.trim() : null;
}

function ipLike(v) {
  const s = str(v);
  return s && /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]{2,45}$/.test(s) ? s : null;
}

/**
 * Validate + normalize one raw event. Returns { ok, event?, reason? }.
 * Never mutates the input to "make it fit".
 */
function normalizeEvent(raw, ingestMeta) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, reason: 'payload must be a JSON object' };
  }
  const domain = str(raw.domain)?.toLowerCase();
  if (!domain || !DOMAINS.includes(domain)) {
    return { ok: false, reason: `unknown domain "${domain}" (expected one of: ${DOMAINS.join(', ')})` };
  }
  const missing = REQUIRED[domain].filter((f) => raw[f] === undefined || raw[f] === null || raw[f] === '');
  if (missing.length) {
    return { ok: false, reason: `missing required field(s) for domain "${domain}": ${missing.join(', ')}` };
  }

  const occurredAt = toIsoOrNull(raw.timestamp ?? raw.time ?? raw.ts);
  if (!occurredAt) {
    return { ok: false, reason: 'missing or unparseable timestamp' };
  }
  const skewSec = Math.abs((Date.now() - new Date(occurredAt).getTime()) / 1000);
  const maxSkew = config.clockSkewToleranceSec * 24 * 30; // allow historical backfill up to ~30d
  if (skewSec > maxSkew) {
    return { ok: false, reason: `timestamp ${occurredAt} too far from current time (>30d)` };
  }

  const action = str(raw.action)?.toLowerCase() ?? null;
  if (action && !ACTIONS.has(action)) {
    // Unknown action is kept but flagged — we do not silently map it.
    return {
      ok: false,
      reason: `unknown action "${action}" — extend the schema or fix the emitter; refusing to guess`,
    };
  }

  const base = {
    event_id: str(raw.event_id) || null, // assigned at commit if absent
    schema_version: 1,
    domain,
    action: action || 'unknown',
    occurred_at: occurredAt,
    source_tool: str(raw.source_tool) || str(raw.sensor) || 'unspecified',
    severity: clampSeverity(raw.severity),
    confidence: clampConfidence(raw.confidence),
  };

  let event;
  switch (domain) {
    case 'endpoint': {
      event = {
        ...base,
        hostname: str(raw.hostname),
        user: str(raw.user) || null,
        process_name: str(raw.process_name),
        process_hash: str(raw.process_hash) || str(raw.file_hash) || null,
        pid: Number.isFinite(raw.pid) ? raw.pid : null,
        parent_process: str(raw.parent_process) || null,
        cmdline: str(raw.cmdline) || null,
      };
      break;
    }
    case 'identity': {
      const ip = ipLike(raw.src_ip ?? raw.ip);
      event = {
        ...base,
        user: str(raw.user),
        action: action || 'login_success',
        src_ip: ip,
        user_agent: str(raw.user_agent) || null,
        mfa_used: typeof raw.mfa_used === 'boolean' ? raw.mfa_used : null,
        geo: str(raw.geo) || str(raw.country) || null,
        device_id: str(raw.device_id) || null,
      };
      break;
    }
    case 'cloud': {
      event = {
        ...base,
        provider: str(raw.provider).toLowerCase(),
        account_id: str(raw.account_id) || null,
        resource: str(raw.resource),
        action: action || 'update',
        principal: str(raw.principal) || str(raw.user) || null,
        src_ip: ipLike(raw.src_ip ?? raw.caller_ip),
        region: str(raw.region) || null,
      };
      break;
    }
    case 'network': {
      const src = ipLike(raw.src_ip);
      const dst = ipLike(raw.dst_ip);
      if (!src || !dst) return { ok: false, reason: 'network event requires valid src_ip and dst_ip' };
      event = {
        ...base,
        action: action || 'connection',
        src_ip: src,
        dst_ip: dst,
        src_port: Number.isFinite(raw.src_port) ? raw.src_port : null,
        dst_port: Number.isFinite(raw.dst_port) ? raw.dst_port : null,
        protocol: str(raw.protocol)?.toLowerCase() || null,
        bytes_out: Number.isFinite(raw.bytes_out) ? raw.bytes_out : null,
        bytes_in: Number.isFinite(raw.bytes_in) ? raw.bytes_in : null,
        dns_domain: str(raw.dns_domain ?? raw.query)?.replace(/^\.+|\.+$/g, '') || null,
        host: str(raw.host) || null,
      };
      break;
    }
    default:
      return { ok: false, reason: 'unhandled domain' };
  }

  // Dedup key: emitter-supplied event_id, else content fingerprint.
  const fingerprint = sha256Hex(canonicalJson({ domain: event.domain, occurred_at: event.occurred_at, payload: stripVolatile(event) })).slice(0, 24);
  const ingest = {
    channel: ingestMeta.channel,
    source_ip: ingestMeta.source_ip,
    token_id: ingestMeta.token_id,
    received_at: ingestMeta.received_at,
    raw_sha256: sha256Hex(canonicalJson(raw)).slice(0, 32),
  };

  return { ok: true, event, fingerprint, ingest };
}

function stripVolatile(ev) {
  const { event_id, ...rest } = ev;
  void event_id;
  return rest;
}

function clampSeverity(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 3;
  return Math.min(10, Math.max(1, Math.round(n)));
}

function clampConfidence(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0.5;
  return Math.min(1, Math.max(0, n));
}

module.exports = { normalizeEvent, DOMAINS, REQUIRED };
