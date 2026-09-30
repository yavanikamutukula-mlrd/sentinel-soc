'use strict';

/**
 * Evidence Registry — the anti-hallucination core.
 *
 * Every event accepted into the system is:
 *  1. Normalized to a canonical schema,
 *  2. Assigned a content hash (SHA-256 over canonical JSON),
 *  3. Chained into a hash chain (prevHash = hash of prior accepted event),
 *  4. Persisted with the chain state so tampering is detectable.
 *
 * Nothing that failed normalization/validation ever enters the registry,
 * so downstream correlation/reporting can only ever cite events that
 * provably exist here. Reports must reference evidence IDs — the report
 * generator refuses to emit a claim that has no backing evidence ID.
 */

const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');
const logger = require('./logger');
const { sha256Hex, canonicalJson, randomId } = require('./util');

const SEED_HASH = sha256Hex('sentinel-soc:genesis');

class EvidenceRegistry {
  constructor() {
    this.events = new Map(); // eventId -> event record
    this.order = []; // insertion order of eventIds
    this.lastHash = SEED_HASH;
    this.chainedCount = 0;
    this.rejected = []; // audit trail of rejected payloads
    this.loadFromDisk();
  }

  get filePath() {
    return path.join(config.dataDir, 'evidence.json');
  }

  loadFromDisk() {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const raw = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      for (const ev of raw.events || []) {
        this.events.set(ev.event_id, ev);
        this.order.push(ev.event_id);
      }
      this.lastHash = raw.chain_state?.last_hash || SEED_HASH;
      this.chainedCount = raw.chain_state?.chained_count || 0;
      logger.info('evidence registry loaded from disk', { events: this.order.length });
    } catch (err) {
      logger.error('failed to load evidence registry', { error: String(err) });
    }
  }

  persist() {
    fs.mkdirSync(config.dataDir, { recursive: true });
    const snapshot = {
      schema_version: 1,
      chain_state: { last_hash: this.lastHash, chained_count: this.chainedCount },
      events: this.order.map((id) => this.events.get(id)),
    };
    const tmp = this.filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(snapshot));
    fs.renameSync(tmp, this.filePath);
  }

  /**
   * Compute the full record for an already-normalized event.
   * Content hash covers the normalized payload + ingest context,
   * NOT anything an AI downstream might have "imagined".
   */
  buildRecord(normalized, ingestMeta) {
    const eventId = normalized.event_id || randomId('evt');
    const content = canonicalJson({ event: normalized, ingest: ingestMeta });
    const record = {
      event_id: eventId,
      received_at: new Date().toISOString(),
      ingest: ingestMeta,
      event: normalized,
      content_hash: sha256Hex(content),
      prev_hash: this.lastHash,
      hash: null, // filled in on commit
    };
    record.hash = sha256Hex(record.prev_hash + record.content_hash);
    return record;
  }

  /**
   * Append a validated record to the chain. Returns the stored record.
   */
  commit(record) {
    if (this.events.has(record.event_id)) {
      // Replay of the same event: idempotent, return existing.
      return { record: this.events.get(record.event_id), replay: true };
    }
    this.events.set(record.event_id, record);
    this.order.push(record.event_id);
    this.lastHash = record.hash;
    this.chainedCount += 1;
    if (this.chainedCount % config.anchorInterval === 0) {
      this.persist();
    }
    return { record, replay: false };
  }

  reject(payload, reason) {
    const entry = { at: new Date().toISOString(), reason, payload_sha: sha256Hex(canonicalJson(payload ?? null)) };
    this.rejected.push(entry);
    if (this.rejected.length > 1000) this.rejected.shift();
    logger.warn('event rejected', { reason });
    return entry;
  }

  get(eventId) {
    return this.events.get(eventId) || null;
  }

  has(eventId) {
    return this.events.has(eventId);
  }

  /**
   * Verify the hash chain end-to-end. Detects any tampering, deletion,
   * or reordering of persisted evidence.
   */
  verifyChain() {
    let expectedPrev = SEED_HASH;
    let verified = 0;
    for (const id of this.order) {
      const ev = this.events.get(id);
      if (!ev) {
        return { ok: false, verified, broken_at: id, reason: 'missing record in order index' };
      }
      if (ev.prev_hash !== expectedPrev) {
        return { ok: false, verified, broken_at: id, reason: 'prev_hash mismatch (deletion or reorder detected)' };
      }
      const content = canonicalJson({ event: ev.event, ingest: ev.ingest });
      if (sha256Hex(content) !== ev.content_hash) {
        return { ok: false, verified, broken_at: id, reason: 'content hash mismatch (payload tampered)' };
      }
      if (sha256Hex(ev.prev_hash + ev.content_hash) !== ev.hash) {
        return { ok: false, verified, broken_at: id, reason: 'chain hash mismatch' };
      }
      expectedPrev = ev.hash;
      verified += 1;
    }
    const anchored = this.lastHash === expectedPrev;
    return {
      ok: anchored && verified === this.order.length,
      verified,
      total: this.order.length,
      head_hash: expectedPrev,
      anchored_head: this.lastHash,
      reason: anchored ? null : 'registry head does not match last verified record',
    };
  }

  stats() {
    const byDomain = {};
    for (const ev of this.events.values()) {
      const d = ev.event.domain || 'unknown';
      byDomain[d] = (byDomain[d] || 0) + 1;
    }
    return {
      total_events: this.order.length,
      by_domain: byDomain,
      chain_head: this.lastHash,
      chained_count: this.chainedCount,
      rejected_recent: this.rejected.slice(-10),
    };
  }
}

module.exports = { EvidenceRegistry, SEED_HASH };
