'use strict';

/**
 * API Key Management — admin-minted ingest credentials.
 *
 * Privacy & security properties:
 *  - Keys are stored ONLY as SHA-256 hashes (data/api-keys.json never
 *    contains a usable credential — a disk leak cannot mint ingest access).
 *  - The plaintext key is shown exactly once at creation; recovery is
 *    impossible by design (same model as GitHub/GitLab personal tokens).
 *  - Validation is timing-safe and honors env bootstrap INGEST_TOKENS so
 *    you can never lock yourself out.
 *  - `last_used` is updated in memory every use but persisted at most once
 *    per minute (avoids a disk write on every ingest request).
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const config = require('../config');
const logger = require('./logger');

const LAST_USED_FLUSH_MS = 60_000;

function hashKey(key) {
  return crypto.createHash('sha256').update(String(key)).digest('hex');
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) {
    crypto.timingSafeEqual(ab, ab); // uniform timing before failing
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

class ApiKeyStore {
  constructor() {
    this.filePath = path.join(config.dataDir, 'api-keys.json');
    this.keys = new Map(); // id -> record (record stores key_hash, never the key)
    this.dirtyLastUsed = false;
    this.lastUsedFlushedAt = 0;
    this.load();
  }

  load() {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const raw = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      for (const rec of raw.keys || []) this.keys.set(rec.id, rec);
      logger.info('api keys loaded', { count: this.keys.size });
    } catch (err) {
      logger.error('failed to load api keys', { error: String(err) });
    }
  }

  persist() {
    fs.mkdirSync(config.dataDir, { recursive: true });
    const tmp = this.filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ schema_version: 2, keys: [...this.keys.values()] }, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  create(name) {
    const id = `key_${crypto.randomBytes(4).toString('hex')}`;
    const key = `sk_ingest_${crypto.randomBytes(24).toString('hex')}`;
    // Show the plaintext key exactly once — store only its hash.
    const rec = {
      id,
      name: String(name || 'unnamed').slice(0, 60),
      key_hash: hashKey(key),
      preview: key.slice(0, 14) + '…',
      created_at: new Date().toISOString(),
      revoked: false,
      last_used: null,
    };
    this.keys.set(id, rec);
    this.persist();
    return { ...rec, key }; // include plaintext one-time
  }

  revoke(id) {
    const rec = this.keys.get(id);
    if (!rec) return null;
    rec.revoked = true;
    rec.revoked_at = new Date().toISOString();
    this.persist();
    return rec;
  }

  list() {
    return [...this.keys.values()].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
  }

  /** Validate an ingest token: env bootstrap tokens OR active managed keys. */
  validate(token) {
    if (config.ingestTokens.some((t) => safeEqual(t, token))) {
      return { ok: true, tokenId: 'bootstrap', managed: false };
    }
    const h = hashKey(token);
    for (const rec of this.keys.values()) {
      if (!rec.revoked && safeEqual(rec.key_hash, h)) {
        rec.last_used = new Date().toISOString();
        this.scheduleLastUsedFlush();
        return { ok: true, tokenId: rec.id, managed: true, name: rec.name };
      }
    }
    return { ok: false };
  }

  /** Persist last_used at most once per minute instead of on every request. */
  scheduleLastUsedFlush() {
    this.dirtyLastUsed = true;
    const due = Date.now() - this.lastUsedFlushedAt >= LAST_USED_FLUSH_MS;
    if (due) {
      this.flushLastUsed();
      return;
    }
    if (this._flushTimer) return;
    this._flushTimer = setTimeout(() => {
      this._flushTimer = null;
      this.flushLastUsed();
    }, LAST_USED_FLUSH_MS).unref();
  }

  flushLastUsed() {
    if (!this.dirtyLastUsed) return;
    this.dirtyLastUsed = false;
    this.lastUsedFlushedAt = Date.now();
    try {
      this.persist();
    } catch (err) {
      logger.error('failed to persist api key last_used', { error: String(err) });
    }
  }
}

module.exports = { ApiKeyStore };
