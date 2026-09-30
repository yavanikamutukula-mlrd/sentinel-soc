'use strict';

/**
 * API Key Management — admin-minted ingest credentials.
 *
 * Keys live in data/api-keys.json (survives restarts alongside evidence).
 * Each key: { id, name, key, created_at, revoked } — revoked keys fail
 * auth but stay listed for audit. The env INGEST_TOKENS remain valid
 * bootstrap keys so you can never lock yourself out.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const config = require('../config');
const logger = require('./logger');

class ApiKeyStore {
  constructor() {
    this.filePath = path.join(config.dataDir, 'api-keys.json');
    this.keys = new Map(); // id -> record
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
    fs.writeFileSync(tmp, JSON.stringify({ schema_version: 1, keys: [...this.keys.values()] }, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  create(name) {
    const id = `key_${crypto.randomBytes(4).toString('hex')}`;
    const key = `sk_ingest_${crypto.randomBytes(24).toString('hex')}`;
    const rec = { id, name: String(name || 'unnamed').slice(0, 60), key, created_at: new Date().toISOString(), revoked: false, last_used: null };
    this.keys.set(id, rec);
    this.persist();
    return rec;
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
    if (config.ingestTokens.includes(token)) return { ok: true, tokenId: 'bootstrap', managed: false };
    for (const rec of this.keys.values()) {
      if (rec.key === token && !rec.revoked) {
        rec.last_used = new Date().toISOString();
        this.persist();
        return { ok: true, tokenId: rec.id, managed: true, name: rec.name };
      }
    }
    return { ok: false };
  }
}

module.exports = { ApiKeyStore };
