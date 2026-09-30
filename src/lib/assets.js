'use strict';

/**
 * Asset Map & IP Intel — operator-provided context (a mini CMDB).
 *
 * Strict correlators face a real problem: network flows carry only IPs,
 * while endpoint/identity events carry users/hosts. Bridging them by
 * GUESSING would be inventing evidence. Instead, operators supply an
 * explicit, auditable inventory. Every link made through this file is
 * flagged in reports as "asset_map" provenance so analysts can review it.
 *
 * Location data follows the same rule: a geo/country is only ever attached
 * with provenance — 'provider_geo' (the IdP/cloud log stated it) or
 * 'operator_intel' (the operator's threat-intel table states it). IPs with
 * no geo evidence are reported as UNKNOWN, never guessed.
 *
 * Files (both optional):
 *   data/assets.json   { "10.4.1.44": { host: "FINWS-4411", user: "j.doe", owner: "finance" }, ... }
 *   data/ip-intel.json { "185.220.101.7": { country: "RU", asn: "AS205100 F3 Netze (TOR exit)", tags: ["tor","known_bad"] }, ... }
 */

const fs = require('node:fs');
const path = require('node:path');
const config = require('../config');
const logger = require('./logger');

function loadJson(fileName) {
  const p = path.join(config.dataDir, fileName);
  try {
    if (!fs.existsSync(p)) return {};
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      logger.warn('asset file has invalid shape, ignoring', { file: p });
      return {};
    }
    return parsed;
  } catch (err) {
    logger.error('failed to parse asset file', { file: p, error: String(err) });
    return {};
  }
}

class AssetMap {
  constructor() {
    this.assets = loadJson('assets.json');
    this.ipIntel = loadJson('ip-intel.json');
    const a = Object.keys(this.assets).length;
    const i = Object.keys(this.ipIntel).length;
    if (a || i) logger.info('asset map loaded', { assets: a, ip_intel_entries: i });
  }

  /** Aliases for an IP (host/user identities it belongs to). */
  aliasesForIp(ip) {
    const rec = this.assets[ip];
    if (!rec) return [];
    const out = [];
    if (rec.host) out.push(`host:${String(rec.host).toLowerCase()}`);
    if (rec.user) out.push(`user:${String(rec.user).toLowerCase()}`);
    if (rec.device) out.push(`device:${String(rec.device).toLowerCase()}`);
    return out;
  }

  /**
   * Location for an IP with explicit provenance.
   * Returns { country, provenance, detail } or { country: null, provenance: 'unknown' }.
   */
  locateIp(ip) {
    const intel = this.ipIntel[ip];
    if (intel && intel.country) {
      return {
        country: intel.country,
        provenance: 'operator_intel',
        detail: intel.asn || intel.tags?.join(', ') || 'operator threat-intel table',
      };
    }
    return { country: null, provenance: 'unknown', detail: 'no geo evidence for this IP — location NOT asserted' };
  }

  isExternalIp(ip) {
    if (!ip) return false;
    if (this.assets[ip]) return false; // belongs to us
    return /^(?!10\.)(?!192\.168\.)(?!172\.(1[6-9]|2\d|3[01])\.)(?!127\.)(?!169\.254\.)/.test(ip);
  }
}

module.exports = { AssetMap };
