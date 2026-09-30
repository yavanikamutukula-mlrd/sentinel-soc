'use strict';

const crypto = require('node:crypto');

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj) ?? 'null';
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',') + '}';
}

function randomId(prefix, bytes = 8) {
  return `${prefix}_${crypto.randomBytes(bytes).toString('hex')}`;
}

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

module.exports = { sha256Hex, canonicalJson, randomId, clamp };
