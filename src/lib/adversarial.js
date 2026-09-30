'use strict';

/**
 * Adversarial Defense Module.
 *
 * Assumes the attacker controls compromised hosts and may inject forged
 * telemetry. Checks are deterministic and every finding cites the evidence
 * IDs it inspected, so analysts can audit the detector itself.
 *
 * Defenses:
 *  - Replay detection: duplicate fingerprints / event_ids with new metadata
 *  - Tamper detection: hash-chain verification over the whole registry
 *  - Source trust scoring: per-token/channel behavioral baselines
 *  - Injection pattern detection: prompt-injection payloads inside log fields
 *  - Impossible/contradictory telemetry: geos + clock skew + field sanity
 */

const { sha256Hex, canonicalJson } = require('./util');

const INJECTION_PATTERNS = [
  { re: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)/i, name: 'instruction_override' },
  { re: /you\s+are\s+now\s+(an?\s+)?(admin|root|assistant)/i, name: 'role_hijack' },
  { re: /disregard\s+(all\s+)?safety/i, name: 'safety_override' },
  { re: /\b(system|assistant)\s*:/i, name: 'chat_role_spoof' },
  { re: /\<\/?(system|assistant|tool)_?prompt\>/i, name: 'fake_markup' },
  { re: /\b(creator|developer)\s+(message|instruction)\s*:/i, name: 'authority_claim' },
  { re: /\breport\s+(that|this)\s+(incident|alert)\s+as\s+(benign|false\s+positive)/i, name: 'verdict_manipulation' },
  { re: /\bmark\s+(as|this)\s+(resolved|closed|benign)\b/i, name: 'state_manipulation' },
];

const SUSPICIOUS_TLDS = /\.(zip|mov|top|xyz|gq|tk|cf|ml|work|click|country|stream|gdn|mom|xin|kim|men|rest|cyou|sbs)$/i;
const ALL_DIGITS_IP = /^\d{5,}(\.\d{5,}){0,3}$/; // decimal-encoded IPs

function scanFields(obj, path, findings, eventId) {
  if (findings.length >= 50) return; // bounded work per event
  if (obj === null || obj === undefined) return;
  if (typeof obj === 'string') {
    for (const p of INJECTION_PATTERNS) {
      if (p.re.test(obj)) {
        findings.push({
          type: 'prompt_injection',
          severity: 'high',
          evidence_id: eventId,
          field: path,
          pattern: p.name,
          note: 'Log field contains text resembling LLM prompt-injection. Content quarantined from AI context.',
        });
      }
    }
    if (SUSPICIOUS_TLDS.test(obj)) {
      findings.push({
        type: 'suspicious_indicator',
        severity: 'medium',
        evidence_id: eventId,
        field: path,
        pattern: 'high_abuse_tld',
        note: 'Reference to a TLD with heavy abuse history — treat as untrusted indicator.',
      });
    }
    if (ALL_DIGITS_IP.test(obj)) {
      findings.push({
        type: 'suspicious_indicator',
        severity: 'medium',
        evidence_id: eventId,
        field: path,
        pattern: 'decimal_encoded_ip',
        note: 'Integer-style IP encoding often used to evade naive parsers.',
      });
    }
    // Control characters / homoglyph obfuscation in log fields
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u0008\u000e-\u001f\u202a-\u202e\u2066-\u2069]/.test(obj)) {
      findings.push({
        type: 'obfuscation',
        severity: 'high',
        evidence_id: eventId,
        field: path,
        pattern: 'control_or_bidi_chars',
        note: 'Control or bidi-override characters detected — likely log-forging or text-direction obfuscation.',
      });
    }
    return;
  }
  if (typeof obj === 'number' || typeof obj === 'boolean') return;
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => scanFields(v, `${path}[${i}]`, findings, eventId));
    return;
  }
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) scanFields(v, path ? `${path}.${k}` : k, findings, eventId);
  }
}

function assessEvent(record, ctx) {
  const findings = [];
  const ev = record.event;
  const eventId = record.event_id;

  // 1. Prompt-injection & obfuscation scan of every field.
  scanFields(ev, 'event', findings, eventId);

  // 2. Replay detection: same core observables seen again from a different
  //    source. Fingerprint EXCLUDES attacker-controlled framing fields
  //    (source_tool, severity, confidence) so a forged copy that renames its
  //    emitter still matches the original.
  const fp = replayFingerprint(ev);
  const seen = ctx.fingerprints.get(fp);
  if (seen && (seen.ingest_token !== record.ingest.token_id || seen.source_tool !== ev.source_tool)) {
    const why = seen.ingest_token !== record.ingest.token_id
      ? `token "${seen.ingest_token}" → "${record.ingest.token_id}"`
      : `source_tool "${seen.source_tool}" → "${ev.source_tool}"`;
    findings.push({
      type: 'replay',
      severity: 'high',
      evidence_id: eventId,
      field: 'event',
      pattern: 'cross_source_duplicate',
      note: `Identical core observables previously recorded (${why}). Possible replay/spoofed emitter.`,
      related_evidence_id: seen.event_id,
    });
  }
  if (!seen) ctx.fingerprints.set(fp, { event_id: eventId, ingest_token: record.ingest.token_id, source_tool: ev.source_tool });

  // 3. Future-dated telemetry: clock skew beyond tolerance is a classic
  //    log-injection / forensics-evasion trick.
  const skewSec = (new Date(ev.occurred_at).getTime() - Date.now()) / 1000;
  if (skewSec > 0) {
    findings.push({
      type: 'clock_anomaly',
      severity: skewSec > 3600 ? 'high' : 'medium',
      evidence_id: eventId,
      field: 'event.occurred_at',
      pattern: 'future_timestamp',
      note: `Event timestamp is ${Math.round(skewSec)}s in the future. Source clock untrusted — do not rely on ordering from this source alone.`,
    });
  }

  // 4. Contradictory identity telemetry: same user, simultaneous logins
  //    from distant geos is captured by correlation; here we catch the
  //    same device claiming two IPs within seconds (session spoofing).
  const devKey = ev.device_id || null;
  if (devKey) {
    const prior = ctx.devices.get(devKey);
    if (prior && prior.src_ip && ev.src_ip && prior.src_ip !== ev.src_ip) {
      const dt = Math.abs(new Date(ev.occurred_at) - new Date(prior.occurred_at)) / 1000;
      if (dt < 30) {
        findings.push({
          type: 'session_anomaly',
          severity: 'medium',
          evidence_id: eventId,
          field: 'event.src_ip',
          pattern: 'device_ip_flip',
          note: `Device ${devKey} flipped IP ${prior.src_ip} → ${ev.src_ip} within ${Math.round(dt)}s.`,
          related_evidence_id: prior.event_id,
        });
      }
    }
    ctx.devices.set(devKey, { src_ip: ev.src_ip, occurred_at: ev.occurred_at, event_id: eventId });
  }

  // 5. Endpoint events without a host/user attribution from an unverified
  //    channel are downgrade-flagged, never dropped (dropping = hiding).
  if (ev.domain === 'endpoint' && !ev.user) {
    findings.push({
      type: 'attribution_gap',
      severity: 'low',
      evidence_id: eventId,
      field: 'event.user',
      pattern: 'unattributed_process',
      note: 'Endpoint event lacks user attribution; process context unverified.',
    });
  }

  return findings;
}

/**
 * Fingerprint over the immutable core of an event (who/what/where/when).
 * Deliberately excludes framing fields an attacker could vary when forging
 * a copy: source_tool, severity, confidence, user_agent.
 */
function replayFingerprint(ev) {
  const core = {
    domain: ev.domain,
    action: ev.action,
    occurred_at: ev.occurred_at,
    user: ev.user ?? null,
    hostname: ev.hostname ?? null,
    src_ip: ev.src_ip ?? null,
    dst_ip: ev.dst_ip ?? null,
    dst_port: ev.dst_port ?? null,
    resource: ev.resource ?? null,
    principal: ev.principal ?? null,
    process_hash: ev.process_hash ?? null,
    dns_domain: ev.dns_domain ?? null,
  };
  return sha256Hex(canonicalJson(core)).slice(0, 24);
}

/**
 * Full sweep: verify chain integrity + rescan recent events.
 * Returns findings sorted by severity.
 */
function sweep(registry) {
  const ctx = { fingerprints: new Map(), devices: new Map() };
  const findings = [];
  for (const id of registry.order) {
    const rec = registry.events.get(id);
    if (!rec) continue;
    findings.push(...assessEvent(rec, ctx));
  }
  const chain = registry.verifyChain();
  const sevRank = { high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => (sevRank[b.severity] ?? 0) - (sevRank[a.severity] ?? 0));

  return {
    chain_integrity: chain,
    finding_count: findings.length,
    by_type: findings.reduce((acc, f) => ((acc[f.type] = (acc[f.type] || 0) + 1), acc), {}),
    findings,
    verdict: !chain.ok
      ? 'REGISTRY INTEGRITY FAILURE — treat all derived reports as unreliable until investigated.'
      : findings.some((f) => f.severity === 'high')
        ? 'High-severity adversarial indicators present. Evidence retained but flagged; reports citing flagged evidence carry explicit warnings.'
        : 'No adversarial indicators detected. Chain verified.',
  };
}

module.exports = { sweep, assessEvent, INJECTION_PATTERNS };
