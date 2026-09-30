'use strict';

/**
 * Correlation Engine — multi-signal incident clustering.
 *
 * Groups registry evidence into incidents using explicit, deterministic
 * rules over shared entities (user, host, IP, domain, process hash) and
 * time proximity. Produces a unified, chronological incident timeline
 * where EVERY entry cites evidence IDs. If signals are sparse, the engine
 * reports coverage gaps instead of bridging them with assumptions.
 */

const config = require('../config');
const { randomId } = require('./util');
const { AssetMap } = require('./assets');

// Shared asset-map instance (operator-provided CMDB + IP intel).
const assetMap = new AssetMap();

// Entity extraction: which observable keys map to which entity types.
const ENTITY_KEYS = {
  user: 'user',
  principal: 'user', // cloud actor identity — same entity type as a user
  hostname: 'host',
  src_ip: 'ip',
  dst_ip: 'ip',
  process_hash: 'hash',
  dns_domain: 'domain',
  resource: 'resource',
  device_id: 'device',
};

function entitiesOf(event) {
  const out = new Set();
  for (const [key, type] of Object.entries(ENTITY_KEYS)) {
    const v = event[key];
    if (typeof v === 'string' && v.length > 0) {
      out.add(`${type}:${v.toLowerCase()}`);
    }
  }
  // Operator-declared aliases: link an IP to its known host/user.
  // These are EXPLICIT operator assertions, never inferred guesses.
  for (const ipKey of ['src_ip', 'dst_ip']) {
    if (typeof event[ipKey] === 'string') {
      for (const alias of assetMap.aliasesForIp(event[ipKey])) {
        out.add(alias);
      }
    }
  }
  return out;
}

function eventTime(ev) {
  return new Date(ev.event.occurred_at).getTime();
}

/**
 * Build incidents from all registry evidence. Deterministic:
 * same evidence set always produces same incidents.
 *
 * Algorithm: entity-centric graph clustering (union-find). Two events join
 * the same incident iff they share an entity AND occur within the merge
 * window of each other. This survives interleaved unrelated events that
 * would break a naive single-pass chain.
 */
function correlate(registry) {
  const records = registry.order.map((id) => registry.events.get(id));
  const sorted = [...records].sort((a, b) => eventTime(a) - eventTime(b));
  const n = sorted.length;

  const parent = new Array(n).fill(0).map((_, i) => i);
  const find = (x) => (parent[x] === x ? x : (parent[x] = find(parent[x])));
  const union = (a, b) => { parent[find(a)] = find(b); };

  const windowMs = config.incidentMergeWindowSec * 1000;
  const entitySets = sorted.map((rec) => entitiesOf(rec.event));

  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const dt = eventTime(sorted[j]) - eventTime(sorted[i]);
      if (dt > windowMs) break; // sorted by time: no later event can be within window of i
      if (find(i) === find(j)) continue;
      for (const e of entitySets[i]) {
        if (entitySets[j].has(e)) { union(i, j); break; }
      }
    }
  }

  // Collect components in chronological order.
  const components = new Map(); // root -> event_refs[]
  for (let i = 0; i < n; i++) {
    const root = find(i);
    if (!components.has(root)) components.set(root, []);
    components.get(root).push(sorted[i].event_id);
  }

  const incidents = [...components.values()].map((refs) => ({ incident_id: randomId('inc'), event_refs: refs }));

  // Enrich incidents with analysis metadata.
  const enriched = incidents.map((inc) => enrich(registry, inc));
  // Sort by severity signal then recency.
  enriched.sort((a, b) => (b.risk_score - a.risk_score) || (b.last_activity - a.last_activity));
  return enriched;
}

function enrich(registry, inc) {
  const events = inc.event_refs.map((id) => registry.events.get(id)).filter(Boolean);
  const domains = new Set();
  const entities = { users: new Set(), hosts: new Set(), ips: new Set(), hashes: new Set(), domains: new Set(), resources: new Set() };
  let maxSeverity = 0;
  let firstTs = Infinity;
  let lastTs = -Infinity;
  let adminActionCount = 0;
  let failureCount = 0;
  let exfilBytes = 0;
  let impossibleTravel = false;
  let newCountries = new Set();

  for (const rec of events) {
    const ev = rec.event;
    domains.add(ev.domain);
    if (ev.user) entities.users.add(ev.user);
    if (ev.hostname) entities.hosts.add(ev.hostname);
    if (ev.src_ip) entities.ips.add(ev.src_ip);
    if (ev.dst_ip) entities.ips.add(ev.dst_ip);
    if (ev.process_hash) entities.hashes.add(ev.process_hash);
    if (ev.dns_domain) entities.domains.add(ev.dns_domain);
    if (ev.resource) entities.resources.add(ev.resource);
    maxSeverity = Math.max(maxSeverity, ev.severity ?? 0);
    const t = new Date(ev.occurred_at).getTime();
    firstTs = Math.min(firstTs, t);
    lastTs = Math.max(lastTs, t);

    if (ev.action === 'login_failure') failureCount++;
    if (['policy_change', 'create', 'delete', 'assume_role'].includes(ev.action) && ev.domain === 'cloud') adminActionCount++;
    if (ev.domain === 'network' && ev.action === 'data_transfer') exfilBytes += ev.bytes_out || 0;
    if (ev.geo) newCountries.add(ev.geo);
  }

  // Impossible travel heuristic (explicit, explainable rule):
  // same user, successful logins from 2+ distinct countries within 1h.
  const logins = events.filter((e) => e.event.domain === 'identity' && e.event.action === 'login_success' && e.event.geo);
  const byUser = {};
  for (const l of logins) {
    const u = l.event.user;
    byUser[u] = byUser[u] || [];
    byUser[u].push(l);
  }
  for (const u of Object.keys(byUser)) {
    const list = byUser[u];
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        const dtH = Math.abs(new Date(list[i].event.occurred_at) - new Date(list[j].event.occurred_at)) / 3.6e6;
        if (list[i].event.geo !== list[j].event.geo && dtH <= 1) {
          impossibleTravel = true;
          newCountries.add(list[i].event.geo);
          newCountries.add(list[j].event.geo);
        }
      }
    }
  }

  // ---- Location enrichment (provenance-tracked, never guessed) ----
  const locations = new Map(); // country -> { count, ips: Set, provenance, detail }
  const unknownIps = new Set();
  for (const rec of events) {
    const ev = rec.event;
    for (const ip of [ev.src_ip, ev.dst_ip]) {
      if (!ip) continue;
      const external = assetMap.isExternalIp(ip);
      if (!external) continue;
      const loc = assetMap.locateIp(ip);
      if (loc.country) {
        const entry = locations.get(loc.country) || { count: 0, ips: new Set(), provenance: loc.provenance, detail: loc.detail };
        entry.count += 1;
        entry.ips.add(ip);
        locations.set(loc.country, entry);
      } else if (!locations.has(ip)) {
        unknownIps.add(ip);
      }
    }
    // Identity geo comes straight from the IdP log (provider_geo provenance).
    if (ev.geo && ev.domain === 'identity') {
      const entry = locations.get(ev.geo) || { count: 0, ips: new Set(), provenance: 'provider_geo', detail: `IdP-asserted geo for ${ev.user}` };
      entry.count += 1;
      if (ev.src_ip) entry.ips.add(ev.src_ip);
      locations.set(ev.geo, entry);
    }
  }
  const location_intel = {
    countries: [...locations.entries()].map(([country, info]) => ({
      country,
      event_count: info.count,
      ips: [...info.ips],
      provenance: info.provenance,
      detail: info.detail,
    })),
    unlocated_ips: [...unknownIps],
    note: unknownIps.length
      ? `${unknownIps.size} external IP(s) have NO location evidence — listed as unlocated rather than guessed.`
      : 'All external IPs carry location evidence with recorded provenance.',
  };

  // Transparent risk scoring — every factor is inspectable.
  const factors = [];
  let risk = 0;
  if (domains.size >= 3) { risk += 25; factors.push({ rule: 'multi_domain_correlation', weight: 25, detail: `${domains.size} domains correlated` }); }
  else if (domains.size === 2) { risk += 12; factors.push({ rule: 'dual_domain_correlation', weight: 12, detail: `${domains.size} domains correlated` }); }
  if (impossibleTravel) { risk += 25; factors.push({ rule: 'impossible_travel', weight: 25, detail: 'same user, distinct countries <1h apart' }); }
  if (failureCount >= 3) { risk += 10; factors.push({ rule: 'credential_stuffing_pattern', weight: 10, detail: `${failureCount} login failures` }); }
  if (adminActionCount > 0) { risk += 15; factors.push({ rule: 'cloud_admin_activity', weight: 15, detail: `${adminActionCount} privileged cloud actions` }); }
  if (exfilBytes > 500e6) { risk += 20; factors.push({ rule: 'bulk_egress', weight: 20, detail: `${(exfilBytes / 1e6).toFixed(0)} MB egress` }); }
  if (maxSeverity >= 8) { risk += 10; factors.push({ rule: 'high_severity_signal', weight: 10, detail: `max sensor severity ${maxSeverity}/10` }); }
  // Threat-location factor: incident reaches a country carrying known-bad intel tags.
  const badGeo = [...locations.entries()].filter(([country, info]) =>
    info.provenance === 'operator_intel'
    && (assetMap.ipIntel[[...info.ips][0]]?.tags || []).some((t) => ['known_bad', 'tor_exit', 'c2_history', 'malware_distribution', 'state_linked'].includes(t))
  );
  if (badGeo.length) {
    risk += 15;
    factors.push({ rule: 'threat_origin_location', weight: 15, detail: `evidence touches ${badGeo.map(([c]) => c).join(', ')} — IPs tagged known_bad/tor/c2 in operator intel` });
  }
  risk = Math.min(100, risk);

  // Coverage: how many of the four domains are represented? Explicit gap flagging.
  const ALL = ['endpoint', 'identity', 'cloud', 'network'];
  const missingDomains = ALL.filter((d) => !domains.has(d));

  return {
    incident_id: inc.incident_id,
    event_refs: inc.event_refs,
    event_count: inc.event_refs.length,
    first_activity: new Date(firstTs).toISOString(),
    last_activity: new Date(lastTs).toISOString(),
    duration_sec: Math.round((lastTs - firstTs) / 1000),
    domains: [...domains],
    missing_domains: missingDomains,
    entities: {
      users: [...entities.users],
      hosts: [...entities.hosts],
      ips: [...entities.ips],
      hashes: [...entities.hashes],
      domains: [...entities.domains],
      resources: [...entities.resources],
    },
    signals: {
      login_failures: failureCount,
      admin_actions: adminActionCount,
      egress_bytes: exfilBytes,
      impossible_travel: impossibleTravel,
      max_severity: maxSeverity,
    },
    location_intel,
    risk_score: risk,
    risk_factors: factors,
    // The report generator (not this module) fills these next fields.
    gap_flags: missingDomains.map((d) => ({
      type: 'missing_domain',
      detail: `No ${d} telemetry in this incident — conclusions involving ${d} are UNSUPPORTED by evidence.`,
    })),
  };
}

module.exports = { correlate, assetMap };
