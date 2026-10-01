'use strict';

/**
 * Location Aggregation — country-level rollup across all incidents.
 *
 * Every country carries explicit provenance ('operator_intel' or
 * 'provider_geo'). IPs with no location evidence are reported as
 * unlocated — never guessed onto a map or into a report.
 */

const { assetMap } = require('./correlate');

function aggregateLocations(incidents) {
  const byCountry = new Map(); // country -> { incidents, events, ips:Set, provenance, risk_max, tags:Set }
  const unlocated = new Set();
  for (const inc of incidents) {
    const li = inc.location_intel || { countries: [], unlocated_ips: [] };
    for (const c of li.countries) {
      const rec = byCountry.get(c.country) || {
        country: c.country,
        incidents: 0,
        events: 0,
        ips: new Set(),
        provenance: c.provenance,
        risk_max: 0,
        tags: new Set(),
      };
      rec.incidents += 1;
      rec.events += c.event_count;
      for (const ip of c.ips) rec.ips.add(ip);
      rec.risk_max = Math.max(rec.risk_max, inc.risk_score);
      for (const ip of c.ips) {
        const intel = assetMap.ipIntel[ip];
        if (intel?.tags) for (const t of intel.tags) rec.tags.add(t);
      }
      byCountry.set(c.country, rec);
    }
    for (const ip of li.unlocated_ips) unlocated.add(ip);
  }
  return {
    countries: [...byCountry.values()]
      .map((c) => ({ ...c, ips: [...c.ips], tags: [...c.tags] }))
      .sort((a, b) => b.risk_max - a.risk_max || b.events - a.events),
    unlocated_ips: [...unlocated],
    note: unlocated.size
      ? `${unlocated.size} external IP(s) unlocated — not guessed.`
      : 'All external IPs located with provenance.',
  };
}

module.exports = { aggregateLocations };
