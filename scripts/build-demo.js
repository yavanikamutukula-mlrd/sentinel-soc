'use strict';

/**
 * Build the static demo snapshot (public/demo-data.json).
 *
 * The GitHub Pages deployment serves the dashboard with NO backend, so this
 * snapshot gives every visitor a fully browsable site (incidents, reports,
 * locations, graphs, integrity, evaluation) generated from the same seed
 * stories the live API uses. The Pages workflow runs this before upload;
 * locally: `npm run build:demo`.
 */

const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

// Isolate the throwaway registry from the operator's data dir BEFORE
// requiring config (config reads DATA_DIR at require time). Asset intel
// falls back to the bundled data/ files, so location tracking still works.
const tmpData = fs.mkdtempSync(path.join(os.tmpdir(), 'cerberus-demo-'));
process.env.DATA_DIR = tmpData;

const config = require('../src/config');
const { EvidenceRegistry } = require('../src/lib/evidence-registry');
const { seedRegistry } = require('./seed-lib');
const { correlate } = require('../src/lib/correlate');
const { generateAll } = require('../src/lib/report');
const { aggregateLocations } = require('../src/lib/locations');
const { runAll } = require('../src/lib/eval');

const registry = new EvidenceRegistry();
const seeded = seedRegistry(registry);
const incidents = correlate(registry);
const gen = generateAll(registry);
if (!gen.ok) {
  console.error('demo build failed: integrity preflight error', JSON.stringify(gen));
  process.exit(1);
}

const snapshot = {
  schema_version: 1,
  generated_at: new Date().toISOString(),
  app: { name: config.appName, version: config.version },
  seed: seeded,
  stats: registry.stats(),
  integrity: registry.verifyChain(),
  adversarial: gen.adversarial,
  incidents,
  reports: gen.reports,
  locations: aggregateLocations(incidents),
  eval: runAll(),
  events: registry.order.map((id) => registry.events.get(id)),
};

const out = path.resolve(__dirname, '..', 'public', 'demo-data.json');
fs.writeFileSync(out, JSON.stringify(snapshot));
console.log(`demo snapshot written: ${out}`);
console.log(
  `  events=${snapshot.stats.total_events} incidents=${snapshot.incidents.length}` +
  ` reports=${snapshot.reports.length} countries=${snapshot.locations.countries.length}`,
);
