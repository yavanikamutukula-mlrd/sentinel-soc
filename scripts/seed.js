'use strict';

const fs = require('node:fs');
const config = require('../src/config');
const { EvidenceRegistry } = require('../src/lib/evidence-registry');
const { seedRegistry } = require('./seed-lib');

function main() {
  fs.mkdirSync(config.dataDir, { recursive: true });
  const registry = new EvidenceRegistry();
  const { accepted, rejected } = seedRegistry(registry);
  registry.persist();
  const chain = registry.verifyChain();
  console.log(`Seeded ${accepted} events (rejected ${rejected}). Chain OK: ${chain.ok}. Restart the server to load them.`);
  if (!chain.ok) process.exit(1);
}

main();
