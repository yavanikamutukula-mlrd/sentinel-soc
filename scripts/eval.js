'use strict';

const { runAll } = require('../src/lib/eval');

const result = runAll();
console.log('\n=== Cerberus Evaluation ===');
console.log(`Scenarios: ${result.scenarios_passed}/${result.scenarios_total} passed`);
console.log(`Claims verified: ${result.aggregate.claims_total}, fabrication rate: ${result.aggregate.fabrication_rate}`);
for (const r of result.results) {
  const flag = r.passed ? 'PASS' : 'FAIL';
  console.log(`\n[${flag}] ${r.scenario}`);
  for (const c of r.checks) {
    console.log(`  ${c.passed ? '✓' : '✗'} ${c.name}: ${c.detail}`);
  }
}
console.log(result.all_passed ? '\nALL SCENARIOS PASSED — fabrication rate 0' : '\nEVALUATION FAILED');
process.exit(result.all_passed ? 0 : 1);
