'use strict';

/**
 * Evaluation Framework — measurable trust in the pipeline.
 *
 * Runs golden scenarios through the REAL pipeline (registry → ingest →
 * correlate → adversarial sweep → report) in an isolated in-memory registry,
 * then measures:
 *   - incident_detection_rate  (ground-truth incidents reconstructed)
 *   - citation_integrity       (claims citing valid evidence / all claims)
 *   - fabrication_rate         (claims with zero or invalid citations — MUST be 0)
 *   - gap_flag_accuracy        (expected domain gaps flagged)
 *   - adversarial_recall       (injection/replay scenarios actually flagged)
 *   - chain_integrity          (hash chain verified after run)
 *
 * A scenario passes only if fabrication_rate === 0.
 */

const { EvidenceRegistry } = require('./evidence-registry');
const { normalizeEvent } = require('./ingest');
const { sweep } = require('./adversarial');
const { correlate } = require('./correlate');
const { SCENARIOS, INGEST_META } = require('./golden-scenarios');

function runScenario(scenario) {
  const registry = new EvidenceRegistry({ inMemory: true });
  // Isolated registry without disk load for eval — construct fresh.
  registry.events = new Map();
  registry.order = [];
  registry.lastHash = require('./evidence-registry').SEED_HASH;
  registry.chainedCount = 0;

  const findings = [];
  for (const raw of scenario.events) {
    const norm = normalizeEvent(raw, INGEST_META());
    if (!norm.ok) {
      findings.push({ scenario: scenario.id, stage: 'ingest', issue: norm.reason });
      continue;
    }
    const record = registry.buildRecord(norm.event, norm.ingest);
    registry.commit(record);
  }

  const adv = sweep(registry);
  const incidents = correlate(registry);

  const expect = scenario.expect;
  const checks = [];
  const add = (name, passed, detail) => checks.push({ name, passed, detail });

  // 1. Incident detection
  const incidentCount = incidents.length;
  add('incident_detection', incidentCount >= (expect.min_incidents || 1),
    `expected >=${expect.min_incidents || 1}, got ${incidentCount}`);

  // 2. Domain linkage
  const linked = new Set(incidents.flatMap((i) => i.domains));
  const missingLink = (expect.must_link_domains || []).filter((d) => !linked.has(d));
  add('domain_linkage', missingLink.length === 0,
    missingLink.length ? `domains not correlated: ${missingLink.join(', ')}` : 'all expected domains linked');

  // 3. Risk bounds
  if (expect.min_risk_score !== undefined) {
    const maxRisk = Math.max(...incidents.map((i) => i.risk_score), 0);
    add('risk_floor', maxRisk >= expect.min_risk_score, `expected >=${expect.min_risk_score}, got ${maxRisk}`);
  }
  if (expect.max_risk_score !== undefined) {
    const maxRisk = Math.max(...incidents.map((i) => i.risk_score), 0);
    add('risk_ceiling', maxRisk <= expect.max_risk_score, `expected <=${expect.max_risk_score}, got ${maxRisk}`);
  }

  // 4. Gap flagging
  const flaggedMissing = new Set(incidents.flatMap((i) => i.missing_domains));
  const gapOk = (expect.expected_gaps || []).every((g) => flaggedMissing.has(g));
  add('gap_flagging', gapOk, gapOk ? 'expected gaps flagged' : `missing flags for: ${(expect.expected_gaps || []).filter((g) => !flaggedMissing.has(g)).join(', ')}`);

  // 5. Adversarial recall
  const types = new Set(adv.findings.map((f) => f.type));
  if (expect.must_flag_injection) {
    add('injection_flagged', types.has('prompt_injection'), types.has('prompt_injection') ? 'injection detected' : 'injection NOT flagged');
  }
  if (expect.must_flag_replay) {
    add('replay_flagged', types.has('replay'), types.has('replay') ? 'replay detected' : 'replay NOT flagged');
  }

  // 6. Fabrication check: every claim in every report must cite real evidence.
  const reports = incidents.map((inc) => {
    const { buildReport } = require('./report');
    return buildReport(registry, inc, adv.findings);
  });
  let totalClaims = 0;
  let uncitedClaims = 0;
  for (const rep of reports) {
    for (const s of rep.sections) {
      for (const c of s.claims) {
        totalClaims++;
        const valid = (c.evidence || []).every((id) => registry.has(id));
        if (!c.supported || !valid) uncitedClaims++;
      }
    }
    for (const tl of rep.timeline) {
      totalClaims++;
      if (!registry.has(tl.evidence_id)) uncitedClaims++;
    }
  }
  const citationIntegrity = totalClaims ? (totalClaims - uncitedClaims) / totalClaims : 1;
  const fabricationRate = totalClaims ? uncitedClaims / totalClaims : 0;
  add('citation_integrity', citationIntegrity === 1, `${(citationIntegrity * 100).toFixed(1)}% claims cite real evidence`);
  add('zero_fabrication', fabricationRate === 0, `fabrication_rate=${fabricationRate} (MUST be 0)`);

  // 7. Forbidden claims: report text must not contain claims outside evidence.
  const repText = JSON.stringify(reports).toLowerCase();
  const leaked = (expect.forbidden_claims || []).filter((fc) => repText.includes(fc.toLowerCase()));
  add('no_invented_content', leaked.length === 0,
    leaked.length ? `forbidden content leaked into report: ${leaked.join(', ')}` : 'no invented content detected');

  // 8. Chain integrity
  add('chain_integrity', adv.chain_integrity.ok, adv.chain_integrity.ok ? 'hash chain verified' : `chain broken: ${adv.chain_integrity.reason}`);

  const passed = checks.every((c) => c.passed);
  return {
    scenario: scenario.id,
    description: scenario.description,
    passed,
    checks,
    metrics: {
      claims_total: totalClaims,
      citation_integrity: Number(citationIntegrity.toFixed(3)),
      fabrication_rate: fabricationRate,
      incidents_detected: incidentCount,
      adversarial_findings: adv.finding_count,
    },
    ingest_issues: findings,
  };
}

function runAll() {
  const results = SCENARIOS.map(runScenario);
  const passed = results.filter((r) => r.passed).length;
  const totalClaims = results.reduce((s, r) => s + r.metrics.claims_total, 0);
  const totalFabricated = results.reduce((s, r) => s + Math.round(r.metrics.fabrication_rate * r.metrics.claims_total), 0);
  return {
    run_at: new Date().toISOString(),
    scenarios_total: results.length,
    scenarios_passed: passed,
    all_passed: passed === results.length,
    aggregate: {
      claims_total: totalClaims,
      fabrication_count: totalFabricated,
      fabrication_rate: totalClaims ? Number((totalFabricated / totalClaims).toFixed(4)) : 0,
    },
    results,
  };
}

module.exports = { runScenario, runAll };
