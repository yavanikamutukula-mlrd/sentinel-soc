# Sentinel SOC — Evidence-Backed AI Security Operations

AI-assisted SOC investigation platform that correlates multi-domain telemetry
(endpoint / identity / cloud / network) into **evidence-backed incident
reports** — without hallucinating missing data.

## Anti-hallucination guarantees (enforced by construction)

| Guarantee | Mechanism |
|---|---|
| Every claim cites evidence | Report generator emits only claims carrying evidence IDs that exist in the registry; a claim without citations becomes a visible **DATA GAP** |
| Missing data is flagged, never invented | Unrepresented domains/fields render as explicit gaps with a coverage note |
| Evidence is tamper-evident | SHA-256 hash chain over canonical JSON; `GET /api/integrity/verify` detects any tamper/reorder/delete |
| Adversarial logs are contained | Prompt-injection / replay / spoof / clock-skew detection; flagged content is excluded from AI context |
| Location is provenance-tracked | Countries shown on the threat map carry `operator_intel` or `provider_geo` provenance; IPs without geo evidence are listed as **unlocated**, never guessed |
| Measurable trust | Golden-scenario suite reports fabrication rate (must be 0), citation integrity, gap-flag accuracy, adversarial recall |

## Quick start

```bash
npm install
npm run seed     # load realistic demo attack stories
npm start        # http://localhost:3000
```

Dashboard: open the URL above. Default tokens (change in production):
- Admin: `sentinel-admin-token`
- Ingest: `ingest-demo-token`

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health` | – | liveness + event count |
| GET | `/api/stats` | – | registry stats by domain |
| POST | `/api/ingest/event` | ingest | submit one telemetry event |
| POST | `/api/ingest/batch` | ingest | up to 500 events |
| GET | `/api/incidents` | admin | correlated incident list |
| GET | `/api/reports` | admin | all evidence-backed reports |
| GET | `/api/incidents/:id/report` | admin | one full report |
| GET | `/api/integrity/verify` | admin | hash-chain verification |
| GET | `/api/adversarial/sweep` | admin | injection/replay/spoof findings |
| POST | `/api/evaluation/run` | admin | golden-scenario evaluation |

Event example:

```bash
curl -X POST $BASE/api/ingest/event \
  -H "Authorization: Bearer ingest-demo-token" \
  -H "Content-Type: application/json" \
  -d '{"domain":"identity","action":"login_failure","timestamp":"2026-10-01T10:00:00Z","user":"j.doe","src_ip":"185.220.101.7","geo":"RU","mfa_used":false,"source_tool":"okta"}'
```

Strict validation: missing/unparseable fields are **rejected with an explicit
reason** — never silently fixed, because fixing = inventing.

## Custom URL

Set `PUBLIC_BASE_URL=https://soc.yourdomain.com` (Render → Environment) after
pointing DNS at the service. All API links then render with your domain.

## Location / threat-origin data

`data/ip-intel.json` maps external IPs → country + ASN + tags (provenance
`operator_intel`). IdP-supplied geo is provenance `provider_geo`. IPs absent
from both sources appear under "unlocated" — the system refuses to guess.

`data/assets.json` maps internal IPs → hosts/users (mini CMDB) used as
explicit, auditable correlation aliases.

## Evaluation

```bash
npm run eval
```

4 golden scenarios: full kill chain, identity-only noise (must NOT invent
context), prompt-injection canary, replay attack. Fabrication rate must be 0.

## Deploy free (Render)

1. Push to GitHub.
2. render.com → New → Blueprint → select repo (`render.yaml` included).
3. Free plan: set `ADMIN_TOKEN` / `INGEST_TOKENS` env vars.
4. Optional: custom domain in Render settings + `PUBLIC_BASE_URL`.

Note: free tier disk is ephemeral — the evidence registry reseeds on restart.
For durable storage, attach a Render disk or point `DATA_DIR` at a mounted path.

## Architecture

```
src/
  server.js               REST API + static dashboard
  config.js               env-driven configuration
  lib/
    evidence-registry.js  append-only hash-chained store (anti-hallucination core)
    ingest.js             strict multi-domain normalization/validation
    correlate.js          union-find entity clustering + provenance-tracked location intel
    adversarial.js        prompt-injection / replay / spoof / tamper detection
    report.js             evidence-cited report generator (gaps > invention)
    eval.js               golden-scenario evaluation framework
    golden-scenarios.js   ground-truth scenarios
    assets.js             operator CMDB + IP intel (location provenance)
public/                   zero-build dashboard (live feed, incidents, threat map, eval)
scripts/                  seed + eval CLI
```
