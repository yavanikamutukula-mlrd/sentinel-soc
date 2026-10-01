# Sentinel SOC — Evidence-Backed AI Security Operations

AI-assisted SOC investigation platform that correlates multi-domain telemetry
(endpoint / identity / cloud / network) into **evidence-backed incident
reports** — without hallucinating missing data.

- **Multi-component pipeline**: high-velocity ingestion with strict
  normalization, union-find correlation across endpoint/identity/cloud/network.
- **Cross-domain correlation**: fragmented, noisy events are pieced into
  cohesive incident storylines with unified timelines.
- **Strict evidence grounding**: every claim cites evidence IDs that provably
  exist in the hash-chained registry; anything unrepresented becomes a
  visible DATA GAP.
- **Adversarial resilience**: prompt-injection, replay, spoofing, clock-skew
  and tamper detection; flagged content never reaches report generation.
- **Production-ready evaluation**: golden-scenario suite auditing fabrication
  rate, citation integrity, gap-flag accuracy and adversarial recall.

## Anti-hallucination guarantees (enforced by construction)

| Guarantee | Mechanism |
|---|---|
| Every claim cites evidence | Report generator emits only claims carrying evidence IDs that exist in the registry; a claim without citations becomes a visible **DATA GAP** |
| Missing data is flagged, never invented | Unrepresented domains/fields render as explicit gaps with a coverage note |
| Evidence is tamper-evident | SHA-256 hash chain over canonical JSON; `GET /api/integrity/verify` detects any tamper/reorder/delete |
| Adversarial logs are contained | Prompt-injection / replay / spoof / clock-skew detection; flagged content is excluded from AI context |
| Location is provenance-tracked | Countries shown on maps/graphs carry `operator_intel` or `provider_geo` provenance; IPs without geo evidence are listed as **unlocated**, never guessed |
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

### Sign in / sign out

Click **Sign in** in the header and paste your admin and/or ingest token.
Tokens are validated against the backend (`GET /api/auth/whoami`), shown as a
session chip, and stored **only in this browser tab** (sessionStorage) — sign
out clears them. Visitors without a token can browse everything when
`PUBLIC_MODE=true` (read-only).

## Publish free (GitHub Pages + Render)

1. **Dashboard on GitHub Pages (static, free):**
   - Push this repo to GitHub (see below).
   - Repo → Settings → Pages → Source: **GitHub Actions**.
   - The included workflow (`.github/workflows/pages.yml`) builds a fresh
     demo snapshot (`public/demo-data.json`) and deploys on every push to
     `main`. Visitors get a fully browsable site — incidents, reports,
     locations with graphs, threat map, evaluation — from the snapshot.
   - To connect real-time data, visitors set the **API URL** field in the
     header, or you share deep links like
     `https://<user>.github.io/repo/?api=https://soc-api.onrender.com`.
2. **API on Render (free web service):**
   - render.com → New → Blueprint → select this repo (`render.yaml` included;
     sets `AUTO_SEED` and `PUBLIC_MODE`).
   - Set `ADMIN_TOKEN` / `INGEST_TOKENS` env vars on the free plan.
3. **Point the dashboard at the API:** set the API URL field once (persisted
   in localStorage) or use `?api=` deep links.

> GitHub Pages serves only static files — the Node API must run somewhere
> like Render. That's why the Pages build ships a demo snapshot as fallback.

### Custom domain & subdomain

**Dashboard (GitHub Pages):**
1. Repo → Settings → Secrets and variables → Actions → **Variables** tab →
   new variable `PAGES_CNAME` = `soc.yourdomain.com` (apex or subdomain).
2. DNS: CNAME record → `<user>.github.io` (apex domains use A/ALIAS records
   to GitHub's IPs).
3. The workflow writes the CNAME file automatically on the next deploy.

**API (Render):**
1. Render → your service → Settings → Custom Domains → add
   `api.yourdomain.com` (or any subdomain) and follow the DNS instructions.
2. Set `PUBLIC_BASE_URL=https://api.yourdomain.com` so `/api` discovery and
   endpoint references use your domain.
3. Set `ALLOWED_ORIGINS=https://soc.yourdomain.com,https://<user>.github.io`
   so the browser dashboard may call the API cross-origin (CORS preflight is
   handled by the server). Keep `*` only for public demos.

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api` | – | discovery: endpoints, domains, access info |
| GET | `/api/health` | – | liveness + event count |
| GET | `/api/stats` | – | registry stats by domain |
| GET | `/api/auth/whoami` | – | token introspection: role + capabilities (login support) |
| POST | `/api/ingest/event` | ingest | submit one telemetry event |
| POST | `/api/ingest/batch` | ingest | up to 500 events |
| GET | `/api/incidents` | admin (open in public mode) | correlated incident list |
| GET | `/api/reports` | admin (open in public mode) | all evidence-backed reports |
| GET | `/api/incidents/:id/report` | admin (open in public mode) | one full report |
| GET | `/api/evidence/:id` | admin (open in public mode) | raw chained evidence record |
| GET | `/api/locations` | admin (open in public mode) | country rollup with provenance |
| GET | `/api/integrity/verify` | admin (open in public mode) | hash-chain verification |
| GET | `/api/adversarial/sweep` | admin (open in public mode) | injection/replay/spoof findings |
| POST | `/api/evaluation/run` | admin (open in public mode) | golden-scenario evaluation |
| POST/GET/DELETE | `/api/keys` | admin | mint / list / revoke ingest API keys |

Event example:

```bash
curl -X POST $BASE/api/ingest/event \
  -H "Authorization: Bearer ingest-demo-token" \
  -H "Content-Type: application/json" \
  -d '{"domain":"identity","action":"login_failure","timestamp":"2026-10-01T10:00:00Z","user":"j.doe","src_ip":"185.220.101.7","geo":"RU","mfa_used":false,"source_tool":"okta"}'
```

Strict validation: missing/unparseable fields are **rejected with an explicit
reason** — never silently fixed, because fixing = inventing.

## Public demo mode

Set `PUBLIC_MODE=true` (enabled in `render.yaml`) to let visitors browse
everything on the website without a token: incidents, evidence-backed reports,
threat-origin **locations with graphs**, integrity verification, adversarial
sweep, and the evaluation runner. Write operations (ingest, API-key
minting/revocation) always require credentials. Set `PUBLIC_MODE=false` for a
private deployment.

## Demo snapshot (static hosting)

`npm run build:demo` regenerates `public/demo-data.json` from the same seed
stories the live API uses. The GitHub Pages workflow runs it automatically.
When the dashboard can't reach a backend it switches to **demo mode**: every
view renders from the snapshot, and write operations return a clear
"needs a live backend" message instead of failing silently.

## Location / threat-origin data

`data/ip-intel.json` maps external IPs → country + ASN + tags (provenance
`operator_intel`). IdP-supplied geo is provenance `provider_geo`. IPs absent
from both sources appear under "unlocated" — the system refuses to guess.

`data/assets.json` maps internal IPs → hosts/users (mini CMDB) used as
explicit, auditable correlation aliases.

## Evaluation

```bash
npm run eval     # CLI
npm test         # boot-the-server smoke tests
```

4 golden scenarios: full kill chain, identity-only noise (must NOT invent
context), prompt-injection canary, replay attack. Fabrication rate must be 0.

## Architecture

```
src/
  server.js               REST API + static dashboard
  config.js               env-driven configuration
  lib/
    evidence-registry.js  append-only hash-chained store (anti-hallucination core)
    ingest.js             strict multi-domain normalization/validation
    correlate.js          union-find entity clustering + provenance-tracked location intel
    locations.js          country-level aggregation (shared by API + demo build)
    adversarial.js        prompt-injection / replay / spoof / tamper detection
    report.js             evidence-cited report generator (gaps > invention)
    eval.js               golden-scenario evaluation framework
    golden-scenarios.js   ground-truth scenarios
    assets.js             operator CMDB + IP intel (location provenance)
    apikeys.js            managed ingest credentials (survives restarts)
public/                   zero-build dashboard (live feed, incidents, threat map,
                          locations with graphs, eval) + demo-data.json snapshot
scripts/                  seed + eval CLI + demo snapshot builder
tests/                    smoke tests (boots the real server)
```

## Push to GitHub

```bash
git init                       # if not already a repo
git add -A
git commit -m "Sentinel SOC: evidence-backed SOC platform"
git remote add origin https://github.com/<you>/sentinel-soc.git
git push -u origin main
```

Then enable Pages (Settings → Pages → Source: GitHub Actions). Deploys are
automatic on every push to `main`.

Note: Render's free tier disk is ephemeral — the evidence registry reseeds on
restart (`AUTO_SEED=true`). For durable storage, attach a Render disk or point
`DATA_DIR` at a mounted path.
