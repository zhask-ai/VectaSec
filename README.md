# VectaSec

**Security posture for the integration layer.** VectaSec connects read-only to the brokers,
gateways, meshes, cloud messaging services, automation platforms and MCP servers that wire a
company's systems together, and answers one question for teams without a security department:

> *Who — which API key, service account, OAuth client or automation — can touch your data, who
> owns it, when it was last used, whether it is reachable from the internet, and what to run to
> fix it.*

It never routes traffic, never brokers a message and never writes to a target. It inventories,
checks, correlates and explains, and every claim it makes cites a stored observation.

- **Console:** Overview · Findings · Access · Estate · Compliance · Settings
- **Engine:** 40 read-only connectors, ~460 deterministic detectors, a non-human-identity graph,
  compliance mapping (PCI DSS 4.0.1, SOC 2, ISO/IEC 27001:2022, DORA, NIS2, HIPAA, MCP spec),
  a guided-fix library with a verify-by-rescan loop, and citation-gated AI triage
- **Delivery:** hosted multi-tenant SaaS on Supabase, or self-hosted from the same code

Where this README and [docs/STATUS.md](docs/STATUS.md) disagree, STATUS.md is right: it is the
file that says what is proven, what is partial and what has never run.

---

## Table of contents

1. [What it does](#what-it-does)
2. [How it works](#how-it-works)
3. [Repository layout](#repository-layout)
4. [Quickstart](#quickstart)
5. [Connecting systems](#connecting-systems)
6. [The console](#the-console)
7. [Engine API and CLI](#engine-api-and-cli)
8. [Data model and guarantees](#data-model-and-guarantees)
9. [Compliance and reports](#compliance-and-reports)
10. [Integrations](#integrations)
11. [Development](#development)
12. [Deployment](#deployment)
13. [Security model](#security-model)
14. [Documentation](#documentation)
15. [Status and roadmap](#status-and-roadmap)

---

## What it does

| Capability | In one sentence | Where |
|---|---|---|
| **Access register** | Every identity the connected systems accept — ACL principals, broker users, Kong consumers, IAM users and roles, OAuth clients, automation connections — with owner, last used, grants, sensitivity of what they reach, and flags for *exposed*, *also in git* and *held by an automation*. Exportable as the register a SOC 2 / ISO auditor asks for. | Console → Access; `GET /reports/access-register` |
| **Findings** | Deterministic detectors per connector (plaintext listeners, wildcard ACLs, default credentials, public policies, missing auth, CVE / end-of-life versions, …) with severity, cited evidence and an honest third state, `not_assessable`, when the evidence could not be read. | Console → Findings; `vectasec findings` |
| **Priority paths** | Correlation across the graph: an exposed surface + an over-privileged identity + sensitive-named data on one path is one critical finding, not three mediums. | Findings → Priority paths |
| **Guided fix + Verify** | Exact per-system fix snippets (CLI, Terraform, Helm, console) templated with the resource's own names, and a Verify button that rescans and resolves the finding automatically when the issue is gone — recorded in the audit trail. | Finding page; `GET /findings/{id}/fix`, `POST /findings/{id}/verify` |
| **Estate** | What is connected, what is on the network but unmonitored (shadow middleware), the full resource inventory with blast radius, and the catalogue of what can be assessed. Scan history is a drawer on each connection. | Console → Estate |
| **External exposure scan** | Enter a domain, prove you own it with a DNS TXT record, get a credential-less, public-safe report of internet-reachable middleware with CVE and end-of-life status attached. | Estate → Unmonitored |
| **Compliance** | Findings mapped to controls. A scan can prove a control *fails*; only a human attestation can make it *pass*. Reports & exports: evidence bundle (OSCAL, CSV, executive summary), runtime SBOM and VEX (CycloneDX 1.6), licensing inventory. | Console → Compliance |
| **Weekly digest** | New findings, newly exposed paths, new credentials, newly unused credentials, what was fixed, posture delta — to Slack, Teams, email, webhook, Vanta or Drata. | `vectasec digest`; Settings → Integrations |
| **Runtime evidence** | Who is connected *right now*, from the brokers themselves (RabbitMQ connections, Redis `CLIENT LIST`, NATS `connz`, PgBouncer, Kafka consumer groups) — the evidence behind "last seen". | Access → Live connections |
| **Supply chain** | Running-version SBOM, OSV + NVD feeds, end-of-support rulepack, integration-as-code analysis (compose, Kubernetes, Helm values, Kafka Connect, RabbitMQ definitions, Kong declarative config) that finds committed credentials and principal names. | Findings → Supply chain lens; Compliance → Reports |

### Connectors

**On the shelf** (shown by default — what a team new to cloud actually runs):
AWS (SQS, SNS, EventBridge, MSK, API Gateway, IAM last-used) · Google Cloud (Pub/Sub, Apigee) ·
Azure (Service Bus, Event Hubs, APIM, Logic Apps) · Kubernetes & service mesh (Istio, Linkerd,
Gateway API, Ingress, RBAC) · Kafka (Apache, Confluent Cloud, Redpanda) · RabbitMQ · Redis ·
Kong · n8n & Zapier · MCP servers · OpenAPI & GraphQL · repos & manifests (IaC).

**Enterprise, on request** (fully supported, hidden behind a toggle):
IBM MQ, Solace, ActiveMQ / Artemis, Pulsar, NATS, MQTT, gRPC, Kafka Connect, Schema Registry,
Flink, Airflow, MuleSoft, Boomi, Workato, managed file transfer, Elasticsearch, Solr, Memcached,
PgBouncer, Vault, Keycloak, vector databases, ZooKeeper / etcd / Consul / Nacos.

Plus the **network discovery sweep**: read-only, pre-authentication fingerprinting of middleware
on declared ranges, correlated against what is connected to surface what nobody monitors.

The per-connector, falsifiable statement of what is read, what is emitted and what is *not*
covered is [docs/coverage-matrix.md](docs/coverage-matrix.md).

---

## How it works

```
                     ┌──────────────────────────── Supabase control plane ────────────────────────────┐
                     │  Postgres (FORCE RLS multi-tenancy) · Auth · Vault · Realtime · pgmq · pg_cron  │
                     └───────▲───────────────────────▲────────────────────────────────▲───────────────┘
                             │ SELECT-only, RLS       │ BYPASSRLS, one transaction      │ queue / cron
                             │                        │ per scan                        │
┌────────────────┐    ┌──────┴──────┐          ┌──────┴──────┐                   ┌──────┴──────┐
│   Browser      │───▶│  Console    │─actions─▶│  Engine API │◀── jobs ──────────│   Worker    │
│                │    │  (Next.js)  │  (token) │  (FastAPI)  │                   │ (vectasec   │
└────────────────┘    └─────────────┘          └──────┬──────┘                   │  worker)    │
                                                      │ collect → detect → persist└──────┬──────┘
                                                      ▼                                   │
                                        ┌──────────────────────────┐                      │
                                        │ Connectors (read-only)   │◀─────────────────────┘
                                        │ Kafka · RabbitMQ · AWS … │        or: customer-side Collector
                                        └──────────────────────────┘        (private networks, outbound-only)
```

**A scan** (`services/engine/src/vectasec/scan.py`) is one transaction:

1. **Collect.** The connector for the connection's type reads the target with List / Get /
   Describe calls only and returns `Resource`s (kind, name, ext_id, labels, raw) and `Edge`s.
   Secrets declared by the connector live in Supabase Vault and are merged into the config in
   memory only.
2. **Enrich.** Identity extractors derive the normalized `identity` / `credential` / `grant`
   kinds; the classifier adds naming-based data classes; the graph engine correlates
   exposure × privilege × sensitivity into attack-path findings.
3. **Detect.** Every registered detector whose `kinds` match runs against each resource and
   returns `Hit`s: observation, remediation, evidence reference, and `assessable=False` when the
   evidence could not be read.
4. **Persist.** Resources upsert (vanished ones are marked stale, never deleted); findings upsert
   by fingerprint so a re-run never resurrects what a human resolved; every finding commits with
   its cited observation in the hash-chained evidence ledger; verify-requested findings that the
   scan no longer emits are resolved and audited; compliance controls are re-evaluated; the OSV /
   NVD feeds run; notifications route.

**The console** reads Postgres directly as the `authenticated` role (SELECT-only under RLS) and
forwards every mutation to the engine through Server Actions carrying a server-verified actor.
The browser never holds a service key or a database URL.

**The engine** authenticates callers with a Supabase user JWT (public JWKS) or a scoped engine
service token, binds to localhost by default, and writes an audit row for every mutation in the
same transaction as the change.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) is the detailed map: auth matrix, Vault flow, scan
pipeline, scheduler, collector protocol.

---

## Repository layout

```
.
├── apps/web/                      Next.js 16 console (React 19, TypeScript, typed routes)
│   ├── app/(app)/                 Authed routes: page.tsx (Overview), findings/, access/, estate/,
│   │                              compliance/, settings/, admin/
│   ├── app/api/reports/[format]/  Download proxy to the engine's report endpoints
│   ├── components/shell/          App shell: six-item nav, top bar, search, theme
│   ├── components/ui/             Design-system primitives (see DESIGN.md)
│   ├── lib/                       Supabase clients, engine client, roles, posture formula
│   ├── scripts/contrast-check.mjs Design-token and WCAG contrast audit (`pnpm contrast`)
│   └── DESIGN.md                  The design system: tokens, laws, primitives
├── services/engine/               Python 3.12 engine (uv project)
│   └── src/vectasec/
│       ├── connect/               One file per connector (+ discover/ for the network sweep)
│       ├── detect/                One rulepack per connector + cross-cutting packs
│       │                          (identity, credential_lifecycle, attack_path, data, cve, …)
│       ├── compliance/map.py      Findings → framework controls; the no-pass-from-silence contract
│       ├── identity.py            NHI derivation: identity / credential / grant builders
│       ├── graph_engine.py        Toxic-combination correlation (attack paths)
│       ├── remediation.py         Guided-fix library (per-rule snippets)
│       ├── exposure.py            External exposure scan + DNS ownership gate
│       ├── assistant.py           AI: cited Q&A, change explanation, quote-verified review, digest opening
│       ├── ai_core.py             Provider-neutral JSON completion over the Anthropic → OpenAI → Gemini chain
│       ├── connect/mcp_client.py  MCP client configs in repos (.mcp.json, .cursor/mcp.json, …); secrets fingerprinted only
│       ├── effective.py           Effective access by each system's own rules (Kafka, RabbitMQ, Redis)
│       ├── breach.py              Breach-day briefs: advisory matched to stored inventory, rotation order
│       ├── leaver.py              Leaver report: what one person owns and what depends on it
│       ├── impact.py              Fix preview ("what breaks") and least-privilege dry runs
│       ├── canary.py              Decoy URLs; only the token hash is stored
│       ├── benchmark.py           Integration-Layer Benchmark generated from the detector registry
│       ├── flows.py               Toxic flows, MCP agent reach, sensitive-data map
│       ├── proof.py               Proof mode: one read-only pre-auth probe per finding, never a credential
│       ├── timemachine.py         Configuration history: scan diff, as-of view, change report
│       ├── digest.py              Weekly change digest
│       ├── notify.py              Slack / Teams / email / webhook / Jira / SIEM / Vanta / Drata
│       ├── report.py              OSCAL, CSV, executive summary, access register
│       ├── sbom.py, osv.py, nvd.py, lifecycle.py, cve_data.py   Supply-chain half
│       ├── scan.py, worker.py     The scan transaction and the pgmq consumer
│       ├── api/                   FastAPI app (main.py) + routers (extra.py, exposure.py)
│       ├── ai.py                  Citation-gated triage with a model fallback chain
│       └── cli.py                 `vectasec` command
├── services/collector/            Customer-side collector for private networks (outbound-only)
├── supabase/migrations/           Schema, RLS, integrity triggers, queue, scheduler — apply in order
├── deploy/dev/                    Deliberately misconfigured Kafka / RabbitMQ / Redis for local scans
├── deploy/aws/                    CloudFormation template for the read-only cross-account role
├── deploy/onprem/                 Self-hosted stack (Compose, Caddy, Helm) — validated, never booted
├── docs/                          Architecture, status, coverage matrix, strategy, research
└── .github/workflows/ci.yml       engine tests · web build · live dev-Kafka detectors · RLS attack tests
```

---

## Quickstart

From clone to a cited finding in about five minutes.

### Prerequisites

| Tool | Why |
|---|---|
| Docker | the local misconfigured scan targets |
| [uv](https://docs.astral.sh/uv/) | the engine is a Python 3.12 uv project |
| Postgres 17 with `pgmq`, `pg_cron`, `supabase_vault` | a free [Supabase](https://supabase.com) project is enough |
| Node 22 + pnpm 9 | the console only |

### 1. Environment

```bash
cp .env.example .env
```

Set `DATABASE_URL` and the `SUPABASE_*` values. `ANTHROPIC_API_KEY` is optional: without it, AI
triage uses its deterministic fallback. Set `VECTASEC_ENGINE_TOKEN` to a random secret in both
the engine environment and `apps/web/.env.local`.

### 2. Apply the schema

Apply every file in `supabase/migrations/` in filename order (Supabase SQL editor, `psql`, or
`supabase db push`). The first migration seeds a Demo tenant the CLI defaults to, so you can scan
before you have users. The `20261017*` migrations add the verify loop, digests, exposure scans
and the Zapier Vault entry; the `20261123*` migrations add change history, proofs, breach briefs
and canaries; `20261124000001` adds confirmed identity owners.

### 3. Start the dev targets

```bash
docker compose -f deploy/dev/docker-compose.yml up -d
```

A Kafka, RabbitMQ and Redis with every bad setting annotated with the rule it should trigger.

### 4. Check the wiring

```bash
cd services/engine
uv run vectasec doctor
```

### 5. Scan from the CLI

```bash
uv run vectasec connections add --type kafka --name dev-kafka --bootstrap localhost:9092
uv run vectasec scan --connection dev-kafka
uv run vectasec findings
uv run vectasec identities
uv run vectasec posture
```

### 6. Run the API and the worker

```bash
cd services/engine
uv run python -m vectasec.api.main     # http://127.0.0.1:8000 — /docs for OpenAPI
uv run vectasec worker                 # second terminal: drains the pgmq scan queue
```

### 7. Run the console

```bash
cd apps/web
cp .env.example .env.local             # Supabase URL + anon key; add VECTASEC_ENGINE_TOKEN
pnpm install
pnpm dev                               # http://localhost:3000
```

Sign in (the user needs a `tenant_members` row, or use the self-serve onboarding), open
**Estate → Connect a system**, pick a card, and watch the first scan land on **Findings** and
**Access**.

---

## Connecting systems

Every connector declares its fields in code (`ConnectorField`, including which are secrets); the
console form, the CLI and the API all validate against the same declaration. Secret fields are
split out to Supabase Vault at write time and are never readable from the browser afterwards.

Typical setups:

- **AWS:** deploy `deploy/aws/vectasec-readonly-role.yaml` (a cross-account role with an
  `ExternalId` trust condition and a least-privilege read-only policy), then paste the role ARN.
  `deploy/aws/README.md` lists why each action is needed.
- **Kafka / RabbitMQ / Redis / Kong:** a read-only user; the connector only describes, lists and
  reads config. The dev compose file shows the minimum.
- **Kubernetes:** a kubeconfig or in-cluster service account with `get` / `list` on the mesh,
  gateway, ingress and RBAC resources.
- **Repos (IaC):** a path or clone of the manifests. Secret values are reduced to a non-reversible
  fingerprint at parse time; principal *names* are kept so Access can show "also in git".
- **n8n / Zapier / MCP:** an API key or bearer token with read scopes; credential values are never
  returned by those APIs and never requested.
- **External exposure scan:** no credentials. Add a domain, publish the `vectasec-verify=…` TXT
  record, verify, run.

Collector mode exists for systems the SaaS cannot reach: `services/collector` runs inside the
customer network, long-polls for jobs, scans locally and pushes findings and resource metadata
out — never raw config.

---

## The console

Six pages. Design laws (tokens only, colour never the only signal, say what is true) are in
[apps/web/DESIGN.md](apps/web/DESIGN.md) and enforced by `pnpm contrast`.

| Page | What it answers |
|---|---|
| **Ask** | A plain-language question about the workspace, answered from stored records with links to each one (or a plain search when no AI provider is configured). |
| **Overview** | Posture score and trend, what changed this week, what to do now, a first-ten-minutes checklist, compliance strip, recent scans. |
| **Findings** | The queue, grouped by rule and ordered by severity, with facets for severity, status, assessment and system, lenses for supply chain / credential lifecycle / over-broad access, the **Priority paths** tab, **Breach day** (match an advisory or vendor breach to the stored inventory and get a rotation order) and **Canaries** (decoy URLs that alert when called). A finding page shows evidence, **Proof** (one read-only pre-authentication request that shows the finding is reachable, with the transcript), **When this opened**, triage, the guided fix and Verify. |
| **Access** | The register: identity × system × owner × last seen × sensitive data × flags × grants × risk, with filters and the CSV / Markdown register export. **Live connections** shows runtime evidence and the observation window. **Right-size** compares each identity's grants with what it was seen using and shows a dry-run change. **Leavers** lists everything one person owns and what keeps running on their authority. **Data & agents** shows toxic flows across automations, what MCP servers can reach, and who can read sensitive data. |
| **Estate** | **Connected** (health, cadence, scan history drawer, actions), **Unmonitored** (discovery results and the external exposure scan), **Inventory** (every resource, blast radius, per-resource change history), **History** (the Time machine: what changed between scans with before and after values, the estate as recorded on a past date, and the access-and-change report), **What we can assess** (the shelf and the enterprise tier). |
| **Compliance** | **Controls** per framework with attestation, **Benchmark** (the generated Integration-Layer Benchmark per system, with your result), **Reports & exports** (OSCAL, CSV, executive summary, SBOM, VEX, licensing). |
| **Settings** | General, members and roles, integrations and routing rules (including the weekly digest). |

Old routes (`/connections`, `/identities`, `/attack-paths`, `/scans`, `/supply-chain`, …)
redirect to their new homes.

---

## Engine API and CLI

The API (`services/engine/src/vectasec/api/main.py`, OpenAPI at `/docs`) is the only write path.
Main groups:

| Group | Endpoints |
|---|---|
| Connections & scans | `POST/PATCH/DELETE /connections`, `POST /connections/{id}/scan`, `/test`, `POST /scans`, `GET /scans/{id}`, `GET /connectors` |
| Findings | `POST /findings/{id}/status`, `/assign`, `/triage`, `GET /findings/{id}/fix`, `POST /findings/{id}/verify`, `GET /findings/{id}/proof`, `POST /findings/{id}/prove`, `POST /suppressions` |
| Compliance & reports | `GET /compliance/{framework}`, `POST /compliance/{fw}/{control}/attest`, `GET /reports/{oscal,csv,summary,sbom,vex,access-register}`, `GET /licensing` |
| Exposure scan | `POST /exposure/targets`, `POST /exposure/targets/{id}/verify`, `POST /exposure/targets/{id}/scan`, `GET /exposure/targets`, `GET /exposure/scans/{id}` |
| Time machine | `GET /timeline/as-of?at=YYYY-MM-DD`, `GET /reports/changes?format=csv\|md\|json&days=30` (or `since` / `until`) |
| Breach day & canaries | `POST /breach-briefs`, `GET /reports/breach-brief?id=`, `POST /canaries`, `POST /canaries/{id}/revoke`, public `ANY /c/{token}` |
| Access analysis | `GET /findings/{id}/impact`, `GET /access/least-privilege`, `GET /people`, `GET /people/report?person=`, `GET /access/flows` |
| Benchmark | `GET /benchmark`, `GET /reports/benchmark?system=&blank=` |
| AI assistant | `POST /assistant/ask`, `GET /assistant/explain-changes?days=`, `POST /assistant/review/{resource_id}`, `GET /assistant/status` |
| Effective access | `GET /access/who-can/{resource_id}`, `GET /access/usage/{resource_id}?format=json\|csv`, `POST /access/owner` |
| Digest & integrations | `POST /digests/run`, `GET /digests`, `GET/POST/DELETE /integrations`, `/integrations/{id}/test`, `GET/POST/DELETE /routing-rules` |
| Tenancy & platform | `/members`, `/admin/*`, `/collector/*`, `GET /graph/blast-radius/{resource_id}` |

CLI (`uv run vectasec --help`): `doctor`, `rules`, `connections add|test|rm`, `scan`, `findings`,
`identities`, `posture`, `scans`, `worker`, `digest`.

---

## Data model and guarantees

- **Tenancy is enforced by Postgres.** Every tenant table has `FORCE ROW LEVEL SECURITY`; the
  browser role is SELECT-only; the engine's BYPASSRLS connection scopes every statement by the
  tenant the verified caller resolved to. CI runs adversarial cross-tenant queries against the
  real migrations.
- **Findings are facts with provenance.** A finding is identified by a fingerprint
  (tenant, connection, rule, resource); it carries `assessment` (`assessed` or
  `not_assessable` with a reason); every one cites observations in an append-only,
  hash-chained ledger (`verify_ledger()` detects rewrites).
- **AI output is citation-gated in the database.** An `ai_outputs` row cannot commit without
  linked evidence; the triage priority never drops below the rule's severity floor without saying
  so.
- **Secrets never land in the data plane.** Connection credentials live in Vault; connectors
  copy no credential material into resources; IaC secrets become fingerprints; the exposure scan
  publishes product / version / port only.
- **AI may relate facts, never introduce them.** Every AI output is checked by code before it is
  shown: answers must cite numbered stored facts, change explanations must cite recorded changes,
  review suggestions must quote a value the engine finds at the stated config path, and the
  digest opening may only use numbers present in the computed digest. Anything that fails is
  discarded and the deterministic result is shown, labelled. AI suggestions are never findings.
- **History is scan-to-scan, and says so.** Each scan compares what it collected with the
  previous state and appends to `resource_changes` (added / removed / modified / returned, with
  masked before and after values and telemetry filtered out). It proves what changed and the two
  scans it changed between; it names who only where the system's API returns an author. It is
  not the system's audit log.
- **Absence is never evidence.** A clean scan cannot write a compliance `pass`; "last seen" says
  *unknown* where no source collects it, never *unused*; a denied API call is a recorded coverage
  gap, not silence.

---

## Compliance and reports

`services/engine/src/vectasec/compliance/map.py` maps rules to controls for PCI DSS 4.0.1,
SOC 2 TSC (CC6.1–6.3, CC6.6, CC6.7, CC7.1, CC7.2), ISO/IEC 27001:2022 Annex A (A.5.15–18,
A.8.2, A.8.3, A.8.5, A.8.9, A.8.20, A.8.24), DORA, NIS2, HIPAA and the MCP authorization spec.
A control is in the catalogue only if an implemented rule maps to it; SOC 2 and ISO texts are
paraphrased (licensed documents) and say so. Rationale and refusals:
[docs/research/compliance-mapping.md](docs/research/compliance-mapping.md).

Exports: `/api/reports/{oscal,csv,summary,sbom,vex,register-csv,register-md}` in the console
proxy to the engine and stream the file back under the caller's own session.

---

## Integrations

Destinations (`notify.py`): **Slack**, **Microsoft Teams**, **email**, **webhook** (JSON, OCSF
detection findings), **Jira**, **SIEM**, **Vanta** (evidence document upload), **Drata**
(external evidence on a control). Routing rules match on minimum severity, connector types,
rule prefixes and event kinds (`new_findings`, `scan_failed`, `weekly_digest`,
`control_evaluated`). The console's integration form is generated from the engine's
`INTEGRATION_FIELDS`, so the two cannot drift.

Weekly digest: schedule `vectasec digest --all` (for example `0 8 * * 1`) or call
`POST /digests/run`; it delivers to every rule that names `weekly_digest` and records what it
sent in the `digests` table.

---

## Development

```bash
# engine
cd services/engine
uv run --with pytest pytest -q                 # ~2,700 offline tests, golden fixtures, no network
uvx ruff check --select E9,F63,F7,F82 .        # the "cannot run" lint subset CI gates on

# collector
cd services/collector && uv run --with pytest pytest -q

# console
cd apps/web
pnpm typecheck && pnpm build && pnpm contrast  # typed routes, production build, token/contrast audit
```

Conventions that matter:

- **One file per connector, one rulepack per connector.** Register with `@connector`,
  `@detector`, `@identity_extractor`; modules under `connect/` and `detect/` auto-import.
- **Pure parse layers, golden fixtures.** Connectors separate "call the API" from "turn the
  response into resources"; tests drive detectors from `tests/fixtures/*.json`. Live systems stay
  out of the unit suite (CI's `detectors-live` job covers the real dev Kafka).
- **Distinct resource kinds per connector** so a rulepack never runs against a foreign resource.
- **Never a silent pass.** Unreadable evidence files a `not_assessable` hit with a reason.
- **Console mirrors are generated, not typed.** `connector-fields.ts` and
  `integration-fields.ts` mirror the engine registries; regenerate from `CONNECTOR_FIELDS` /
  `INTEGRATION_FIELDS` when they change.
- **Migrations are additive.** Applied migrations are never edited; a later file extends them
  (see `20260801000001_lock_schema_migrations.sql`).

CI (`.github/workflows/ci.yml`): engine lint + unit tests, collector tests, console typecheck +
build, the connector and rulepack against a real misconfigured Kafka, migrations from empty, and
adversarial cross-tenant RLS tests. `ci` is the single aggregate check.

---

## Deployment

- **Hosted:** a Supabase project (migrations applied), the engine API + worker on any host that
  can reach it (keep the API off untrusted networks — it holds a BYPASSRLS connection), the
  console on Vercel or any Node host with the variables in `apps/web/.env.example`.
- **AWS role:** `deploy/aws/vectasec-readonly-role.yaml` via `aws cloudformation deploy`.
- **Self-hosted:** `deploy/onprem/` (Compose, Caddy, Helm) validates (`compose config`,
  `helm lint`, `kubeconform`) and has not been booted end to end; read its README first.
- **Collector:** `services/collector`, enrolled through `POST /collector/enroll`, outbound-only.

---

## Security model

- The console never receives `SUPABASE_SERVICE_ROLE_KEY` or `DATABASE_URL`.
- The engine verifies every caller (Supabase JWT or the engine service token, optionally pinned
  to one tenant). Self-asserted headers exist only behind `VECTASEC_DEV_TRUST_HEADERS=1`, default
  off, and warn loudly.
- Outbound notifications and evidence pushes go through `guard_url`, which refuses private and
  loopback destinations unless explicitly allowed.
- The network discovery sweep touches declared targets only, private ranges unless public
  scanning is declared, a hard host cap, a do-not-contact list, and never sends a credential; the
  external exposure scan additionally requires DNS-proven ownership and is rate-limited.
- Every mutation writes an `audit_log` row in the same transaction; config keys are logged, values
  never.

Report a vulnerability privately to the maintainers rather than in a public issue.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the code actually works: auth matrix, Vault flow, scan pipeline, scheduler, collector |
| [docs/STATUS.md](docs/STATUS.md) | What is done, partial and not built, each claim pointing at a file; dated notes per sprint |
| [docs/coverage-matrix.md](docs/coverage-matrix.md) | Per connector: reads, kinds, edges, NHI, rules, and what is **not** covered |
| [docs/vectasec-smb-strategy-2026-10.md](docs/vectasec-smb-strategy-2026-10.md) | The current product strategy: anchor, consolidation, eight-week plan |
| [docs/vectasec-capability-atlas.md](docs/vectasec-capability-atlas.md) | The long-term capability target |
| [docs/research/](docs/research/) | Sourced research behind rulepacks, compliance mapping, the exposure scan and the market |
| [apps/web/DESIGN.md](apps/web/DESIGN.md) | The console design system |
| [deploy/aws/README.md](deploy/aws/README.md) | The read-only AWS role, action by action |

---

## Status and roadmap

Proven offline by the test suites and locally by the console build; not everything has been run
against live systems. In particular, as of 2026-10-17: the AWS last-used pass has not been run
against a real account, the Zapier connector against a real account, or the Vanta / Drata pushes
against a sandbox; the collector round trip was observed once; the self-hosted stack has never
been booted. [docs/STATUS.md](docs/STATUS.md) keeps the exact list.

Next, in order (strategy §4): ten-minute onboarding polish, pricing and billing with a free tier,
Vanta / Drata control-status pull, SSO, and the remaining atlas items.
