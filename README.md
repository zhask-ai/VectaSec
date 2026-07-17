# VectaSec

**A security posture platform for the integration layer** — the message brokers, API gateways, service meshes, iPaaS/ESB platforms, and MCP / agent gateways that connect a company's systems together.

VectaSec builds a live inventory of everything running and how it's wired, checks each asset against a security benchmark, maps the results to compliance frameworks, and presents findings through an AI assistant that explains and prioritizes them. Detection is deterministic; the AI is grounded — every claim it makes cites a stored observation.

It ships **two ways from one codebase**:

- **Hosted SaaS** — a multi-tenant control plane we run on Supabase; customers connect in minutes.
- **On-prem / self-hosted** — a regulated customer runs the *entire* stack (self-hosted Supabase + our services) in their own environment; nothing leaves their network.

Because the systems being scanned live in private networks with no cloud-API equivalent (there's no `AssumeRole` that returns a Kafka ACL), the **primary** collection path is a lightweight **customer-side Collector** that reads systems locally, keeps their credentials and raw data in the customer's network, and sends only findings outward over an outbound-only channel. Managed middleware (MSK, API Gateway, hosted MCP) can optionally be reached agentlessly via a cross-account read-only role — no install — for a first finding in minutes.

**Positioning:** we don't sell "middleware security" as a category (no budget line yet). The wedge is **Non-Human Identity + integration posture** — the OAuth tokens, service accounts, connectors, and MCP tools across your brokers, iPaaS, gateways, meshes, and agent gateways that Wiz/Salt/CNAPP can't see — with **MCP/agent-gateway security as the fast-growing land-grab** and the Salesloft Drift breach as the cold-open.

## What it does

**This table is the target product, not a description of the code.** Read the Status column, not
the prose — three of these seven rows have no code at all today. The per-phase breakdown is
**[docs/STATUS.md](docs/STATUS.md)**; where the two disagree, STATUS.md is right.

| Capability | What it does | Status |
|---|---|---|
| **Discovery** | Inventories every broker, topic, gateway, route, mesh service, iPaaS recipe, credential, and MCP tool, and maps how they connect. | ⚠️ **Partial** — 12 resource kinds across Kafka/Kong/RabbitMQ/MCP. No mesh service, iPaaS recipe, or credential kind. Kong/RabbitMQ/MCP emit graph edges; **Kafka emits none**, so "maps how they connect" is empty on the one end-to-end target. |
| **Posture** | Scores each asset against a security benchmark (Kafka ACLs, Kong auth, Istio mTLS, …) into findings with severity and remediation. | ✅ **Built** for Kafka, Kong, RabbitMQ, MCP — 73 detectors, severity + remediation. **No Istio.** |
| **Identity** | Inventories non-human identities and OAuth grants; flags over-scoped, stale, or leaked credentials and their blast radius. | ❌ **Not built.** No code. This is the positioning wedge above and it does not exist. |
| **Supply chain** | SBOM + CVE scan of connectors/images/deps; static analysis of integration-as-code (DataWeave, gateway policies, workflow JSON, MCP manifests). | ❌ **Not built.** No SBOM, no CVE scan, no IaC static analysis. (Some RabbitMQ rules read a version string — a version check, not a CVE scan.) |
| **Compliance** | Maps findings to PCI DSS 4.0.1, DORA, HIPAA, NIS2; generates audit evidence and the DORA Article 28 register. | ⚠️ **Mapping only.** The PCI/DORA/HIPAA/NIS2 mapping is written and sourced, but **nothing calls the evaluator**, so the `controls` table is always empty and the compliance page renders empty. No Article 28 register, no OSCAL export. |
| **MCP security** | Discovers MCP servers/tools and agent gateways; scans for tool-poisoning and auth-spec violations; ties each tool to the middleware it wraps. | ⚠️ **Mostly built** — 19 rules: tool-poisoning, auth-spec, transport, session. Spec pinned to `2025-11-25`. "Ties each tool to the middleware it wraps" needs the graph and is **not** done. |
| **Runtime** *(optional)* | In-cluster sensor for east-west traffic, egress anomalies, and attack paths. | ❌ **Not built.** No sensor. |

## Architecture (one line)

A Supabase-backed control plane (Postgres + RLS multi-tenancy, Auth/SSO, Storage, Realtime, `pgmq` queue, Vault) + a Python **engine** (connectors, deterministic detectors, grounded AI, compliance) + a customer-side **Collector** for private systems. Runs as multi-tenant SaaS or fully on-prem from the same artifacts. Credentials for private systems never leave the customer's environment.

*That is the target. Postgres + RLS, Auth (email+password sign-in), and `pgmq` are real today; SSO, Storage, and Vault are not, and the Collector cannot yet reach the control plane. The on-prem path is **written but unproven**: `deploy/onprem/` is a complete 8-service self-hosted stack (Postgres, auth, rest, realtime, engine, web, Caddy) plus a Helm chart, and its compose file validates — but nobody has ever booted it, so treat it as untested. See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for what is built and **[docs/STATUS.md](docs/STATUS.md)** for the gap.*

## Docs

| Doc | What's in it |
|---|---|
| **[docs/vectasec-build-plan.md](docs/vectasec-build-plan.md)** | The plan: product critique, market analysis, target architecture, credential/trust model, data model, pricing hypothesis, phases. |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | How the code that exists actually works. Start here on day one. |
| **[docs/STATUS.md](docs/STATUS.md)** | What is done, partial, and not built — mapped to the plan's phases, with the known gaps named. |
| **[docs/research/](docs/research/)** | Sourced research behind the rulepacks, compliance mapping, and console UX. |

## Status

Phase 0 is substantially done; parts of Phase 1–3 were built out of order (the rulepacks ran ahead of the plumbing). **[docs/STATUS.md](docs/STATUS.md)** is the honest, per-phase breakdown. The short version:

**Works end to end today.** `docker compose up` a deliberately misconfigured Kafka → `vectasec scan` → deterministic detectors → findings with cited observations committed to Postgres in one transaction → `vectasec findings`. That path is real and reproducible on a laptop in about five minutes.

- 4 read-only connectors (`kafka`, `kong`, `rabbitmq`, `mcp`) and 73 detectors
- A passing offline unit suite (`uv run pytest` in `services/engine` and `services/collector`) — detector, redaction, scan-logic and AI-citation-gate level, plus CI jobs for cross-tenant RLS and the integrity triggers; see gaps below
- Schema with `FORCE RLS` on 18 tenant tables; the citation gate (no `ai_output` commits without citing an observation of its own tenant) and the append-only evidence ledger (`observations` and `audit_log` reject UPDATE) are enforced by Postgres triggers, not by application code — and attacked in CI, including via the engine's own write path. What the ledger does **not** stop is DELETE, so a holder of the engine's DB credential can still delete-and-reinsert an observation; see [docs/STATUS.md](docs/STATUS.md) *Known gaps*
- Grounded AI triage: structured-output citations, range-checked, with a deterministic fallback and a fingerprint cache
- FastAPI engine for actions (status / assign / suppress / triage), one audit row per mutation, in the same transaction
- Next.js console: server-rendered, reads Supabase under RLS, forwards every mutation to the engine

**Not built yet.** Named plainly because the plan is not the product:

- **Console sign-in is a placeholder** — every route redirects to `/login`, which says so. The console does not currently render real data for a normal user.
- **No queue worker** — `POST /scans` enqueues to `pgmq` and nothing consumes it; queued scans stay `queued`. The working path is `inline: true` and the CLI.
- **Collector has no control plane** — the agent's code and tests exist, but the `/collector/*` endpoints it enrolls and polls against do not. Only `check` and `preview` work.
- **Compliance is never evaluated** — the rule→control mapping is written but nothing calls it, so the `controls` table is always empty and the compliance page renders empty.
- **Engine API auth is self-asserted headers** (dev stand-in, binds to localhost). Any caller can name any tenant and any actor.
- **No Identity / NHI capability at all** — no non-human-identity inventory, no OAuth-grant blast radius, no workload-identity audit. This is the wedge in the positioning line above and it has zero code.
- **No supply chain capability at all** — no SBOM, no CVE scan, no integration-as-code static analysis (DataWeave, gateway policies, workflow JSON).
- **No DORA Article 28 register and no OSCAL export.**
- **No runtime sensor** — the optional Runtime row is unstarted.
- **No Istio, iPaaS, or mesh connectors** — the 4 connectors are Kafka, Kong, RabbitMQ, MCP.
- **The Kafka connector emits no graph edges**, so blast radius on the one end-to-end target is a single node.
- No agentless cross-account role, no Slack/Jira, no SSO/RBAC, no SOC 2.
- **The on-prem path is config-validated but never booted** — `deploy/onprem/` has Compose + a Helm chart that lint clean, but the stack has never been started and it ships with the self-asserted-header cross-tenant hole above. See [deploy/onprem/README.md](deploy/onprem/README.md) before deploying anything.

## Quickstart

Gets you from clone to a cited finding. ~5 minutes.

### Prerequisites

- **Docker** — runs the dev scan target
- **[uv](https://docs.astral.sh/uv/)** — the engine is a Python 3.12 uv project
- **Postgres 17** — a [Supabase](https://supabase.com) project (free tier is fine) or self-hosted Supabase. `pgmq` and `pg_cron` must be available.
- **Node 20+ / pnpm 9** — only if you want the console

### 1. Environment

```bash
cp .env.example .env
```

Fill in `DATABASE_URL` (Supabase → Settings → Database) and the `SUPABASE_*` values. `ANTHROPIC_API_KEY` is optional — without it the AI layer runs its deterministic fallback and nothing else changes. `.env` is gitignored; never commit it.

The `vectasec` CLI and the engine API find `.env` by searching upward from the working directory, so they work from `services/engine`. Only those two entry points load it: importing `vectasec` as a library does not touch `os.environ`, because the Collector imports the engine and reads its own security posture from the environment (see `services/engine/src/vectasec/config.py`).

### 2. Apply the schema

Two migrations, in order, against your database — via the Supabase SQL editor, `psql`, or `supabase db push`:

```
supabase/migrations/20260717000001_core_schema.sql     # tenancy, inventory, graph, scans, findings, evidence
supabase/migrations/20260717000002_platform_schema.sql # platform tables, pgmq/pg_cron, RLS hardening, the two integrity triggers
```

`001` seeds a Demo tenant (`00000000-0000-0000-0000-000000000001`) that the CLI defaults to, so you can scan before you have any users.

### 3. Start the dev target

A single-node Kafka wired with real, deliberate misconfigurations — each one annotated with the rule it should trigger. It is the fixture for the end-to-end proof, not a deployment of VectaSec.

```bash
docker compose -f deploy/dev/docker-compose.yml up -d
```

It seeds topics (`payments`, `customer-pii`, `orders`, …) and is healthy in ~30s.

### 4. Check the wiring

```bash
cd services/engine
uv run vectasec doctor
```

Expect 4 connectors, 73 detectors, a connected database, and `pgmq, pg_cron` present. If this is unhappy, nothing below will work.

### 5. Scan

```bash
uv run vectasec scan --type kafka --bootstrap localhost:9092
```

The whole scan is one transaction: resources and edges upsert, every detector runs against every matching resource, and each finding writes its triggering observation to the evidence ledger alongside it. Findings dedupe on a fingerprint of `(tenant, rule_id, ext_id)`, so re-running this is idempotent and never resurrects a finding a human resolved.

### 6. See what it found

```bash
uv run vectasec findings   # findings for the tenant, worst first, with evidence counts
uv run vectasec rules      # the loaded rulepack — every rule, severity, and target kind
uv run vectasec doctor     # engine + database wiring
```

`--json` on `scan` prints the stats blob. `--tenant <uuid>` targets a tenant other than Demo.

### 7. The engine API (optional)

Needed only for actions — status, assign, suppress, AI triage — and for the console's mutations.

```bash
cd services/engine
uv run python -m vectasec.api.main   # http://127.0.0.1:8000, /docs for the OpenAPI UI
```

It binds to localhost on purpose: it holds a `BYPASSRLS` database connection and its auth is a self-asserted header. Do not expose it.

### 8. The console (optional)

```bash
cd apps/web
cp .env.example .env.local     # NEXT_PUBLIC_SUPABASE_URL + NEXT_PUBLIC_SUPABASE_ANON_KEY only
pnpm install
pnpm dev                       # http://localhost:3000
```

**Read this before you spend time on it:** sign-in is not implemented. `proxy.ts` redirects anonymous traffic to `/login`, and `/login` is a placeholder that says as much — so a fresh `pnpm dev` dead-ends there. The pages behind it are built and server-rendered, but reaching them needs a Supabase Auth session plus a `tenant_members` row linking that user to a tenant. See [docs/STATUS.md](docs/STATUS.md).

The console never receives `SUPABASE_SERVICE_ROLE_KEY` or `DATABASE_URL`. It reads Postgres as `authenticated` (SELECT-only, RLS-scoped) and forwards every mutation to the engine API.

### Running the tests

```bash
cd services/engine    && uv run pytest
cd services/collector && uv run pytest
```
