# VectaSec

**A security posture product for the integration layer** — the message brokers, API gateways,
service meshes, event buses, and MCP / agent gateways that connect a company's systems together.
Not a middleware platform: it routes no traffic and brokers no messages. The claim it is growing
into is **the security posture, identity, and governance layer for everything that connects
systems together** ([docs/vectasec-v4-blueprint.md](docs/vectasec-v4-blueprint.md) Part 1).

VectaSec builds a live inventory of what's running and how it's wired, checks each asset against
deterministic detectors, derives the non-human identities behind it all, maps results to
compliance frameworks, and explains findings through a grounded AI — every claim it makes cites a
stored observation, enforced by the database, not by convention.

It ships **two ways from one codebase**:

- **Hosted SaaS** — a multi-tenant control plane on Supabase.
- **On-prem / self-hosted** — the entire stack in the customer's environment. *Written but
  unproven: `deploy/onprem/` validates and has never been booted. See
  [docs/STATUS.md](docs/STATUS.md) before deploying it.*

Collection is read-only, always, over two paths:

- A **customer-side Collector** for private systems (there's no cloud API that returns a
  self-hosted Kafka's ACLs): credentials and raw config stay in the customer's network; only
  findings and resource metadata leave, outbound-only. *Both ends of this loop exist in code; a
  full round trip has not yet been observed — see STATUS.md.*
- An **agentless path via a cross-account read-only role — true today for AWS, and only AWS**:
  one `AssumeRole` connection scans SQS, SNS, EventBridge, MSK, and API Gateway across regions
  with List/Get/Describe calls only. No other provider has an agentless path yet (Azure and GCP
  are on the roadmap; [docs/coverage-matrix.md](docs/coverage-matrix.md) is the honest list).

**Positioning:** we don't sell "middleware security" as a category (no budget line exists). The
wedge is **Non-Human Identity + integration posture** — the service accounts, OAuth clients, ACL
principals, and MCP tools across brokers, gateways, meshes, and agent infrastructure that
CNAPP/API-security tools can't see — with the cross-layer graph as the long-term moat.

## What it does

**Read the Status column, not the prose** — this table is the target product, and two of its
seven rows still have no code. The per-phase breakdown is **[docs/STATUS.md](docs/STATUS.md)**;
where the two disagree, STATUS.md is right.

| Capability | What it does | Status |
|---|---|---|
| **Discovery** | Inventories brokers, topics, gateways, routes, mesh policies, cloud messaging, MCP tools, and how they connect. | ✅ **Built** — resource kinds + graph edges across every connector, plus derived identity/credential/grant kinds and data-classified resources. **Now also finds what you did NOT name**: a `discovery` connector fingerprints middleware from the wire read-only and pre-auth (Kafka ApiVersions, AMQP Connection.Start, Redis PING/INFO, NATS INFO, MQTT CONNACK, memcached, ZooKeeper 4lw, Elasticsearch, etcd, Vault, Consul, Kong Admin, RabbitMQ management, and OpenAPI/GraphQL/MCP descriptors), then correlates the result against your configured connections to surface **shadow middleware nobody is monitoring** (`COVERAGE.SERVICE.UNMONITORED`). Guardrails are the product: declared targets only, private ranges unless public scanning is explicitly declared, a hard host cap, a do-not-contact list (raw-print 9100-9107 and IBM MQ, where connecting is itself the harm), and **no credential is ever sent**. |
| **Posture** | Scores each asset against deterministic detectors with severity, evidence, and remediation. | ✅ **Built** — **129 detectors over 7 connectors**: Kafka, Kong, RabbitMQ, Redis, MCP, **AWS** (SQS/SNS/EventBridge/MSK/API Gateway), **Kubernetes** (Istio/Linkerd/Gateway API/Ingress/RBAC). Continuous: per-connection scheduled rescans (DB-side pg_cron) + posture trend history. Rules that cannot read their evidence file an honest `not_assessable` state — never a silent pass. |
| **Identity (NHI)** | Inventories non-human identities, credentials, and grants; flags over-scoped, default, weak. | ✅ **Built (v1)** — normalized identity/credential/grant model derived from **all 7 connectors** (ACL principals, consumers, service users, OAuth clients, IAM policy principals, ServiceAccounts+RBAC), cross-system `/identities` inventory, OWASP-NHI-aligned detectors. Credentials are metadata only — no secret value is ever read or stored. *Gap: no usage/staleness telemetry yet.* |
| **Supply chain** | SBOM + CVE scan; static analysis of integration-as-code. | ⚠️ **Partial — SBOM/VEX + live OSV feed + plugin inventory built, IaC analysis not.** `GET /reports/sbom` emits a **CycloneDX 1.6** SBOM of the *running* estate — which a build SBOM cannot produce, since Kafka Connect scans `plugin.path` at startup and no build manifest knows what is loaded. Every component carries **both** a PURL and a CPE, because the feeds disagree about coverage: RabbitMQ and NATS are invisible to NVD, Pulsar is invisible to OSV, and one identifier halves the estate. The CPE vendor strings are the ones that actually match (`vmware:rabbitmq`, `redis:redis`, `nats:nats_server`) — the plausible-looking alternatives return zero CVEs rather than an error, which is the worst failure mode a scanner has. Verified live: `pkg:bitnami/rabbitmq@3.13.7` resolves to 3 OSV advisories for a version NVD reports nothing for. The document is honest about itself: `lifecycles.phase` is `operations` only when every version was read by an authenticated connector and downgrades to `discovery` if any came from a probe, inferred versions carry `evidence.identity` confidence, and `compositions.aggregate` declares itself incomplete so a short vulnerability list is never read as safety. VEX support uses **`requires_configuration`** — a justification that exists only in CycloneDX and that only a config-reading scanner can assert — with the config key, observed value, read timestamp, and the change that would invalidate the claim. The OSV feed is now **wired into the scan loop** (`osv.py`, after every scan): each purl-addressable component is checked against `api.osv.dev` with the version inside the purl (OSV does the range matching server-side), advisories are filed as `SUPPLY.OSV.KNOWN_VULNERABILITY` findings with one ledger citation per advisory, advisories already in the curated CVE dataset are deduped rather than double-filed, an unreachable feed files a `SUPPLY.OSV.NOT_ASSESSABLE` coverage gap (never silence, because silence is byte-identical to "checked, clean"), and `VECTASEC_OSV_DISABLED=1` records the air-gapped opt-out. The SBOM's `vulnerabilities[]` section re-expresses those stored findings (plus the curated pack's), so the download and the findings queue cannot disagree. Plugin/extension inventory is also real now: Kafka Connect's `/connector-plugins` (installed classes with the versions they *state* — never inherited from the worker), RabbitMQ's `enabled_plugins` per node, and Kong's `available_on_server`/`enabled_in_cluster` sets. *Not built: IaC/integration-as-code static analysis.* |
| **Compliance** | Maps findings to PCI DSS 4.0.1, DORA, HIPAA, and the MCP spec; human attestation for passes. | ✅ **Wired** — `evaluate()` runs in the same transaction as every scan; a control shows `fail` from findings, `unknown` from coverage gaps, and `pass` **only** from a human attestation (a live failing finding beats a signature). No OSCAL export or Article 28 register yet. |
| **MCP security** | Discovers MCP servers/tools; scans for tool poisoning, auth-spec and transport violations, session hygiene. | ✅ **Built** — 24 rules, speaking **both protocol generations**: the 2026-07-28 stateless revision (`server/discover`) first, with fallback to ≤ 2025-11-25 `initialize`, plus lifecycle rules that flag servers stuck on the superseded spec. No fleet discovery or registry/rug-pull tracking yet. |
| **Runtime** *(optional)* | Evidence of what the estate is actually doing, not just what it permits. | ⚠️ **Partial — agentless half built.** No sensor is required: RabbitMQ's `/api/connections` and Redis' `CLIENT LIST` + `ACL LOG` already name **who is connected right now** (principal, vhost, peer address, SASL mechanism, TLS, last command, denials). That yields live rules — credentials authenticated in cleartext, a default account in active use, an unattributable client, a client from public address space — plus an accumulating `runtime_evidence` table that can eventually say *"this identity has never been observed in use."* That claim is gated: it requires a real observation window (14 days / 20 scans) measured from when observation began on **that** connection, and files a not-assessable finding until then, because absence of evidence is not evidence of absence. *Not built: the optional in-cluster eBPF sensor.* Note eBPF cannot recover Kafka topic metadata for TLS-enabled Java clients at all (the JSSE `SSLEngine` gap), which is why broker-side is the primary path rather than the fallback. |

## Architecture (one line)

A Supabase control plane (Postgres + FORCE-RLS multi-tenancy, Auth, **Vault** for connection
credentials, Realtime, `pgmq` queue, `pg_cron` scheduler) + a Python **engine** (connectors,
detectors, NHI derivation, grounded AI, compliance) + a queue **worker** + a customer-side
**Collector** for private systems. The database enforces the integrity guarantees itself: an AI
output cannot commit without citing evidence, and the evidence ledger is append-only and
hash-chained. **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** is the real map.

## Docs

| Doc | What's in it |
|---|---|
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | How the code that exists actually works — auth matrix, Vault flow, scan pipeline, scheduler. Start here on day one. |
| **[docs/STATUS.md](docs/STATUS.md)** | What is done, partial, and not built, with every claim pointing at a file. Where anything disagrees, STATUS.md is right. |
| **[docs/coverage-matrix.md](docs/coverage-matrix.md)** | The falsifiable coverage matrix: per connector — what it reads, what it emits, every rule pack's honest caveats, and the not-yet-supported list. |
| **[docs/vectasec-v4-blueprint.md](docs/vectasec-v4-blueprint.md)** | The verdict on this codebase and the complete-product blueprint: market bar, connector roadmap, execution order. |
| **[docs/vectasec-build-plan.md](docs/vectasec-build-plan.md)** | The original plan: architecture, trust model, data model, phases. |
| **[docs/research/](docs/research/)** | Sourced research behind the rulepacks, compliance mapping, and console UX. |

## Status

**[docs/STATUS.md](docs/STATUS.md)** (as of 2026-07-23) is the honest breakdown. The short version:

**Works end to end today.** Console: sign in → Connections → connect a system → the scan queues on
`pgmq`, the worker runs it, findings with cited observations land on the page. CLI:
`docker compose up` the misconfigured dev targets → `vectasec scan` → `vectasec findings`.

- **7 read-only connectors, 129 detectors** (counted from the live registry: `vectasec rules`) —
  see [the coverage matrix](docs/coverage-matrix.md)
- **Agentless AWS**: one cross-account read-only role → SQS, SNS, EventBridge, MSK, API Gateway
- **Kubernetes/mesh posture**: one cluster read → Istio, Linkerd, Gateway API, Ingress, RBAC, NHI
- **Continuous scanning**: per-connection cadence, queued by `pg_cron` in the database; posture
  trend history (`posture_snapshots`) with a sparkline on the Overview
- **Verified-token engine auth**: Supabase JWTs (public JWKS) or a scoped engine service token;
  self-asserted headers are a dev-only opt-in, **default off**
- **Connection credentials in Supabase Vault** — `connections.config` holds metadata only;
  secrets are split out per the connector's own field declarations and merged back in memory at
  scan time
- **NHI inventory** across every connector; **data classification** with the toxic-combination
  rule (sensitive-named data on an unauthenticated plaintext broker → critical)
- **Compliance evaluated per scan** with human attestation for passes; append-only,
  **hash-chained** evidence ledger; citation-gated AI triage with a model fallback chain
- Postgres-enforced tenancy: FORCE RLS, SELECT-only browser role, audit row per mutation in the
  same transaction

**Not proven yet** — named plainly because the plan is not the product:

- **The collector round trip has never been observed** (both ends exist in code)
- **The on-prem stack has never been booted** (config-validated only — and written before the
  auth rework; read `deploy/onprem/README.md` first)
- **CI has never been seen green on GitHub**
- **No SSO/SAML/SCIM**, no Slack/Jira/SIEM out (in progress), no iPaaS or Azure/GCP connectors
  yet, no SBOM/CVE scanning, no runtime sensor, **no SOC 2, no design partner, no customer**

## Quickstart

Clone to a cited finding, ~5 minutes.

### Prerequisites

- **Docker** — the dev scan targets
- **[uv](https://docs.astral.sh/uv/)** — the engine is a Python 3.12 uv project
- **Postgres 17** via [Supabase](https://supabase.com) (free tier fine) or self-hosted.
  `pgmq`, `pg_cron`, and `supabase_vault` must be available.
- **Node 20+ / pnpm 9** — only for the console

### 1. Environment

```bash
cp .env.example .env
```

Fill in `DATABASE_URL` and the `SUPABASE_*` values. `ANTHROPIC_API_KEY` is optional — without it
AI triage runs its deterministic fallback. For the console flow, also set `VECTASEC_ENGINE_TOKEN`
to a random secret in both the engine's environment and `apps/web/.env.local` — the engine
requires a verified token by default (see step 7).

### 2. Apply the schema

Apply every migration in `supabase/migrations/` in filename order (SQL editor, `psql`, or
`supabase db push`):

```
20260717000001_core_schema.sql        # tenancy, inventory, graph, scans, findings, evidence
20260717000002_platform_schema.sql    # platform tables, pgmq/pg_cron, RLS, integrity triggers
20260717000003..8                     # fixes, facets, citation-gate completeness, attestations,
                                      # assessability, realtime, hash chain
20260723000001_scheduler_trend.sql    # continuous scanning + posture history
20260723000002_vault_creds.sql        # credentials → Supabase Vault (backfills existing rows)
```

`001` seeds a Demo tenant the CLI defaults to, so you can scan before you have users.

### 3. Start the dev targets

```bash
docker compose -f deploy/dev/docker-compose.yml up -d
```

A deliberately misconfigured Kafka, RabbitMQ, and Redis — each bad value annotated with the rule
it should trigger. Healthy in ~30s.

### 4. Check the wiring

```bash
cd services/engine
uv run vectasec doctor
```

Expect **7 connectors, 129 detectors**, a connected database, `pgmq, pg_cron` present.

### 5. Scan (CLI path)

```bash
uv run vectasec connections add --type kafka --name dev-kafka --bootstrap localhost:9092
uv run vectasec scan --connection dev-kafka

# or ad-hoc; secret fields (passwords, tokens) go to Vault, never into connections.config
uv run vectasec scan --type rabbitmq --url http://localhost:15672 --username guest --password guest
```

One transaction per scan: resources and edges upsert, every matching detector runs, each finding
commits with its cited observation. Findings dedupe on a fingerprint, so re-running is idempotent
and never resurrects what a human resolved.

### 6. See what it found

```bash
uv run vectasec findings      # worst first, with evidence counts
uv run vectasec identities    # the cross-system NHI inventory
uv run vectasec posture       # the score, beside the raw counts it came from
uv run vectasec connections   # the estate: health, resources, open findings
uv run vectasec scans         # history with status and durations
uv run vectasec rules         # the live rulepack
uv run vectasec doctor        # wiring, incl. queue depth
```

### 7. The engine API + worker (needed for the console flow)

```bash
cd services/engine
uv run python -m vectasec.api.main   # http://127.0.0.1:8000, /docs for OpenAPI
uv run vectasec worker               # second terminal: drains the pgmq scan queue
```

(`python -m vectasec.api.main`, not bare `uvicorn` — the module entry point loads `.env`.)
The API accepts **verified tokens only** by default: a Supabase user JWT, or the
`VECTASEC_ENGINE_TOKEN` service token for the console's server side (pin it to one tenant with
`VECTASEC_ENGINE_TOKEN_TENANT`). The old self-asserted-header mode exists solely behind
`VECTASEC_DEV_TRUST_HEADERS=1`, is off by default, and warns loudly when enabled. The API still
binds localhost by default — it holds a BYPASSRLS database connection; keep it off untrusted
networks regardless.

### 8. The console

```bash
cd apps/web
cp .env.example .env.local     # Supabase URL + anon key; add VECTASEC_ENGINE_TOKEN (see step 1)
pnpm install
pnpm dev                       # http://localhost:3000
```

Sign in (email + password; the user needs a `tenant_members` row), then **Connections →
+ Connect a system**. Watch the scan on **Scans**, work the queue on **Findings**, see the estate
on **Assets** and **Identities**. The console never receives `SUPABASE_SERVICE_ROLE_KEY` or
`DATABASE_URL`: it reads Postgres as `authenticated` (SELECT-only, RLS-scoped) and forwards every
mutation to the engine with a server-verified actor. Connection secrets pass through a Server
Action to the engine, land in Vault, and are never readable from the browser afterwards.

### Running the tests

```bash
cd services/engine    && uv run pytest
cd services/collector && uv run pytest
```
