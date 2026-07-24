# VectaSec — Architecture

How the system that **exists** works. For what's planned but absent, see [STATUS.md](STATUS.md);
for why any of it exists, see [vectasec-build-plan.md](vectasec-build-plan.md) and
[vectasec-v4-blueprint.md](vectasec-v4-blueprint.md). Where the two disagree, this file is right
and the plan is aspiration. Per-connector coverage and its honest caveats live in
[coverage-matrix.md](coverage-matrix.md).

Read this first, then read `scan.py` and `connect/kafka.py`. Those two files teach the rest.

---

## 1. The shape

Four pieces, one Python package shared by two of them.

```
  apps/web (Next.js console)
      │  reads: SELECT-only under RLS, straight to Supabase/PostgREST
      │  mutations: engine API only, authenticated with the engine service
      │  token (or a user JWT) — never a DB write from the console
      ▼
  services/engine (the product)
      connect/  detect/  scan.py  identity.py  classify.py  ai.py  graph.py
      compliance/map.py  creds.py  worker.py  api/ (FastAPI)
      │  read-only collection ─▶ Kafka / Kong / RabbitMQ / Redis / MCP
      │                          AWS (cross-account AssumeRole) / Kubernetes
      │  BYPASSRLS psycopg ────▶ Supabase Postgres (+ Vault, pgmq, pg_cron, Realtime)
      ▲
      │  /collector/* — HMAC service token, outbound-only long-poll
  services/collector (customer-side)
      imports the engine's connect/ + detect/ unmodified; redact() at the exit;
      pushes findings + resource METADATA, never Resource.raw.
      ⚠ Both ends exist; a full enroll → poll → scan → push round trip has not
        been OBSERVED against a live engine. See STATUS.md.
```

The engine package is the product. The console is a view of its output. The collector is the same
engine code with a different topology and a redaction boundary bolted to its exit. The database is
not passive: pg_cron schedules scans, a trigger snapshots posture history, and constraint triggers
enforce the two integrity guarantees (§2) — those behaviors live in `supabase/migrations/`, not in
any service.

**Repo layout** (actual):

```
services/engine/src/vectasec/
  contracts.py      Resource, Edge, Collected, Hit, ScanContext — the shapes everything speaks
  registry.py       @connector / @detector decorators, ConnectorField specs, the registries
  scan.py           the scan loop: collect → detect → persist → compliance. The spine.
  identity.py       NHI derivation: connector output → identity/credential/grant resources
  classify.py       data-classification (DSPM) tagging
  creds.py          Supabase Vault split/merge for connection credentials (§5)
  worker.py         pgmq consumer: adopts queued scans, poison-message cap, stuck-scan reaper
  ai.py             grounded triage + model fallback chain + deterministic fallback + cache
  graph.py          blast radius / neighbours / exposure paths — THE one graph implementation
  compliance/map.py rule → framework control mapping + evaluate(), called per scan
  api/main.py       FastAPI: actions + scan orchestration + collector control plane
  api/auth.py       Supabase JWT verification (JWKS) + collector HMAC service tokens
  connect/          one file per system: kafka, kong, rabbitmq, redis, mcp, aws, k8s
  detect/           one rulepack per system + cross-cutting identity.py, data.py
services/collector/src/collector/
  main.py           enroll → heartbeat → long-poll → run locally → redact → push
  config.py         targets.json + ${ENV_VAR} credential refs
  redact.py         the payload boundary
apps/web/           Next.js 16 console
supabase/migrations/  ten files, 20260717000001 … 20260723000002 — the schema IS behavior here
deploy/dev/docker-compose.yml   deliberately misconfigured Kafka + RabbitMQ + Redis — scan targets
deploy/onprem/      self-hosted stack: Compose + Caddy + Helm. Config-validated, NEVER BOOTED,
                    and written BEFORE the auth rework — read its README with that in mind.
```

---

## 2. The schema, and the guarantees Postgres enforces

`20260717000001` core spine (tenancy, inventory, graph, scans, findings, observations);
`20260717000002` platform layer + RLS hardening + the original triggers; `003` pipeline fixes;
`004` findings facets; `005` citation-gate completeness; `006` foundation (attestations,
assessability, Realtime publication, the observation hash chain); `007` compliance unknown-state;
`008` ledger FK housekeeping; `20260723000001` scheduler + posture history (§10);
`20260723000002` Vault credentials (§5).

### Guarantee 1 — the citation gate

> An `ai_outputs` row cannot exist in a committed transaction without citing at least one
> `observations` row **of its own tenant**.

Deferred constraint triggers on both `ai_outputs` and `ai_output_evidence` (002 + 005).
`DEFERRABLE INITIALLY DEFERRED` is the whole trick: the natural write order (output first, then
its evidence links) would be rejected by a non-deferred trigger; deferring the check to `COMMIT`
lets the transaction assemble a complete, cited output. 005 exists because "uncited output" is a
*state* and the original gate checked one *event* — the evidence-DELETE, observation-cascade, and
`ON CONFLICT DO UPDATE` paths (the engine's own write path) all walked around it, and a fourth
hole let tenant A cite tenant B's observation. All four attacks run in CI. This is why
`ai.triage_finding()` takes an open cursor: the caller owns the transaction, so output and
citations commit together or not at all.

### Guarantee 2 — the evidence ledger: append-only, and now hash-chained

> An observation's evidence can never be UPDATEd — and a delete/reinsert/reorder is **detectable**.

Two layers, added in that order:

- **Append-only** (002, narrowed by 008): UPDATE on `observations` and `audit_log` is rejected by
  trigger. 008 narrows the block to the *evidence* fields — Postgres's own `ON DELETE SET NULL` on
  `observations.resource_id` was being rejected too, which broke resource churn and offboarding;
  the FK pointer is bookkeeping, not evidence. DELETE stays allowed (offboarding, FK cascades):
  retention is a policy question, mutation is an integrity question.
- **Hash chain** (006): each observation's `row_hash` commits to its claim and its position over
  the previous observation of the same finding (`prev_hash`). Delete-and-reinsert at the same id —
  the classic bypass of an UPDATE-only guard — now breaks the chain, and `verify_ledger()` reports
  the first broken link per finding. Honest limits: rows written before 006 carry no hash and are
  excluded (stated in the migration); the function **detects** tampering, it does not prevent it;
  and nothing currently schedules or exposes `verify_ledger()` — checking is a manual query today
  (STATUS.md gap). The claim to an auditor is "tamper-evident from 006 forward, if you run the
  check", and nothing stronger.

### The third outcome: assessability (006)

A detector has three honest answers: this is wrong (a finding), this is fine (no finding), or
**I could not tell**. `findings.assessment` (`assessed` / `not_assessable`, with a reason) is the
third one as a state instead of prose. The AWS pack files it when an API call is AccessDenied, the
K8s pack when RBAC hides a resource type, the RabbitMQ pack when the credential can't read part of
the surface. The console renders it distinctly and `compliance/map.py::evaluate()` maps it to
`unknown` — never `fail`, never a silent pass.

### RLS and the trust model

Migration 002 runs `ENABLE` + `FORCE ROW LEVEL SECURITY` over the tenant tables (and every later
tenant table, e.g. `posture_snapshots`, follows suit) and grants `authenticated` a **SELECT policy
and nothing else**. `app_tenant_ids()` is the pivot: `SECURITY DEFINER`, pinned `search_path`;
`tenant_members_select` scopes on `user_id = auth.uid()` directly and must never call it (policy
recursion).

The engine connects as `postgres` and **bypasses RLS entirely**. In `api/main.py`, `graph.py`, and
`scan.py`, a missing `and tenant_id = %s` is a cross-tenant leak, not a bug. RLS is not a backstop
server-side; the predicates in those files are the only thing between two customers' estates.

---

## 3. Who is calling — the auth matrix

`api/main.py::principal()` + `api/auth.py`. Nothing self-asserted is trusted by default. Three
paths, checked in this order:

| Path | Credential | Verified how | Tenant comes from | Actor comes from | Intended caller |
|---|---|---|---|---|---|
| 1 | `Authorization: Bearer <engine-token>` | constant-time compare against `VECTASEC_ENGINE_TOKEN` (unset ⇒ path disabled) | `VECTASEC_ENGINE_TOKEN_TENANT` if set (a mismatched header is 403); else the `X-VectaSec-Tenant` header, asserted by the authenticated *service* | `X-VectaSec-Actor`, the service's server-confirmed user id | the console's server side (`apps/web/lib/engine.ts`, which verifies the user and derives the tenant under RLS before calling) |
| 2 | `Authorization: Bearer <supabase-jwt>` | signature against the project's **public JWKS** (ES256/RS256; `aud=authenticated`, `exp`, `sub` required — `api/auth.py::verify_supabase_jwt`) | resolved from `tenant_members` for the token's `sub`; a requested tenant the user doesn't belong to is 403; membership in none is 403, in several without naming one is 400 | the token's `sub` | end users / anything holding a real session |
| 3 | bare `X-VectaSec-*` headers | **none** — accepted only when `VECTASEC_DEV_TRUST_HEADERS` is explicitly truthy; the default is OFF with no localhost carve-out, and enabling it prints a wall-of-text startup warning | the header | the header | a single-operator dev loop, nothing else |
| — | `Authorization: Bearer <collector-token>` on `/collector/*` only | stateless HMAC over `{tenant, collector, exp}` with a server-side secret (`api/auth.py::mint_collector_token` / `verify_collector_token`), minted at `/collector/enroll`, short-lived, memory-only on the client | inside the signed token | the collector id | the customer-side collector |

Mutating endpoints additionally require a non-empty actor (`acting()`): an unattributed write is
refused rather than recorded anonymously, because the audit row is written in the same transaction
as every mutation.

**The honest caveat on path 1** (also STATUS.md gap #2): the engine token authenticates the
*calling service*, which is then trusted to assert the acting user and (unless pinned) the tenant.
A compromised token-holder can forge any actor into the audit trail. It is transitional — the end
state is per-user JWTs on every console call — and it is why `VECTASEC_ENGINE_TOKEN_TENANT`
pinning exists for single-tenant deployments.

---

## 4. The scan pipeline

`scan.py::run_scan(type_, config, tenant_id, connection_name, mode)`.

```
ensure_connection_with_creds   upsert the connections row; split declared secrets → Vault (§5)
insert scans (status='running'), COMMIT   ── collect happens OUTSIDE the write critical section
resolve_secrets + runtime_config          ── Vault secrets merged into config IN MEMORY only
CONNECTORS[type](config) → Collected(resources, edges)
    on exception: mark the scan 'error' on its own transaction, re-raise
_enrich_collected      identity.py derivation + classify.py tagging appended to the collection
_persist_resources     upsert on (connection_id, ext_id); anything absent now → stale = true
_persist_edges         delete this connection's edges, re-insert; unresolvable endpoints dropped
for d in DETECTORS: for r in resources of d.kinds:
    hits = d.fn(r, ctx)          ← one detector raising is caught, recorded, skipped
    upsert findings on (tenant_id, fingerprint)   +   insert observations — same transaction
compliance.evaluate(cur, tenant_id)   ← recomputed IN the scan's transaction, so `controls`
                                        can never lag the findings it derives from; an evaluate
                                        failure is recorded in stats, never voids the scan
update scans (status='done', stats);  insert audit_log;  COMMIT — one transaction
```

The same tail (persist → compliance → commit) runs for collector-pushed results
(`scan.py::persist_pushed`).

Decisions worth understanding before touching this file — unchanged from day one:
**fingerprint dedup** (`fingerprint(tenant_id, connection_id, rule_id, ext_id)` — same real-world
problem across 100 scans is ONE row; triage state survives rescans; `LiveFindings.tsx` depends on
INSERT meaning "genuinely new"); **evidence written with the finding, never after**; **one
transaction per scan**; **stale, not deleted**; **suppressions applied by the scan loop** — a new
suppression bites at the next scan and `POST /suppressions` says so.

---

## 5. Credentials: the Vault flow

`creds.py` + migration `20260723000002`. The rule: **`connections.config` holds metadata only;
anything a connector declares `secret=True` lives in Supabase Vault.**

- **The connector's own field spec is the authority.** `registry.ConnectorField(secret=True)`
  (e.g. `rabbitmq.password`, `aws.secret_access_key`, `k8s.token`; kafka declares none) drives the
  split — there is no second list to maintain, so a new connector's secrets are Vault-handled the
  moment it declares them.
- **Write path** (`creds.split_config` → `store_secrets`, called from the API, the CLI, and
  `run_scan` itself): secret fields are stripped from the submitted config and stored as **one**
  Vault secret per connection (`vectasec/connection/<id>`, a JSON object of the secret fields);
  `connections.creds_ref` holds the `vault.secrets.id`. Same transaction as the connection row —
  a row and its secret commit or fail together. An empty secret on a re-submitted form means
  "unchanged" (merge), not "empty password".
- **Read path** (`resolve_secrets` → `runtime_config`): at scan/test time the secrets are read
  from `vault.decrypted_secrets` and merged into the in-memory config handed to the connector.
  They exist joined-together only inside the process about to dial the target. Nothing logs,
  returns, or persists them; audit rows record config **keys** only.
- **Delete path**: `delete_secret` in the same transaction as the connection delete — an orphaned
  credential is pure risk.
- **Queue hygiene**: pgmq job payloads carry the public config only. Messages enqueued *before*
  the migration may persist secrets in pgmq's archive table; the migration header documents the
  purge (`delete from pgmq.a_vectasec_scans`).

What this protects against: any read of `connections` (a dump, PostgREST, a misissued read
credential) sees hosts and usernames, never passwords. What it does not: the engine's own role can
read `vault.decrypted_secrets` — Vault moves the boundary from "anyone who can read the table" to
"the key-holding extension path", it does not make the engine unable to read what it must use.

---

## 6. The registry, and the fan-out connector pattern

`registry.py`. Two decorators, module-level registries, no central list. Registration happens on
import; every entry point does `from . import connect as _connect  # noqa: F401` — that `noqa` is
load-bearing. **To add a detector: drop a file in `detect/`.** That is the entire process.

The contracts (`contracts.py`): `Resource` (kind/name/`ext_id`/labels/raw), `Edge` (by ext_id,
resolved at persist, unresolvable = dropped), `Hit` (severity override, `assessable` +
`assessment_reason` for the third outcome), `ScanContext` (every resource in the scan —
cross-resource rules like "this topic is exposed *because* its broker is PLAINTEXT").

`Hit.observation` is the load-bearing field: the exact string in the immutable ledger and the only
thing the AI may cite. It states a fact with the observed value in it, never a conclusion.
Connectors record the *outcome*, not just the result (`ok` / `security_disabled` / `error` /
`access_denied`) — an empty ACL list must never be read as "no authorizer", and "not read" is
distinguishable from "read, empty".

**The fan-out pattern** (`connect/aws.py`, `connect/k8s.py` — the shape every wide connector
should copy): one connection, many surfaces, honest per-surface failure.

- **One credential fans out**: AWS reaches SQS + SNS + EventBridge + MSK + API Gateway per region
  from a single role; K8s reaches core + RBAC + Istio + Linkerd + Gateway API from one cluster
  read. The connector, not the user, does the enumeration.
- **Per-surface error isolation**: each (service, region) or CRD-group collection runs in its own
  try/except. A denied `kafka:ListClusters` or a 403 on `security.istio.io` records an outcome on
  the umbrella resource (`aws_account`, `k8s_cluster`) instead of voiding the scan — and the
  rulepack turns it into a `not_assessable` coverage-gap finding. A 404 on a CRD group means "not
  installed": fewer kinds, no error.
- **Distinct kinds, always** (`aws_sqs_queue`, `mesh_gateway`, …) so no other rulepack ever runs
  against these resources by accident — the same reason `connect/redis.py` refused to reuse
  `broker`.
- **Pure parse layer**: boto3 dicts / cluster snapshots in, `Resources` out, tested offline
  against golden fixtures (`tests/fixtures/aws_responses.json`). A shape drift between connector
  and rulepack fails a test instead of silently mis-firing — and the SDK stays out of the suite.
- **NHI comes with it**: an `@identity_extractor` per connector (inline for aws/k8s, in
  `identity.py` for the rest) means every new connector feeds the identity plane on day one.

Current coverage: **7 connectors, 129 detectors** (AWS 21, MCP 24, KAFKA 20, K8S 18, RABBITMQ 18,
KONG 16, REDIS 6, + cross-cutting NHI 4 and DATA 2). `uv run vectasec rules` prints the live
rulepack; [coverage-matrix.md](coverage-matrix.md) is the per-connector statement with caveats.

---

## 7. The Collector's trust model

`services/collector/src/collector/main.py`, runs inside the customer's network. Three properties:

1. **Outbound only.** No `bind()`, no `listen()`, no port. Jobs are pulled via long-poll against
   `/collector/jobs`; the engine parks the connection until a job exists.
2. **Credentials stay local.** `${ENV_VAR}` refs in `targets.json`, used in-process, never
   serialised outbound. The enrollment token is not kept at rest (state file stores its sha256);
   the service token it buys is a short-lived HMAC token (§3) held in memory only.
3. **Raw config stays local.** Connectors *and* detectors run in the collector; `Resource.raw`
   never enters the outbound payload. What leaves is findings, observations, resource metadata,
   edges — `redact()` is the single exit boundary, and `vectasec-collector preview` prints exactly
   what would be pushed so an operator can read it instead of trusting us.

A job is a *reference* (`{"target": "prod-kafka"}`) that must already exist in the collector's
local config — the control plane can never aim the collector at a host of its choosing while it
holds the customer's credentials. Fingerprints are computed with the engine's `fingerprint()`,
imported not reimplemented, so migrating a system from cloud path to collector keeps its triage
history.

The engine side (`/collector/enroll|heartbeat|jobs|results` in `api/main.py`) exists: HMAC
service tokens, tenant-scoped job claiming with `skip locked`, a results path that persists
through the same `persist_pushed` tail as any scan (compliance recompute included) and never
receives `Resource.raw`. **What has not happened: a real collector observed completing the round
trip against a live engine.** Until then, treat the loop as untested integration ([STATUS.md](STATUS.md)).

---

## 8. Grounded AI

`ai.py`. The premise: an LLM that confidently narrates a finding it cannot substantiate is worse
than no LLM. Four mechanisms, in increasing order of strength: (1) the model gets only this
finding's observations, numbered, citations enforced by structured-output schema; (2) every
citation is range-checked — one invented index discards the whole output; (3) Postgres refuses to
commit an uncited output (§2); (4) refusals are a normal outcome, not a crash.

Availability is a *chain*, not a pin: `MODELS` lists a primary (overridable via
`VECTASEC_AI_MODEL`) and fixed alternates; an overloaded model hands off to the next before
anything falls back to the deterministic `_rule_based` summary — which cites trivially, labels
itself, and runs with no API key at all. The `ai_outputs` cache is unique on
`(tenant_id, kind, fingerprint)`: one explanation per finding-class, ever.

Injection honesty: observation text quotes scanned systems verbatim, and scanning hostile systems
is the product — MCP metadata, AWS policy documents, K8s annotations are all attacker-influencable
prose that lands in the prompt. Claims are fenced in unclosable `<observation>` elements, capped,
and the system prompt calls an embedded "known false positive" note evidence of tampering — but
that is mitigation, not proof. The deterministic severity, not the AI priority, is what the
findings list sorts and filters on; AI priority appears only on the detail page inside a labelled
provenance fence. Do not let anything route or alert on model-owned `priority` before reading
STATUS.md gap #5.

---

## 9. The API

`api/main.py`. FastAPI. **No list endpoints, on purpose** — the console reads Supabase directly
under RLS; this service only changes state or starts work, which needs what RLS cannot give: an
authenticated actor (§3) and an audit trail.

Surface: `GET /health`; `POST /scans` (inline or enqueued to pgmq in the same transaction as the
scans row); `GET /scans/{id}`; connection lifecycle (`GET /connectors` from the registry,
`POST /connections` with declared-field validation + Vault split, `POST /connections/{id}/test`
via the real collect path, `POST /connections/{id}/scan`, `DELETE /connections/{id}`); finding
actions (`status`, `assign`, `triage`); `POST /suppressions`;
`GET /compliance/{framework}` + `POST /compliance/{framework}/{control_id}/attest`;
`GET /graph/blast-radius/{id}` (delegates to `graph.py` — one implementation, cycle-guarded,
`depth_bounded` honesty flag); the `/collector/*` control plane (§7).

Rules this file lives by: every statement filters `tenant_id` explicitly (BYPASSRLS role); every
mutation writes its audit row in the same transaction; status transitions take `FOR UPDATE`;
`suppressed` is not a settable status (suppressions carry reason + expiry and apply at the next
scan); handlers are sync `def` (psycopg blocks; FastAPI threadpools sync handlers).

---

## 10. The scheduler and posture history (DB-side, deliberately)

Migration `20260723000001`. Both features live in the database because their inputs and outputs
do: the queue contract already exists between `api/main.py::_enqueue_scan` and
`worker.py::parse_job`, and the migration *reproduces* it rather than inventing a second path.

**Scheduler.** `connections.scan_interval_minutes` (NULL = point-in-time only — absence is a
meaningful state, not a default) + `queue_due_scans()`, run by pg_cron every minute. For each
active, due connection it inserts the same `queued` scans row `POST /scans` writes and — cloud
mode only — sends the same pgmq payload; collector-mode connections get only the row, which the
enrolled collector claims via `GET /collector/jobs` (same rule as the API: pgmq must never hand a
cloud worker a job whose target it cannot reach). Due = interval elapsed since the later of
`last_queued_at` and `last_scanned_at` (a manual "Scan now" resets the clock); a queued/running
scan blocks re-queueing; `FOR UPDATE SKIP LOCKED` keeps overlapping cron ticks from double-queueing.
The function is `revoke`d from public — the browser cannot queue work by calling it.

⚠ **The payload shape is a hand-mirrored contract.** `queue_due_scans()` must build exactly what
`worker.py::parse_job` validates — anything else is archived as poison. A change to
`_enqueue_scan`'s payload **must** change the SQL twin in the same commit (STATUS.md gap #7 asks
for the test that enforces this).

**Posture history.** `posture_snapshots` gets one row per scan transitioning to `done` (an
`AFTER UPDATE OF status` trigger — every completion path is such an UPDATE), throttled to one per
tenant per 5 minutes so a scheduler burst records one honest point. The console's Overview renders
the trend (`PostureTrend` in `app/page.tsx`); RLS: SELECT-only for members, written only by the
trigger as `postgres`.

⚠ **The formula lives in two places and must change in lockstep.** `snapshot_posture()` mirrors
`apps/web/lib/posture.ts` digit-for-digit: `weighted = 10·crit + 4·high + 1.5·med + 0.5·low` over
open findings (info excluded), `score = 100` when weighted = 0 else
`max(1, round(100·(1 − weighted/(weighted+40))))` — and SQL `round(numeric)` matches JS
`Math.round` for positive inputs by rounding half away from zero. If you touch the weights, the
curve, or the rounding in **either** place, change the other in the same commit, or the sparkline
and the live score silently diverge — in the product whose pitch is that its numbers are
checkable. (Gap #6 in STATUS.md asks for the shared-fixture test.)

---

## 11. The console

`apps/web` — Next.js 16, React 19, server components. Routes: `/`, `/findings`, `/findings/[id]`,
`/assets`, `/assets/[id]`, `/identities`, `/connections`, `/scans`, `/compliance`, `/login`.

### Reads go to Supabase. Actions go to the engine. Never the reverse.

**Reads** — `lib/supabase/server.ts`, `server-only`, anon key, `authenticated` role: SELECT-only,
RLS-scoped. Pages don't filter by tenant — RLS does. The console must never receive
`SUPABASE_SERVICE_ROLE_KEY` or `DATABASE_URL`. List pages read a bounded page (`LIST_LIMIT`) plus
`count: 'exact'` head-counts, so totals are never a JS tally of a silently capped array — and the
UI says what it is not showing.

**Actions** — Server Actions → `lib/engine.ts` (`server-only`, URL not `NEXT_PUBLIC_`) → the
engine API, authenticated with the engine service token (§3 path 1) and carrying the
server-verified tenant/actor. The browser cannot reach that file, see the URL, or influence the
headers.

### Three layers of auth; only one is load-bearing

1. `proxy.ts` refreshes sessions and redirects anonymous users — **not** an authorization boundary.
2. Every Server Action re-verifies with `getVerifiedUser()` (a revocation-checking network hop,
   not a signature check) and then reads the target row **under RLS** — the IDOR check.
3. **RLS is the actual guarantee.**

### Design constraints worth knowing

- **`LiveFindings.tsx`** shows a pill, not an auto-refresh (re-sorting under an analyst's cursor
  invites a click on the wrong finding). Its DB prerequisite — `findings`/`scans` in the
  `supabase_realtime` publication — landed in migration 006; live delivery has still not been
  *observed*, and the component fails silent by design, so verify before relying on it.
- **`/compliance`** scores over evaluated controls only; a pass requires a human attestation
  (`control_attestations`), a live failing finding beats an attestation, `0/0` renders "Not
  scored", never 100%.

---

## 12. Day-one checklist

```bash
cd services/engine
uv run vectasec doctor                                       # 7 connectors, 129 detectors, DB, pgmq+pg_cron
docker compose -f deploy/dev/docker-compose.yml up -d        # misconfigured Kafka + RabbitMQ + Redis
uv run vectasec scan --type kafka --bootstrap localhost:9092
uv run vectasec findings                                     # cited findings
uv run vectasec rules                                        # the rulepack
uv run pytest                                                # the offline suite
```

Then read, in this order: `contracts.py` → `registry.py` → `connect/kafka.py` → `scan.py` →
one detector in `detect/kafka.py` → `connect/aws.py` (the fan-out pattern) → `ai.py`. Then
[STATUS.md](STATUS.md) for what's missing and [coverage-matrix.md](coverage-matrix.md) for what's
covered.
