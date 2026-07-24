# VectaSec — Architecture

How the system that **exists** works. For what's planned but absent, see [STATUS.md](STATUS.md); for why any of it exists, see [vectasec-build-plan.md](vectasec-build-plan.md). Where the two disagree, this file is right and the plan is aspiration.

Read this first, then read `scan.py` and `connect/kafka.py`. Those two files teach the rest.

---

## 1. The shape

Four pieces, one Python package shared by two of them.

```
  ┌──────────────────────┐        reads (SELECT-only, RLS)        ┌────────────────────────┐
  │  apps/web            │───────────────────────────────────────▶│  Supabase / Postgres   │
  │  Next.js console     │                                        │  the system of record  │
  │                      │──┐                                     └────────────────────────┘
  └──────────────────────┘  │                                              ▲          ▲
                            │ mutations only                               │          │
                            ▼                                    BYPASSRLS │          │ (not wired)
  ┌──────────────────────┐                                                 │          │
  │ services/engine      │─────────────────────────────────────────────────┘          │
  │  connect/ detect/    │                                                            │
  │  scan.py ai.py       │──── read-only ───▶ Kafka / Kong / RabbitMQ / MCP           │
  │  api/ (FastAPI)      │                    (the "cloud path")                      │
  └──────────────────────┘                                                            │
                                                                                      │
  ┌──────────────────────┐   imports engine's connect/ + detect/ unmodified           │
  │ services/collector   │─── read-only ───▶ the customer's private systems           │
  │  (customer-side)     │─── outbound-only push ─────────────────────────────────────┘
  └──────────────────────┘        ⚠ the receiving endpoints do not exist yet
```

The engine package is the product. The console is a view of its output. The collector is the same engine code with a different topology and a redaction boundary bolted to its exit.

**Repo layout** (actual, not `vectasec-build-plan.md` §16 — that section describes a target that was never built):

```
services/engine/src/vectasec/
  contracts.py      Resource, Edge, Collected, Hit, ScanContext — the shapes everything speaks
  registry.py       @connector / @detector decorators + the two registries
  scan.py           the scan loop: collect → detect → persist. The spine.
  config.py         settings (read from os.environ on access); .env loading, entry points only
  db.py             psycopg connect()
  connect/          one file per system: kafka.py, kong.py, rabbitmq.py, mcp.py
  detect/           one file per system's rulepack: kafka.py, kong.py, rabbitmq.py, mcp.py
  ai.py             grounded triage + deterministic fallback + fingerprint cache
  graph.py          CTE walks over resources/edges     ⚠ currently unreferenced — see §9
  compliance/map.py rule → framework control mapping   ⚠ currently never called — see §9
  api/main.py       FastAPI: actions + scan orchestration
services/collector/src/collector/
  main.py           enroll → heartbeat → poll → run locally → redact → push
  config.py         targets.json + ${ENV_VAR} credential refs
  redact.py         the payload boundary
apps/web/           Next.js 16 console
supabase/migrations/  the schema (three files)
deploy/dev/docker-compose.yml   a deliberately misconfigured Kafka — the thing we scan
deploy/onprem/      self-hosted stack: Compose + Caddy + a Helm chart.
                    Config-validated, NEVER BOOTED. Read its README before using it —
                    it inherits the engine API's self-asserted-header cross-tenant hole.
```

---

## 2. The schema, and the two guarantees Postgres enforces

`supabase/migrations/20260717000001_core_schema.sql` — the spine: `tenants`, `tenant_members`, `connections`, `resources`, `edges`, `scans`, `findings`, `observations`.

`supabase/migrations/20260717000002_platform_schema.sql` — the platform layer: `collectors`, `api_keys`, `audit_log`, `suppressions`, `controls`, `ai_outputs`, `ai_output_evidence`, `integrations`, `routing_rules`, `usage`; `pgmq` + `pg_cron`; RLS hardening; and the triggers below.

`supabase/migrations/20260717000005_citation_gate_completeness.sql` — the citation gate as originally shipped checked one transition (INSERT on `ai_outputs`) and three others walked around it. 005 re-states it as a check on *state*. Read it before you trust Guarantee 1; the history is in its header comment.

### Guarantee 1 — the citation gate

> An `ai_outputs` row cannot exist in a committed transaction without citing at least one `observations` row **of its own tenant**.

```sql
create constraint trigger ai_outputs_citation_gate
  after insert or update on ai_outputs
  deferrable initially deferred
  for each row execute function enforce_citation_gate();

create constraint trigger ai_output_evidence_citation_gate
  after insert or update or delete on ai_output_evidence
  deferrable initially deferred
  for each row execute function enforce_citation_gate_evidence();
```

`DEFERRABLE INITIALLY DEFERRED` is the whole trick, and it is not a performance knob. The natural write order is: insert the output, get its id, then insert the `ai_output_evidence` links that reference that id. A non-deferred trigger would fire on the INSERT — before any link could possibly exist — and reject every output, including correct ones. Deferring the check to `COMMIT` lets the transaction assemble a complete, cited output.

**Why there are two triggers, and why the first one alone was a lie.** "Uncited output" is a *state*, and until 005 the schema only checked one *event* that could produce it. The other three all committed cleanly:

| Attack | Why the INSERT-only gate never saw it |
|---|---|
| `delete from ai_output_evidence where ai_output_id = X` | no INSERT on `ai_outputs` happens; `ai_output_evidence` had no trigger at all |
| `delete from observations where id = X` | `ai_output_evidence.observation_id` is `ON DELETE CASCADE` — the citation is stripped silently. Migration 002's own comment invites the retention job that does this |
| `insert ... on conflict (tenant_id, kind, fingerprint) do update` | Postgres fires UPDATE triggers on the conflict path, not INSERT triggers. **This is the engine's own write path** (`ai.py::triage_finding`) — the one write in the system the gate never saw |

A fourth hole was on the tenant axis: nothing required a cited observation to belong to the same tenant as the output. `ai_output_evidence` has no `tenant_id` of its own and its RLS policy scopes reads through the parent output, so tenant A's output citing tenant B's observation committed cleanly and rendered in A's console as A's own evidence. 005 checks that too, on both sides of the link.

**Deferring rather than `ON DELETE RESTRICT`** is the load-bearing choice on the delete path. `RESTRICT` on `observation_id` would make the cascade order of `delete from tenants` significant — `tenants` cascades to *both* `observations` and `ai_outputs`, and Postgres does not promise which FK action runs first — so offboarding would fail intermittently. At COMMIT the deferred check has no such problem: the parent output is either already gone (offboarding, cascade — nothing to protect) or still there (a selective delete — raise). Retention still works; it just has to delete the outputs along with the evidence they cite, which is what "the output cites the evidence" means.

This is why `ai.triage_finding()` takes an open cursor instead of opening its own connection: the caller owns the transaction, so the output and its citations commit together or not at all. `api/main.py::triage` catches the `DatabaseError` at `conn.commit()` and returns a 500 rather than swallowing it — that commit is where ungrounded output dies.

All four attacks above are executed in CI (`.github/workflows/ci.yml`, the *evidence integrity* step) alongside controls proving the gate does not break the engine's cache refresh or tenant offboarding. Before 005 that job was green while three of them succeeded.

### Guarantee 2 — the evidence ledger is append-only

> An `observations.claim` can never be **UPDATE**d. That is what makes it evidence.

```sql
create trigger observations_append_only before update on observations
  for each row execute function reject_update();
create trigger audit_log_append_only before update on audit_log
  for each row execute function reject_update();
```

DELETE is deliberately still allowed — tenant offboarding and FK cascades need it. Retention is a policy question; mutation is an integrity question. Only the second one is closed here.

**Take that qualifier literally: the headline says UPDATE, not "rewritten".** `observations.id` defaults to `gen_random_uuid()` rather than being generated-always, so a writer who can DELETE can also re-INSERT at the same id with different claim text and never issue an UPDATE. Nothing in the schema detects that. It needs the `postgres`/`service_role` credential — the browser's `authenticated` role has no write policy on any table and cannot reach it — and no shipped code path does it. But an auditor who reads this section is entitled to know that the ledger's tamper-evidence stops at UPDATE, and that "an operator with the engine's own credential cannot rewrite history" is **not** a claim this schema supports. See *Known gaps* in [STATUS.md](STATUS.md) for the options and why none is taken yet.

### RLS and the trust model

Migration 002 runs `ENABLE` + `FORCE ROW LEVEL SECURITY` over all 18 tenant tables and grants `authenticated` a **SELECT policy and nothing else**. There is no INSERT/UPDATE/DELETE policy for the browser role anywhere in the schema — least privilege by construction, not by convention.

`app_tenant_ids()` is the pivot: `SECURITY DEFINER`, pinned `search_path`, owned by `postgres` (BYPASSRLS). Two non-obvious properties:

- The pinned search_path is not hygiene, it is the difference between a helper and an injection vector.
- `tenant_members_select` must **never** call `app_tenant_ids()`, because that function reads `tenant_members`. It scopes on `user_id = auth.uid()` directly. Break that and you get infinite policy recursion.

The engine connects as `postgres` and **bypasses RLS entirely**. So in `api/main.py`, `graph.py`, and `scan.py`, a missing `and tenant_id = %s` is a cross-tenant leak, not a bug. RLS is not a backstop on the server side; the predicates in those files are the only thing between two customers' estates.

---

## 3. The scan pipeline

`services/engine/src/vectasec/scan.py` — `run_scan(type_, config, tenant_id, connection_name)`.

```
_ensure_connection    upsert the connections row
insert scans          status='running'
────────────────────  collect happens OUTSIDE the write critical section
CONNECTORS[type](config) → Collected(resources, edges)
    on exception: mark the scan 'error', commit, re-raise. A slow or dead target fails the
    scan cleanly instead of holding a write lock.
────────────────────
_persist_resources    upsert on (connection_id, ext_id); anything absent now → stale = true
_persist_edges        delete this connection's edges, re-insert; unresolvable endpoints dropped
for d in DETECTORS:
  for r in resources:
    if r.kind in d.kinds:
      hits = d.fn(r, ctx)          ← one detector raising is caught, recorded, and skipped
      for h in hits:
        upsert findings on (tenant_id, fingerprint)
        insert observations        ← same transaction, always
update scans          status='done', stats
insert audit_log      'scan.completed'
COMMIT                one transaction for the whole scan
```

Four decisions worth understanding before you touch this file:

**Fingerprint dedup.** `fingerprint(tenant_id, rule_id, ext_id)` → `sha256(...)[:32]`, unique with `tenant_id` on `findings`. It deliberately excludes the scan id and the resource's DB uuid (which changes if a resource is deleted and recollected). It is keyed on *what a human would call the same problem on the same thing*. Consequence: the same real-world issue across 100 scans is ONE row with a stable history, and `status` / `assignee` / `due_at` survive re-scanning. Re-scanning must never resurrect a finding a human resolved into a fresh row. `apps/web/components/LiveFindings.tsx` depends on this to claim an INSERT means "genuinely new" — if the dedupe contract changes, that component silently starts lying.

**Evidence is written with the finding, not after it.** The `observations` insert sits inside the same `for h in hits` block as the `findings` upsert. A finding without evidence is a rumour.

**One transaction per scan.** A half-written scan shows a security team an incomplete picture, which is worse than showing them an error.

**Stale, not deleted.** A resource that vanishes is itself a signal, and deleting it would destroy finding history. It gets `stale = true`.

**Suppressions** are applied *by the scan loop* (`_is_suppressed`), matching `{}` (tenant-wide), `{ext_id}`, or `{kind}`. So a new suppression bites at the next scan — `POST /suppressions` says so explicitly in its `applies_at_next_scan: true` response rather than implying it took effect now.

---

## 4. The registry

`services/engine/src/vectasec/registry.py`. Two decorators, two module-level registries, **no central list to edit**.

```python
@connector("kafka")
def collect(config: dict) -> Collected: ...

@detector(kinds=["broker"], rule_id="KAFKA.AUTHZ.NO_AUTHORIZER", severity="high", title="...")
def no_authorizer(resource: Resource, ctx: ScanContext) -> list[Hit]: ...
```

Registration happens on import. `connect/__init__.py` and `detect/__init__.py` import their submodules, and every entry point (`scan.py`, `cli.py`, `api/main.py`, `collector/main.py`) does `from . import connect as _connect  # noqa: F401`. That `noqa` is load-bearing — an over-eager linter removing it silently empties the registries.

**To add a detector: drop a file in `src/vectasec/detect/`.** That is the entire process. Nothing else changes.

### The contracts (`contracts.py`)

- **`Resource`** — `kind`, `name`, `ext_id`, `namespace`, `labels`, `raw`. `ext_id` is the stable id within a connection and the join key for the whole graph. `raw` is the normalized read from the target.
- **`Edge`** — `src_ext_id` → `dst_ext_id` by `ext_id`, resolved to uuids at persist time. An edge to something not collected is dropped, never guessed at.
- **`Hit`** — what a detector returns. `severity` is optional and overrides the decorator's when a rule's seriousness depends on the resource.
- **`ScanContext`** — carries **every** resource in the scan, so cross-resource rules are expressible ("this topic is exposed *because* its broker's listener is PLAINTEXT"). `ctx.of_kind("broker")` is the accessor.

### `Hit.observation` is the load-bearing field

It is the exact string written to the immutable ledger and **the only thing the AI is ever allowed to cite**. It must state a fact read from the target, with the actual observed value in it:

```
✅ "config authorizer.class.name is empty"
✅ "listener EXTERNAL://0.0.0.0:9092 maps to security protocol PLAINTEXT"
❌ "the broker is insecure"          ← a conclusion, not an observation
❌ "authorizer is misconfigured"     ← no observed value
```

Every rule read from a target uses `resource.raw.get(...)`, never `resource.raw[...]`. Real API responses omit keys.

### Connector rules

Read-only. Always. Never write to a customer system. Two patterns from `connect/kafka.py` (the reference — read it):

- **Record the outcome, not just the result.** ACL collection stores `{"outcome": "ok"|"security_disabled"|"error", "bindings": [...], "error": ...}`. An empty list does not prove "no authorizer" — an authorizer with zero ACLs returns `[]` too, and a permissions failure must never be read as "there are no ACLs". Detectors read `outcome` and can say *indeterminate*.
- **Distinguish "not read" from "read, empty".** `None` vs `{}`. `is_sensitive`/`is_default` are preserved because the broker redacts PASSWORD-typed values to `None`; without them a detector cannot tell "explicitly configured but unreadable" from "not set" and would report the wrong one.

Current coverage: **5 connectors, 85 detectors** — KAFKA 20, MCP 19, RABBITMQ 18, KONG 16, REDIS 6, plus cross-cutting NHI (4) and DATA (2) packs that run on the normalized identity/credential/grant and data-classified resources. `uv run vectasec rules` prints the live rulepack.

---

## 5. The Collector's trust model

`services/collector/src/collector/main.py`. It runs inside the customer's network, next to their broker. Three properties, and every choice in that file serves one of them:

**1. Outbound only.** No `bind()`, no `listen()`, no web framework, no port. Jobs are *pulled* via long-poll: the collector opens the connection, the control plane parks it until a job exists, then answers on that same socket. Dispatch rides an egress flow the customer already allows. The collector is not reachable — it runs behind NAT with every ingress rule denied.

**2. Credentials stay local.** The customer's credential is read from local config (`${ENV_VAR}` refs in `targets.json`, never literals), used in-process to dial the private system, and never serialised outbound. The control plane does not have it and has no way to ask for it. The enrollment token is the only long-lived secret and is not kept at rest — the state file gets `sha256(token)`. The service token it buys lives in memory only.

**3. Raw config stays local.** Connectors **and detectors** both run in the collector. `Resource.raw` — the broker config, the plugin config, the topic settings the rules ran against — is deliberately never built into the outbound payload. What leaves is the conclusion: findings, observations, resource metadata (`kind`, `name`, `ext_id`, `namespace`, `labels`), edges. That omission is the difference between "we send findings" and "we send your configuration".

Two more mechanisms:

- **A job is a reference, never a config.** `{"target": "prod-kafka"}` — a name that must already exist in the collector's local `targets.json`. Config-shaped fields on an incoming job are ignored by construction. If the control plane could hand this process a host and a credential, then whoever took the control plane could aim the collector at any address inside the customer's network — or at a broker of their own — while it holds the customer's credentials.
- **`redact()` is the boundary.** One line in `_handle()`; nothing reaches the control plane except through it. `run_job()` is already assembled from credential-free parts — `redact()` is what makes that a guarantee rather than a promise, for this payload and for every connector added later. A `_SecretFilter` on the log *handler* (not the logger — a logger filter isn't consulted for records propagating up from `vectasec.*`) scrubs connector exception text that might carry a URL with userinfo.

`vectasec-collector preview` exists for the security review: it scans real targets with real credentials and prints exactly what *would* be pushed, sending nothing. Rather than take our word for what leaves the network, an operator reads the JSON.

Fingerprints are computed with the engine's `fingerprint()`, imported not reimplemented — so a tenant migrating a cluster from the cloud path to a collector does not have its triage history reset.

> ⚠️ **The collector cannot run today.** It enrolls and polls against `/collector/enroll`, `/collector/heartbeat`, `/collector/jobs`, `/collector/results` — none of which exist in `api/main.py`. Only `check` and `preview` work. See [STATUS.md](STATUS.md).

---

## 6. Grounded AI

`services/engine/src/vectasec/ai.py`. The premise: an LLM that confidently narrates a finding it cannot substantiate is worse than no LLM, because a security team acts on it. Four mechanisms, in increasing order of strength:

1. **The model gets only this finding's observations**, numbered, and is told it was not there and cannot see the system. The citation array is enforced by a JSON schema (structured outputs) — not by parsing prose for `[1]`. The model physically cannot return an uncited shape.
2. **Every citation is range-checked** against the observations actually sent. One out-of-range index means the model invented evidence, so the *whole* output is discarded — never partially trusted.
3. **The database refuses to commit** an `ai_output` with no linked observation (§2). Even if 1 and 2 were bypassed, Postgres is the backstop.
4. **Refusals are a normal outcome.** A security scanner asks about exploitation for a living. `stop_reason == "refusal"` and `max_tokens` both raise `UncitedOutput` and fall through, rather than crashing or surfacing nothing.

**The fallback** (`_rule_based`) runs when the model is unavailable, unconfigured, refuses, or returns something uncited. It is deterministic, constructed *from* the observation (so it cites trivially), labels itself `model="rule-based-fallback"`, and asserts nothing beyond the evidence — which is why its `confidence` is `high`. **The product never depends on the AI being reachable.** No `ANTHROPIC_API_KEY`? Everything still works; you get the deterministic summary and the finding and its evidence are unaffected.

**The cache.** `ai_outputs` is unique on `(tenant_id, kind, fingerprint)`. One explanation of "wildcard ACL" serves every occurrence, on every re-scan, forever. That is what makes it affordable to default to the strongest model: triage quality is the product, and we pay per distinct finding-class, not per occurrence.

If a finding has no observations, `triage_finding` returns `None` and the API returns 422. A finding with no evidence is a rumour, and the AI layer does not speak about it.

---

## 7. The API

`services/engine/src/vectasec/api/main.py`. FastAPI. **It has no list endpoints, on purpose.**

> The console READS Supabase directly (PostgREST + RLS). This service only changes state or starts work — and both need what RLS cannot give: an authenticated actor and an audit trail.

- `GET /health` — 200 even when the DB is down; `db` carries the truth. A health check that refuses to answer can't tell an operator which half is broken.
- `POST /scans` — `inline: true` runs it in-request (the dev/demo path). Otherwise it enqueues to `pgmq` in the same transaction as the `scans` row, so a worker can never pull a job whose scan row doesn't exist yet. ⚠️ **No worker consumes the queue.**
- `GET /scans/{id}`, `POST /findings/{id}/status`, `POST /findings/{id}/assign`, `POST /findings/{id}/triage`, `POST /suppressions`, `GET /compliance/{framework}`, `GET /graph/blast-radius/{id}`

Rules this file lives by:

- **Every statement filters `tenant_id` explicitly** — BYPASSRLS role, so isolation is not free here the way it is in the browser.
- **Every mutation writes its `audit_log` row in the same transaction as the change.** An action that commits without its audit row is an action nobody can account for. An unattributed write is *refused* (`acting` requires `X-VectaSec-Actor`) rather than recorded anonymously.
- **Status transitions take `FOR UPDATE`** — two analysts triaging the same finding must not interleave into an audit trail recording a transition that never happened. The note lives only in the audit row: it explains a *change*, so a column on `findings` would be overwritten by the next one.
- **`suppressed` is not a settable status.** A suppression carries a reason and an expiry and is applied by the scan loop, so it goes through `POST /suppressions`. As a plain status it would create exceptions nobody can audit or expire. `reason` is validated non-blank; unknown scope keys are rejected rather than silently matching nothing.
- **Handlers are sync `def`** on purpose: psycopg blocks, and FastAPI runs sync handlers in a threadpool, so blocking costs a worker thread instead of stalling the event loop.

> ⚠️ **`principal()` is a development stand-in.** `X-VectaSec-Tenant` and `X-VectaSec-Actor` are self-asserted — any caller can name any tenant and any actor. A real deployment must verify a Supabase JWT against the project JWKS and take the tenant from membership claims. This is why `main()` binds `127.0.0.1` by default and why the console proxies rather than letting the browser call it. There is a `TODO(auth)` on it.

---

## 8. The console

`apps/web` — Next.js 16, React 19, server components. Routes: `/`, `/findings`, `/findings/[id]`, `/assets`, `/assets/[id]`, `/connections`, `/compliance`, `/login`.

### Reads go to Supabase. Actions go to the engine. Never the reverse.

**Reads** — `lib/supabase/server.ts` creates a server client with `NEXT_PUBLIC_SUPABASE_URL` + `NEXT_PUBLIC_SUPABASE_ANON_KEY`, marked `server-only` (a build error if imported from a client component). It talks to Postgres as `authenticated`: SELECT-only, RLS-scoped. Pages don't filter by `tenant_id` — RLS does. The console must **never** receive `SUPABASE_SERVICE_ROLE_KEY` or `DATABASE_URL`; those bypass RLS and the tenant-isolation guarantee with them.

**Actions** — `app/findings/actions.ts` (Server Actions) → `app/findings/engine.ts` → the engine API. The browser role is SELECT-only on every table, so nothing in the console writes to Postgres.

`engine.ts` is `server-only` and its URL is deliberately not `NEXT_PUBLIC_`. **The console is the thing that makes the engine's self-asserted headers trustworthy:** callers never pass a tenant — it's derived from a row RLS already agreed the user can see — and the actor is the id from a server-confirmed `getUser()`, never a form field. The browser cannot reach that file, cannot see the URL, and cannot influence either header.

### Three layers of auth; only one is load-bearing

1. `proxy.ts` (**not** `middleware.ts` — Next 16 renamed the convention) refreshes the session and redirects anonymous users. **This is not an authorization boundary.** Server Functions are POSTs to the route where they're defined, so a matcher change silently removes coverage with no test failing.
2. Every Server Action re-verifies with `getVerifiedUser()` — a network hop to the Auth server, not `getClaims()`. `getClaims` verifies a signature, not revocation: a fired analyst's unexpired token still has a valid signature. Then `getActionContext()` reads the finding **under RLS** — if Postgres doesn't hand back the row, the user cannot act on it. That is the IDOR check, which authentication alone never answers.
3. **RLS is the actual guarantee.**

### Two design constraints worth knowing

- **`LiveFindings.tsx`** subscribes to Realtime and shows a *pill*, not an auto-refresh. Re-sorting a table under an analyst's cursor loses their place and invites a click on the wrong finding — in a tool whose buttons are suppressions and triage decisions, that's a real misfire. Interruption is opt-in. It needs two things **not in any migration**: `findings` in the `supabase_realtime` publication, and a Realtime authorization policy on `realtime.messages` (a table-level SELECT policy on `findings` is not sufficient). Without both it renders nothing, forever — by design. The live layer is an enhancement over a page that is already correct without it.
- **`/compliance`** computes its score over *evaluated controls only*. A finding can prove a control FAILS; a finding's absence can never prove it PASSES. `0/0` renders as "Not scored", never 100%.

---

## 9. Two things that are not wired up

Both are real code with real intent that nothing calls. Know about them before you rebuild either by accident.

**`graph.py` is unreferenced.** It implements `neighbours()`, `blast_radius()`, `exposure_paths()`, `summary()` — with a per-path cycle guard (`not (r.id = any(w.path))`), a `distinct on` that keeps the *shortest* path to each node, a `depth_bounded` flag so a truncated walk is never presented as complete, and an undirected default (reachability in a posture sense is symmetric even when the edge recording it is not). `api/main.py::blast_radius` does **not** use any of it — it reimplements a *different* walk inline: directed-only, depth-guard only, no path guard, so on a cyclic graph it can report the root as its own blast radius. Two implementations that disagree on semantics. Pick one.

**`compliance/map.py` is never called.** 1000+ lines of sourced rule→control mapping for PCI DSS 4.0.1 / DORA / HIPAA / the pinned MCP spec, with an `evaluate()` that would populate the `controls` table. Nothing in `scan.py` or `api/main.py` calls it. So `controls` is always empty, `GET /compliance/{framework}` always returns `count: 0`, and the console's compliance page always renders its empty state. Unlike `detect/` and `connect/`, there is deliberately no auto-registration here — a mapping is a claim about a published standard, so it lives in one reviewable table with its sources attached.

---

## 10. Day-one checklist

```bash
cd services/engine
uv run vectasec doctor                                      # 5 connectors, 85 detectors, DB, pgmq+pg_cron
docker compose -f deploy/dev/docker-compose.yml up -d        # the misconfigured Kafka
uv run vectasec scan --type kafka --bootstrap localhost:9092
uv run vectasec findings                                     # cited findings
uv run vectasec rules                                        # the rulepack
uv run pytest                                                # the offline suite
```

Then read, in this order: `contracts.py` → `registry.py` → `connect/kafka.py` → `scan.py` → one detector in `detect/kafka.py` → `ai.py`. Then [STATUS.md](STATUS.md) for what's missing.
