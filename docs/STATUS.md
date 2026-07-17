# VectaSec — Status

**As of 2026-07-17.** Verified by reading the code, running the tests, and running `vectasec doctor` against the live database. Every claim below points at a file. If a file isn't named, treat the claim as unsupported.

Phases refer to [vectasec-build-plan.md](vectasec-build-plan.md) §18.

**One-line summary:** the deterministic core is real and provable — the plumbing around it is not. Phase 0 is substantially done, the Phase 1 *rulepacks* ran far ahead into Phase 2/3 territory, and the Phase 1 *plumbing* (worker, collector bridge, compliance evaluation, sign-in, integrations) is largely missing. No phase is "done" by its own **Done when** bar.

---

## What actually works, end to end

This is the honest floor. It runs on a laptop and does what it says:

```
docker compose -f deploy/dev/docker-compose.yml up -d
cd services/engine && uv run vectasec scan --type kafka --bootstrap localhost:9092
uv run vectasec findings
```

A deliberately misconfigured Kafka → read-only collection → 73 deterministic detectors → findings and cited observations committed to Postgres in **one transaction**, deduped by fingerprint, listed back with their evidence counts. Re-running is idempotent. That path is not a demo mock.

Nothing else in this document reaches that bar.

---

## DONE

| Thing | Where | Notes |
|---|---|---|
| Core schema | `supabase/migrations/20260717000001_core_schema.sql` | Applied to the live DB. Tenancy, inventory, graph, scans, findings, evidence. Seeds the Demo tenant. |
| Platform schema | `supabase/migrations/20260717000002_platform_schema.sql` | Applied. 18 tenant tables + `schema_migrations` (the 19 `vectasec doctor` reports); `pgmq` + `pg_cron` present. Verified against the live DB. |
| **Citation gate** | migration 002 + **005**, `enforce_citation_gate()` / `enforce_citation_gate_evidence()` | Deferred constraint triggers on both `ai_outputs` and `ai_output_evidence`. An `ai_output` cannot commit uncited, cannot be *left* uncited by an evidence or observation DELETE, cannot slip through the engine's own `ON CONFLICT DO UPDATE` path, and cannot cite another tenant's observation. As shipped in 002 the gate only fired on INSERT and the other three all committed — 005 is the fix, and all four are now attacked in CI. |
| **Append-only evidence ledger** | migration 002, `reject_update()` | UPDATE rejected on `observations` and `audit_log`. DELETE deliberately allowed (offboarding / FK cascade) — which means **delete + re-insert at the same id rewrites a claim without an UPDATE**. Gap #15. |
| RLS hardening | migration 002 | `ENABLE` + `FORCE` on all 18 tenant tables; `authenticated` has SELECT-only policies and no write policy anywhere. `app_tenant_ids()` is SECURITY DEFINER with a pinned search_path; `tenant_members_select` is non-recursive by construction. |
| Contracts + registry | `contracts.py`, `registry.py` | `@connector` / `@detector` auto-registration. Drop a file in `detect/`, done. No central list. |
| Scan loop | `scan.py` | collect → detect → persist, one transaction, fingerprint dedup, stale-marking, per-detector error isolation, suppression application. |
| Connectors (4) | `connect/{kafka,kong,rabbitmq,mcp}.py` | Read-only. Kafka is the reference. |
| Detectors (73) | `detect/{kafka,kong,rabbitmq,mcp}.py` | KAFKA 20, MCP 19, RABBITMQ 18, KONG 16. `uv run vectasec rules`. |
| Grounded AI triage | `ai.py` | Structured-output citations, range-checked, deterministic fallback, fingerprint cache, refusal handling. Works with no API key. |
| Engine API (actions) | `api/main.py` | health, scans, finding status/assign/triage, suppressions, compliance read, blast-radius. Audit row per mutation, in-transaction. |
| CLI | `cli.py` | `scan`, `rules`, `findings`, `doctor`. |
| Dev scan target | `deploy/dev/docker-compose.yml` | Misconfigured Kafka, each bad value annotated with the rule it should trigger. |
| Console pages | `apps/web/app/**` | Server-rendered findings queue + detail, assets + blast radius, connections, compliance. Reads under RLS; mutations forwarded to the engine. |
| Collector code | `services/collector/src/collector/**` | Outbound-only design, local credentials, `redact()` boundary, `preview` for security review. **The code. Not a working deployment** — see PARTIAL. |
| Tests | `services/engine/tests/`, `services/collector/tests/` | **Run `uv run pytest` in each — this document deliberately states no count.** A hardcoded total was wrong here, in the README twice, and in ARCHITECTURE.md for exactly as long as it took someone to add a detector, and a stale number in a document whose only asset is being checkable is worse than no number. What the suite is: offline unit tests over detectors, redaction, `scan.py`'s pure logic, `ai.py`'s citation gate, and `compliance/map.py`'s no-pass contract. What it is not: see gap #8. |
| Research | `docs/research/**` | Sourced rulepack, compliance-mapping, threat-landscape, platform-API, console-UX notes. |

---

## PARTIAL

### Phase 0 — Foundation
**Verdict: substantially done. Fails its own "Done when" on two counts.**

The bar was: *"connect a real (managed) Kafka, scan, see a cited finding update live; the same stack runs against self-hosted Supabase."*

- ✅ Schema, hardened RLS, `pgmq`, `pg_cron`, engine skeleton, evidence ledger + citation gate, one connector end to end.
- ⚠️ **Kafka is scanned via Docker, not a real managed cluster.** No MSK, no cross-account role, no agentless path (see NOT BUILT).
- ⚠️ **"Update live in the console" is not reachable.** `LiveFindings.tsx` is written and correct, but (a) sign-in doesn't exist so you can't get to the page, and (b) the two DB-side prerequisites are in no migration: `alter publication supabase_realtime add table findings;` and a Realtime authorization policy on `realtime.messages`. The component fails silently by design — which means this has never actually been observed working.
- ✅ **CI exists.** `.github/workflows/ci.yml`: engine + collector unit tests, web typecheck/build, the detectors against a live dev Kafka, and — the one that matters — adversarial cross-tenant RLS queries and the two integrity guarantees (citation gate, append-only ledger) against the real migrations applied to an empty database. Aggregate `ci` job for branch protection. **Never observed green on GitHub** — the repo has 3 commits and most of the tree is untracked, so nothing has pushed.
- ⚠️ **On-prem path exists on paper only.** `deploy/onprem/` — Compose, Caddyfile, engine/web Dockerfiles, and a Helm chart (11 templates: engine/web/worker deployments, services, ingress, networkpolicy, secret, configmap, serviceaccount). Per [deploy/onprem/README.md](../deploy/onprem/README.md) §Validation status: `docker compose config`, `caddy validate`, `helm lint` and `kubeconform -strict` all pass — **and the stack has never been started.** Syntax and schema are verified; runtime is not. Nothing proves an image builds, a migration applies, or a container reaches its neighbour. It also inherits gap #5 below: containerising the engine necessarily overrides its `127.0.0.1` bind, so the self-asserted-header cross-tenant hole is exposed to whatever can reach it, with a Caddy CIDR gate standing in for the authentication that does not exist. **Do not deploy it without reading its README.** On-prem parity is unproven.

### Phase 1 — Core product + first sale
**Verdict: the rulepacks are ahead of plan; the plumbing is missing. Not close to its "Done when".**

| Phase 1 item | State |
|---|---|
| The Collector, end to end | ⚠️ **Code exists, cannot run.** `collector/main.py` enrolls and polls `/collector/enroll`, `/collector/heartbeat`, `/collector/jobs`, `/collector/results`. **None of those endpoints exist** in `api/main.py` (`grep -rn collector services/engine/src` → nothing). Only `check` and `preview` work. The trust properties are real in the code and real in `preview`; the loop has never talked to a control plane. |
| Kafka connector + rulepack | ✅ 20 rules. |
| Kong connector + rulepack | ✅ 16 rules. |
| One iPaaS | ❌ Not started. |
| Asset graph | ⚠️ `resources` + `edges` persist; Kong/RabbitMQ/MCP emit edges. **The Kafka connector emits none** (`Collected(resources=..., edges=[])`) — so the only end-to-end target produces an empty graph and a blast radius of one node. `graph.py` exists and is unreferenced (see Known gaps). |
| Findings workflow (assignee, suppression-with-expiry, dedup) | ✅ Via the engine API. Suppressions apply at next scan, and the API says so. |
| Compliance: PCI 6.4.2 + DORA + OSCAL | ⚠️ **Mapping written, never evaluated.** `compliance/map.py` is 1000+ lines of sourced PCI/DORA/HIPAA/MCP-spec mapping with a working `evaluate()`. **Nothing calls it.** The `controls` table is never populated, so `GET /compliance/{framework}` always returns `count: 0` and the console's compliance page always renders empty. No OSCAL export. |
| Grounded-AI triage v1, fingerprint-cached | ✅ `ai.py`. |
| Slack + Jira out | ❌ `integrations` / `routing_rules` tables exist. No code. |
| SSO + RBAC | ❌ `tenant_members.role` column exists and is read by nothing. No RBAC anywhere. No SSO. |
| Audit log | ✅ Written on every mutation, in-transaction, append-only. |
| SOC 2 observation window | ❌ Not started. **Do not claim SOC 2 anywhere.** |
| Open-source benchmark + free Collector | ❌ Not published. Repo has 3 commits and most of the tree is untracked. |
| <10-min cloud / <30-min Collector onboarding | ❌ No onboarding flow exists. |

### Phase 2 — Breadth + identity
**Verdict: one connector landed early. Everything else absent.**

- ✅ **RabbitMQ** connector + 18 rules (Phase 2 work done during Phase 1).
- ❌ Istio, Apigee, Boomi/Workato/n8n.
- ❌ **Identity / NHI**: no inventory, no OAuth-grant blast radius, no workload-identity audit. This is the *positioning wedge* in the README and there is no code for it.
- ❌ **Supply chain**: no `iac-scan`, no GitHub Action, no SBOM, no CVE scan. (Some RabbitMQ rules read a version string and flag known-CVE series — that is a version check, not a CVE scan.)
- ❌ DORA Article 28 register generator; Vanta/Drata push.
- ❌ Billing/metering (the `usage` table exists and nothing writes to it), SCIM, SIEM/webhook, read API, US+EU regions.

### Phase 3 — MCP + runtime + enterprise
**Verdict: the MCP rulepack landed very early. Nothing else.**

- ✅ **MCP** connector + **19 rules**: tool-poisoning (hidden instructions, invisible chars, schema poisoning), auth-spec violations (PRM, PKCE, scope, AS metadata), transport (plaintext, deprecated SSE, origin validation), session handling. The spec revision is pinned (`MCP_SPEC_2025_11_25`) because MCP moves fast enough to invalidate detectors.
- ❌ Registry/allowlist with rug-pull detection.
- ❌ MCP tool blast radius traced through the middleware it wraps — needs the graph, and Kafka emits no edges.
- ❌ Runtime sensor (Tetragon/Pixie), egress anomalies, cross-layer attack paths.
- ❌ Enterprise: dedicated tenant, hardened/air-gapped on-prem, offline licensing, BYO-KMS, Terraform provider, **SOC 2 Type II**.

---

## NOT BUILT (claimed somewhere, exists nowhere)

Things the README, the plan, or the schema imply that have **zero code**:

- **Agentless cloud path via cross-account read-only role.** The README says managed middleware "can optionally be reached agentlessly via a cross-account read-only role — no install". There is no AWS SDK, no IAM, no `AssumeRole`, no MSK-specific code anywhere. What exists as the "cloud path" is `run_scan()` dialing a host with a config dict. That is not agentless — it is the same connector run from a different machine.
- **Vault.** `connections.creds_ref` is commented "Vault ref (cloud path)". No Vault integration exists. Credentials for the cloud path live in `connections.config` as plain JSONB.
- **Supabase Storage.** Named in the architecture. Unused.
- **Edge Functions.** `supabase/functions/` does not exist.
- **`packages/`.** `pnpm-workspace.yaml` globs `packages/ui` and `packages/contracts-ts`. **The directory does not exist.** No shared UI library, no generated TS contracts (`apps/web/lib/types.ts` is hand-maintained and can drift from `contracts.py` with nothing to catch it).
- **Most of the plan's §16 repo layout.** `identity/`, `supplychain/`, `mcp/`, `evidence/`, `graph/`, `scan/`, `ai/` as packages; `packages/iac-scan`, `packages/benchmark`; `deploy/saas`. None exist. `graph.py`/`scan.py`/`ai.py` are flat modules. Treat §16 as a wish list, not a map. (`deploy/onprem` **does** exist — see Phase 0 above. It is the one §16 path that landed.)
- **SSO / SAML / SCIM.** Sign-in itself now exists (`apps/web/app/login/page.tsx` — email+password via `signInWithPassword`, verified end to end against the live project), but it is *only* that. No SSO, no SAML, no SCIM, no invite flow, no password reset, no user directory — which is also why "assign a finding to a colleague" is a dead end (see Known gaps).
- **SOC 2 (any type), on-prem validation, a design partner, a customer.** None. Do not imply otherwise in any doc, deck, or commit message.

---

## Known gaps — the specific list

Ranked by how much they'd hurt.

0. **A scan that dies mid-collect leaves a stuck `running` row, and nothing reaps it.** Introduced deliberately by `20260717000003` + the `scan.py` transaction fix, and recorded here rather than papered over. `run_scan` now COMMITs the `connections` + `scans('running')` rows *before* collecting, because holding them uncommitted took an exclusive lock on the `connections` row for the entire collect — a 5-minute Kafka connect blocked every concurrent scan of that connection, and `running` was a status no reader could ever observe (the row was invisible outside the open transaction). The trade is real and is the right way round: a *crash* (SIGKILL, OOM, pod eviction) during collect now leaves a durable `running` row that nothing transitions, where before it left no row at all. An in-process exception is still recorded — both the connector and the persist phase now write `status='error'` on their own transaction. **There is no reaper**: nothing ages out a `running` scan, so the console would show it as in-flight forever. Wants a sweeper (`update scans set status='error' where status='running' and started_at < now() - interval '1 hour'`), which is naturally the queue worker's job (gap 2) — a worker owns a scan's lifecycle and is the right place for a heartbeat/lease. Not built here: inventing a reaper without the worker that leases the scan is guesswork about a component that does not exist yet.

0b. **Findings with no resource are not re-fingerprinted.** `20260717000003` rewrites `findings.fingerprint` to include `connection_id`, joining through `resources` to get it. A finding whose `resource_id` is NULL (or whose resource has a NULL `connection_id`) has no connection to hash, so no correct new value exists and the row keeps its old fingerprint. It becomes unreachable: the next scan inserts a fresh row under the new key, and the old one keeps its triage state and ages in place. This should be rare — `findings.resource_id` cascades on resource delete, so it is only NULL when `_persist_resources` did not return an id for the ext_id. The migration deliberately does **not** delete those rows: deleting a security finding is not a migration's call. Worth a query before the next release to confirm the count is zero.

1. **The console is unreachable.** `proxy.ts` redirects all anonymous traffic to `/login`; `/login` is a placeholder. A fresh `pnpm dev` dead-ends. Every page behind it is built and untested against real auth. *Fix: a client-side `supabase.auth` sign-in + an `/auth/callback` route to exchange the code, plus a `tenant_members` row per user.*

2. **No queue worker.** `POST /scans` enqueues to `pgmq.vectasec_scans` in the same transaction as the `scans` row — correctly — and **nothing reads the queue**. Queued scans stay `queued` forever. Flagged `TODO(worker)` in `api/main.py`. Compounding issue: `run_scan()` opens its *own* `scans` row, so a worker cannot adopt the queued one; the queued row would become an orphan placeholder. `run_scan` needs to accept a `scan_id` before a worker can exist.

3. **The Collector has no other end.** Four endpoints missing (§PARTIAL). The most trust-critical component in the product, the one the README leads with, has never completed a round trip. `preview` is genuinely useful for a security review today; the loop is not deployable.

4. **Compliance never runs, and when it does it can only ever say `fail` or `unknown`.** `compliance/map.py::evaluate()` is dead code — nothing calls it, so the `controls` table is permanently empty and the console's compliance page — the budget-holder's view — renders empty. One call from the scan loop fixes that, and it is the cheapest high-value gap on the list.

   **Know what that call buys before you sell it.** `evaluate()` has no path to `pass` — the `allow_pass` flag that used to provide one was removed, deliberately, because the `controls` table has no provenance column and a scan-derived pass would have been indistinguishable from a human attestation while `apps/web/app/compliance/frameworks.ts` promises the buyer every pass is attested. So wiring the call yields a page of `fail` and `unknown`, a score of "Not scored" (0/0 renders as null, not 100%), and a coverage number. That is the honest output and it is **not** a compliance score.

   **The gap this leaves is a product decision, not a bug, and it is not made.** A real "pass" needs an attestation mechanism that does not exist: no attestation table, no column, no writer, no UI (`grep -rni attest` over the repo returns only the three prose sites making the promise). Until someone builds it, VectaSec cannot tell a customer a control is met — only that it is failing or unproven. Whether that is a defensible product or an unsellable one is the open question; do not close it by re-adding a flag that writes `pass` from silence.

5. **Engine API auth is self-asserted.** `X-VectaSec-Tenant` / `X-VectaSec-Actor` headers, no verification: any caller can name any tenant and any actor, giving cross-tenant writes and a forgeable audit trail. Mitigated only by binding `127.0.0.1` and by the console being the sole caller (`engine.ts` is `server-only`, URL not `NEXT_PUBLIC_`). **The engine must not be exposed to any untrusted network until it verifies a Supabase JWT.** `TODO(auth)` in `api/main.py`.

6. **Two blast-radius implementations that disagree.** `graph.py` is entirely unreferenced — `neighbours`, `blast_radius`, `exposure_paths`, `summary`, all with careful cycle guards, shortest-path selection, and a `depth_bounded` truncation flag. `api/main.py::blast_radius` reimplements a *different* walk inline: directed-only, depth-guard only, **no per-path cycle guard**. On a cyclic graph (broker → topic → mirrors → back to broker — the docstring's own example) the API version can report the root as its own blast radius. One of the two must go.

6b. **The Assets and Connections pages still count rows in JavaScript over an unbounded select, and hosted PostgREST caps that at 1000.** The Findings facets and the Overview counts were moved onto the `findings_facets` aggregate view (`20260717000004`) precisely because an unbounded `.select()` is silently truncated at Supabase's Max Rows while the `count: 'exact'` total beside it is not — two numbers, two mechanisms, disagreeing by construction past the cap. `apps/web/app/assets/page.tsx` (the `resources` + per-resource open-finding tallies) and `apps/web/app/connections/page.tsx` (per-connection resource and finding counts) have the same shape and were **not** fixed here. **Only the hosted/SaaS path is affected**: `deploy/onprem/docker-compose.yml` sets no `PGRST_DB_MAX_ROWS`, and PostgREST's own default is unlimited. The cap value is also unverified — the project's Max Rows setting was not readable, so 1000 is Supabase's documented default, not an observed number; the mismatch is a defect at whatever cap is configured.

   **Not fixed because the honest fix is a product decision, not a one-line query change.** An aggregate view cannot rescue these pages the way it rescued the facets: both *render every row*, so the list itself is capped, not just the counts — a `resource_open_findings` view would be O(resources) rows and truncate at exactly the same place. Making these correct at scale means paginating the asset inventory (or adopting the Findings page's `LIST_LIMIT` + visible truncation footer), and how a security team should page through an estate they are trying to see whole is a question for whoever owns the inventory view. A silently capped count in a posture tool is worse than a visibly capped one, and both are worse than a page that admits what it is not showing. Until then: **treat asset and connection counts as unreliable above ~1000 resources or findings on hosted.** Note `connections` is bounded in practice by connections a human created, so that page's exposure is via its `resources`/`findings` reads, not its own list.

   One trap for whoever takes this: the reflexive fix is a `SECURITY DEFINER` aggregate RPC. Do not. These tables are `FORCE RLS` and the view added in `20260717000004` is `security_invoker = true` for this reason — a definer-rights aggregate runs as `postgres` (BYPASSRLS) and would return every tenant's counts to every caller, turning a wrong-number bug into a cross-tenant leak.

7. **Realtime is not enabled in the schema.** `LiveFindings.tsx` needs the `supabase_realtime` publication entry and a `realtime.messages` policy. Neither is in a migration. The component fails silent by design, so this looks like nothing rather than like a bug.

8. **Test coverage is shallow where it is not absent.** Every test is offline and in-process. What is covered: detector logic, redaction, `scan.py`'s two pure functions (`fingerprint`, `_is_suppressed`), `ai.py`'s citation range-check against a stubbed client, `compliance/map.py`'s no-pass contract against a fake cursor. What is **not** covered by any test: `scan.py`'s actual spine (transactionality, dedup against a real DB, stale-marking), `api/main.py` (tenant scoping, audit-in-transaction, locking), `graph.py` — nothing at all. The two integrity guarantees and cross-tenant RLS are exercised **only** by the `rls-cross-tenant` CI job's raw SQL against real migrations, never by the Python suite — and that job has never run on GitHub (nothing is pushed), so it has only ever passed locally, if at all.

9. **The Kafka connector emits no edges.** The graph, the blast radius, and every "what does this touch" story are empty for the only target we can scan end to end. Kafka should at minimum emit `broker → topic` (hosts) edges.

10. ~~**Duplicate/conflicting resource constraints.**~~ **FIXED** by `20260717000003_pipeline_fixes.sql`, and it was worse than this entry said. Migration 001's `unique (connection_id, kind, name)` and 002's `resources_conn_extid_uniq on (connection_id, ext_id)` were both live while `scan.py` upserted `on conflict (connection_id, ext_id)` — which arbitrates only the *ext_id* constraint. The break needed no rename: **two distinct resources that legitimately share `(kind, name)`** miss the ON CONFLICT target entirely, take the INSERT path, and raise `unique_violation` on the legacy constraint. Kong reaches this on any ordinary deployment — `connect/kong.py` sets `name = instance_name or name`, and `instance_name` is null by default, so `key-auth` on two routes yields two `kind='plugin', name='key-auth'` rows with distinct ext_ids. The exception aborted the **whole scan**, and (until the `_mark_scan_error` fix landed alongside) rolled the `scans` row back with it, so it failed silently and permanently on every re-run. `ext_id` is the documented identity; the 001 unique is dropped.

11. **`connections.mode` is hardcoded.** The DB default is `'collector'`; `scan._ensure_connection` inserts `'cloud'` literally. There is no way to record a collector-sourced connection, which is fine only because collector-sourced connections cannot exist yet.

12. **CI is written but has never run.** `.github/workflows/ci.yml` covers the unit tests (it runs `pytest` without asserting a count, deliberately), the web build, live-Kafka detectors, migrations against an empty database, cross-tenant RLS, and the two integrity triggers. None of it has ever executed: the repo has 3 commits and `apps/`, `services/`, `supabase/`, `deploy/`, `docs/research/`, `.github/` are all **untracked**, so nothing has been pushed and no branch protection exists. An unpushed workflow is a plan, not a gate — treat every CI-derived assurance in this document as unobserved until it is green on a real PR.

13. **Hand-maintained type duplication.** `apps/web/lib/types.ts` mirrors `contracts.py` and the schema by hand. `packages/contracts-ts` was the plan's answer; it doesn't exist.

14. **`ai.py` pins a model string.** `MODEL = "claude-opus-4-8"` with an env override. Fine, but there is no fallback model chain — an unavailable model drops straight to the rule-based path, which is safe but silently degrades quality.

15. **The evidence ledger is tamper-evident against UPDATE, not against DELETE + re-INSERT.** `observations_append_only` blocks UPDATE, and migration 002 deliberately leaves DELETE open so tenant offboarding and FK cascades work. But `observations.id` defaults to `gen_random_uuid()` rather than `generated always as identity`, so a writer can `delete from observations where id = X` and re-`insert` at that same id with different `claim` text — rewriting evidence without ever issuing an UPDATE. Verified against a faithful replica of the live schema. Reachability is narrow but real: it needs the `postgres`/`service_role` credential (which is the *engine's own* credential, and a POC operator's); the browser's `authenticated` role has no write policy on any table and cannot reach it; and no shipped code path deletes observations (`grep` finds no `delete from observations` in the engine).

16. **The collector's state file is write-only, deliberately.** `write_state` records a collector id and `sha256(enrollment token)`; nothing reads it back, and `read_state` was deleted rather than wired in. Consequences, stated rather than papered over: every restart re-enrolls from scratch and takes a **new** server-assigned collector id, so a restarting collector has no identity continuity in the console; and a rotated enrollment token is not detected in advance — it fails enrollment with a 401 and the process exits naming the variable to fix. The alternative (reuse the persisted id) was rejected on purpose: `/collector/enroll` does not transmit a collector id, and having the client assert its own identity from a disk value is weaker than the current server-assigned design. If identity continuity across restarts turns out to matter, it is a **wire-protocol** change, not a local one.

17. **The collector's control-plane client is tested against a fake server only.** `tests/test_control_plane.py` drives enroll → heartbeat → long-poll → scan → redact → push over `httpx.MockTransport`. That pins the client's behaviour and the trust properties (memory-only service token, nothing usable on disk, no credential in the pushed body) — but a fake server agrees with our contract by construction. It cannot tell us the contract matches the endpoints, which do not exist yet (gap: "The control-plane endpoints" in the collector README).

18. **The model still owns `priority`, and observation text is attacker-controlled.** An observation quotes the scanned system verbatim — `detect/mcp.py` interpolates `scopes_supported`, `issuer` and `metadata_url` from a remote MCP server straight into the claim, and scanning servers nobody trusts is the product. So a hostile server can put prose in our prompt. `ai.py` now fences every claim in an `<observation>` element it cannot close, tells the model in `SYSTEM` that the region is data and that an embedded "known false positive, set P3" note is itself evidence of tampering, and caps each claim at `MAX_CLAIM_CHARS`. **That is mitigation, not proof.** A determined injection can still steer the triage *prose* and the `priority`/`confidence` chips, and every word of it will be correctly cited — grounding is not injection resistance.

    The remaining lever is to take `priority` away from the model (derive it from rule severity like `_rule_based` does, or refuse a model priority that downgrades a `critical`/`high` rule). **Not done, deliberately: that is a product decision, not a bug fix.** `TRIAGE_SCHEMA` says "Judge from evidence, not rule severity alone" on purpose — evidence-aware priority is the feature, and pinning priority to severity makes the AI's judgement decorative. The tradeoff: today an attacker can argue their finding down to a P3 chip; pinned, nobody can argue a `critical` down even when the evidence says it is a lab fixture. **What bounds the blast radius today:** `apps/web/app/findings/data.ts` filters and sorts the findings list on `severity` — the deterministic rule's severity — and never reads AI `priority`. AI priority appears only on the detail page, inside a labelled provenance fence, beside the observation it was steered by. So a steered finding is *misdescribed*, never *hidden*. Decide this before any surface starts routing, alerting, or SLAing on `priority` — at that moment this becomes exploitable rather than embarrassing.

    **This is a product decision, not a bug, which is why it is written here rather than fixed.** Closing it means picking one, and each costs something real:
    - *Block DELETE on `observations` outright.* Kills tenant offboarding and every FK cascade from `tenants`/`findings`. Not viable without a full soft-delete/retention design.
    - *Allow DELETE only via a retention path* (e.g. a session GUC the retention job sets, checked by a BEFORE DELETE trigger). Cheap, but it is a speed bump against exactly the actor — someone holding the DB credential — who can also just `set` the GUC. Security theatre unless the retention job is the only thing with the credential, which today it is not.
    - *Make the ledger externally verifiable* — hash-chain each observation over its predecessor, or ship an append-only mirror off-box (WORM storage / a second DB the engine can only INSERT to). This is the only option that actually survives a hostile credential-holder, and it is the one worth doing before anyone claims tamper-evidence to an auditor. It is a design task, not a trigger.

    Until one of those lands, the honest claim is **"an observation cannot be UPDATEd"** and nothing stronger. ARCHITECTURE.md §2 and the README now say exactly that, and the CI integrity job carries a comment marking this as deliberately unasserted so its green is not misread as covering it.

---


19. **A rule that cannot read its evidence has nowhere to say so except prose.** `docs/research/README.md` requires an evidence gap to be reported as NOT-ASSESSABLE and never as a pass. There is no such concept in the schema: a finding has a `severity` and a triage `status` (`open`/`suppressed`/`resolved`/…), and a rule that *cannot determine* its answer has exactly two options — stay silent, or fire and explain the gap in `detail` prose that no filter, count, or compliance mapping can read.

    This bit `KAFKA.TOPIC.AUTO_CREATE_ENABLED`. The broker types `allow.everyone.if.no.acl.found` as PASSWORD and *always* redacts it to null, and `_is_true(None)` is `False`, so the rule's escalation gate read "unreadable" as "false" and then wrote the customer a conclusion it had not established: *"an authorizer is configured, so … no security boundary is crossed."* Absence of evidence, sold as evidence of absence, in the append-only ledger. **Fixed** (the redacted-but-explicitly-configured case now states that the question was not settled by this scan, and still does not escalate — escalating on an unknown would be a false positive). But the fix is a sentence in `detail`, not a state. The console still renders that finding as a plain `low`, and a buyer filtering by severity cannot distinguish "we checked, it's fine" from "we could not check".

    **The decision is open and deliberately not made here.** A real fix is a third axis — an assessability state on `findings` (`assessed` / `not_assessable`) with a reason, written by the detector, surfaced in the console and consumed by `compliance/map.py::evaluate()` (which already refuses to emit `pass`, and would then have a principled source for `unknown` instead of inferring it from silence). That is a migration, a contract change to `Hit`, a console change, and a rulepack-wide audit of every `continue`-on-unknown branch — too large to land inside a detector fix, and it interacts directly with gap #4's attestation question. Until it exists, treat any VectaSec `low` on a redaction-prone key as "unproven", not "clean".

## What to do next (opinionated)

In order, cheapest-first among the things that unblock the most:

1. **Call `compliance.evaluate()` from the scan loop.** One line of wiring turns 1000 lines of written work into a working page.
2. **Give Kafka edges.** `broker → topic`. Makes the graph, blast radius, and the whole "integration layer" story non-empty on the one target that works.
3. **Delete one of the two blast-radius implementations.** Keep `graph.py`'s — it's the correct one — and have the API call it.
4. **Wire console sign-in.** The console is finished work sitting behind a locked door.
5. **Push, so CI actually runs.** The integrity and cross-tenant jobs exist and pass locally against a replica; until the tree is committed and pushed they gate nothing (gap #12). Then take gap #15 — a hash-chained or externally mirrored ledger — before anyone shows an auditor the word "tamper-evident".
6. **Make `run_scan` adopt a `scan_id`, then write the worker.** Unblocks queued scans and, after it, the collector bridge.
7. **JWT verification in `api/main.py`.** Required before the engine is reachable from anywhere but localhost.
