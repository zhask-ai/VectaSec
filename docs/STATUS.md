# VectaSec — Status

**As of 2026-07-23.** Verified by reading the code, running both unit suites, and printing the
live registry (`uv run vectasec rules`). Every claim below points at a file. If a file isn't
named, treat the claim as unsupported.

Two scoping notes for this revision, stated up front because the contract demands them:

- **This snapshot was taken while work was landing.** At read time the tree contained in-flight,
  partially-landed work (an action/notification layer, an RBAC surface, Azure/GCP connectors were
  all being built concurrently). In-flight pieces are **deliberately not assessed here** — this
  document describes only what could be verified in the tree at read time, and says so where the
  edge was visibly moving.
- **"In the tree" and "on GitHub" are no longer the same thing.** The repo is pushed
  (`github.com/zhask-ai/VectaSec`; local `main` = `origin/main` at commit `1161ab3`), but a large
  part of what this document describes — the AWS and K8s connectors, Vault credentials
  (`creds.py`), the `20260723*` migrations, the MCP dual-generation migration, the header-trust
  default-OFF change — was **uncommitted working-tree state** at read time (`git status`: ~19
  modified + ~17 untracked files, ~1,700 diff lines). Where it matters, each claim below says
  which side of that line it sits on.

Phases refer to [vectasec-build-plan.md](vectasec-build-plan.md) §18; the forward plan is
[vectasec-v4-blueprint.md](vectasec-v4-blueprint.md).

**One-line summary:** the deterministic core is real, provable, and now *broad* — 7 connectors /
129 detectors including an agentless AWS path and a Kubernetes/mesh connector — with verified-token
API auth, Vault-held credentials, DB-side continuous scheduling, a hash-chained evidence ledger,
and compliance evaluation actually wired in. What is still unproven: the collector round trip,
the on-prem stack, CI on GitHub, and everything involving a second human (SSO/SAML/SCIM, a design
partner, SOC 2).

---

## What actually works, end to end

**The console path** (observed working 2026-07-17 against the live Supabase project; the engine
suite covering the same endpoints passed locally 2026-07-23 — the flow itself was not re-driven
for this revision):

```
uv run python -m vectasec.api.main     # engine API
uv run vectasec worker                 # queue consumer
pnpm -C apps/web dev                   # console
```

Sign in → Connections → **+ Connect a system** → pick a connector, fill its declared fields →
submit. The engine validates the config, splits declared-secret fields into Supabase Vault
(working tree — see DONE), writes the connection, enqueues the first scan on `pgmq`; the worker
adopts the queued row, scans, and commits findings + cited observations in one transaction;
Connections re-renders with counts, `/scans` shows the run, the findings queue facets by rulepack.
Per-row **Scan now**, **Test**, **Remove** verified 2026-07-17.

**The CLI-only path:**

```
docker compose -f deploy/dev/docker-compose.yml up -d
cd services/engine && uv run vectasec scan --type kafka --bootstrap localhost:9092
uv run vectasec findings
```

Misconfigured Kafka, RabbitMQ, Redis → read-only collection → deterministic detectors → findings
and cited observations in one transaction, deduped by fingerprint, idempotent on re-run.

**Verified today (2026-07-23):** `uv run vectasec rules` → **129 rules across 9 packs, 7
connectors** (AWS 21, MCP 24, KAFKA 20, K8S 18, RABBITMQ 18, KONG 16, REDIS 6, NHI 4, DATA 2).
`uv run pytest`: **914 passed** in `services/engine`, **55 passed** in `services/collector`. (The
counts will drift; run them yourself. They are recorded here as *observed on this date*, not as a
contract.)

Nothing else in this document reaches that bar.

---

## DONE

Rows added or materially changed since the 07-17 revision are marked **new**. "Pushed" /
"working tree" states where each sits relative to `origin/main` at read time.

| Thing | Where | Notes |
|---|---|---|
| **Repo pushed** (new) | `github.com/zhask-ai/VectaSec` | 8 commits; local `main` == `origin/main` (`1161ab3`). The 07-17 "3 commits, most of the tree untracked" state is over. **But**: the 2026-07-23 work described below was still uncommitted at read time — GitHub's `main` does not yet contain it. |
| **Engine API auth: verified tokens** (new) | `api/auth.py`, `api/main.py::principal()` | Three paths — see the auth matrix in [ARCHITECTURE.md](ARCHITECTURE.md). (1) Engine service token (`VECTASEC_ENGINE_TOKEN`, constant-time compare, optional tenant pinning) for the console's server side; (2) Supabase user JWT verified against the project's public JWKS (ES256/RS256, `aud`+`exp`+`sub` enforced), tenant resolved from `tenant_members`, never from the request; (3) bare `X-VectaSec-*` headers **only** when `VECTASEC_DEV_TRUST_HEADERS` is explicitly enabled — **default OFF, no localhost carve-out**, with a loud startup warning when on. JWT verification (`api/auth.py`) is pushed; the default-OFF flip and the engine-token path were working-tree at read time — **`origin/main` still defaults header trust ON**. Tested in `tests/test_api_auth.py`, `tests/test_auth.py`. |
| **Credentials in Supabase Vault** (new) | `creds.py`, `supabase/migrations/20260723000002_vault_creds.sql`, `scan.py::ensure_connection_with_creds` | Gap #11b closed in the tree: fields a connector declares `secret=True` are split out of `config` at write time (API, CLI, scan), stored as one Vault secret per connection, referenced by `connections.creds_ref` (now a real uuid), merged back **in memory only** at collect time. Empty re-submitted secret = "unchanged", not "empty password". Secret deleted in the same transaction as its connection. The migration backfills pre-existing plaintext rows and documents the pgmq-archive purge (`delete from pgmq.a_vectasec_scans`) — the backfill and purge are reported executed against the live project on 2026-07-23, which this document **cannot verify from the tree**. Working tree, not pushed. Tests: `tests/test_creds.py`. |
| **Compliance actually evaluates** (new) | `scan.py` (both persist paths), `compliance/map.py::evaluate()`, migrations `006`/`007` | The 07-17 "nothing calls it" gap is closed and **pushed**: `evaluate()` runs inside the same transaction as every completed scan (inline/worker and collector-push paths both), so `controls` can never lag findings. The no-pass contract survived intact and got its missing halves: `control_attestations` (006) lets a human attestation turn a clean control into `pass` (a live failing finding always beats it), and `controls.unknown_finding_ids` (007) keeps not-assessable findings as coverage gaps, never fails. `POST /compliance/{framework}/{control_id}/attest` is the API surface. |
| **Assessability is a state, not prose** (new) | migration 006 (`findings.assessment`), `contracts.py` `Hit.assessable`, used throughout `detect/aws.py`, `detect/k8s.py`, `detect/rabbitmq.py` | Gap #19 closed and pushed: a rule that cannot read its evidence files a `not_assessable` finding with a reason — a first-class coverage gap the console renders distinctly and `evaluate()` maps to `unknown`. AccessDenied on an AWS service, a 403 on a K8s resource type, a redacted Kafka config — all land as this state, never as silence or a pass. |
| **Hash-chained evidence ledger** (new) | migrations 006 (`prev_hash`/`row_hash`, `verify_ledger()`), 008 (FK housekeeping) | Gap #15's chosen option landed and is pushed: each observation hashes over its predecessor per finding; delete, reinsert, or reorder breaks the chain and `verify_ledger()` reports where. Honest limits: rows written before 006 carry no hash (excluded, stated in the migration); `verify_ledger()` is a SQL function **nothing schedules or exposes** — no CLI/API surface calls it, so tamper-evidence exists but tamper-*checking* is a manual query; and the chain detects rewrites, it does not prevent them — an external WORM mirror remains undone. 008 fixes the trigger blocking `ON DELETE SET NULL` on `resource_id` (resource churn used to abort), narrowing append-only to the evidence fields, which is what the guarantee was always about. |
| **Realtime wired in the schema** (new) | migration 006 §3 | Gap #7 closed and pushed: `findings` and `scans` added to the `supabase_realtime` publication (guarded, idempotent). RLS still governs what a subscriber receives. `LiveFindings.tsx` was written for this; live delivery **observed working is not claimed here** — the DB prerequisite exists now, the end-to-end observation is still owed. |
| **Kafka emits edges** (new) | `connect/kafka.py` (`broker --hosts--> topic`), `tests/test_connect_kafka_edges.py` | Gap #9 closed, pushed. The end-to-end target no longer produces an empty graph. |
| **One blast-radius implementation** (new) | `graph.py`, `api/main.py::blast_radius` | Gap #6 closed, pushed: the endpoint now delegates to `graph.blast_radius` (per-path cycle guard, shortest-path, `depth_bounded` truncation flag, undirected default) and only enriches with open-finding counts and edges. The divergent inline walk is gone. `tests/test_graph.py`. |
| **Continuous scheduling, DB-side** (new) | `supabase/migrations/20260723000001_scheduler_trend.sql` | `connections.scan_interval_minutes` (NULL = point-in-time), `queue_due_scans()` run by pg_cron every minute: inserts the same `queued` scans row and pgmq payload as `POST /scans` (shape mirrored from `api/main.py::_enqueue_scan`, validated by `worker.py::parse_job`); collector-mode connections get only the row, for `GET /collector/jobs`. Double-queue guarded (`FOR UPDATE SKIP LOCKED` + skip while queued/running). Working tree, not pushed; **cron execution on the live project is not verified from the tree.** The console shows the cadence (`connections/page.tsx`) and has a whitelist-only set-cadence action (`connections/actions.ts`) — but at the moment this snapshot was read, the `PATCH /connections/{id}` route that action calls was **not present** in `api/main.py` (concurrent work was landing; re-verify before relying on the setter). |
| **Posture history + trend** (new) | same migration (`posture_snapshots` + `snapshot_posture()` trigger), `apps/web/app/page.tsx::PostureTrend` | One snapshot per scan reaching `done`, throttled to one per tenant per 5 minutes. **The trigger duplicates the score formula of `apps/web/lib/posture.ts` digit-for-digit — they must change in lockstep** (see ARCHITECTURE.md, which now carries the warning). Overview renders a 30-point sparkline. Working tree, not pushed. |
| **AWS connector — the agentless path, made real** (new) | `connect/aws.py` (21 rules in `detect/aws.py`) | One connection → SQS, SNS, EventBridge, MSK, API Gateway v1+v2, per region, strictly List*/Get*/Describe*. Cross-account `AssumeRole` + ExternalId is a declared field — the README's agentless claim is now true **for AWS specifically** and still false for everything else. Per-service error isolation; AccessDenied → not-assessable findings. Pure parse layer tested against golden fixtures (`tests/fixtures/aws_responses.json`) — boto3 and live accounts stay out of the suite, which also means **no live AWS account has been scanned in CI**. Working tree, not pushed. |
| **Kubernetes/mesh connector** (new) | `connect/k8s.py` (18 rules in `detect/k8s.py`) | One cluster read → Istio, Linkerd, Gateway API, Ingress, Service exposure, RBAC, ServiceAccounts + token secrets. LIST/GET only; token values never leave the metadata snapshot; 404 = CRDs absent, 403 = recorded and not-assessable. Pure `_build_resources` tested offline. Working tree, not pushed; **no live cluster scan is claimed.** |
| **MCP dual-generation migration** (new) | `connect/mcp.py`, `detect/mcp.py` (24 rules) | The 07-17 pack was pinned to spec `2025-11-25` — a revision superseded on 2026-07-28. The connector now tries the stateless `server/discover` generation first and falls back to the legacy `initialize` handshake, recording which generation the server speaks; the pack grew lifecycle rules (legacy revision, deprecated features, session dependency, Trace Context) and RFC 9207 `iss` checking. Working tree, not pushed. |
| **Coverage matrix** (new) | [docs/coverage-matrix.md](coverage-matrix.md) | The public, falsifiable per-connector statement: reads, kinds, edges, NHI, rule counts, and — the point — what is *not* covered. |
| Core + platform schema | migrations `20260717000001`–`002` | As before. 18 tenant tables, FORCE RLS, `pgmq` + `pg_cron`. |
| Citation gate | migrations 002 + 005 | Unchanged: deferred constraint triggers on `ai_outputs` + `ai_output_evidence`, all four bypasses attacked in CI. |
| Contracts + registry | `contracts.py`, `registry.py` | Unchanged: `@connector`/`@detector` auto-registration; `Hit` grew `assessable`/`assessment_reason`. |
| Scan loop | `scan.py` | collect → detect → persist, one transaction, fingerprint dedup, stale-marking, per-detector error isolation, suppressions, and now compliance recompute + Vault merge. |
| Connectors (7) / Detectors (129) | `connect/`, `detect/` | Counted from the registry 2026-07-23 (`uv run vectasec rules`). Per-pack breakdown and caveats: [coverage-matrix.md](coverage-matrix.md). |
| NHI / identity model | `identity.py`, `detect/identity.py`, `/identities` | All 7 connectors now feed it — `@identity_extractor` for kafka/rabbitmq/kong/redis/mcp in `identity.py`, aws/k8s inline in their connectors. Credentials remain metadata-only. |
| Data classification (DSPM) | `classify.py`, `detect/data.py` | Unchanged; "named like" honesty intact. |
| Posture score + dashboard | `lib/posture.ts`, `app/page.tsx`, `vectasec posture` | Unchanged formula — now duplicated in the snapshot trigger (see the lockstep warning above). |
| Grounded AI triage | `ai.py` | Citation-gated as before. Gap #14 (single pinned model) is closed: a model *chain* (`MODELS`, primary overridable via `VECTASEC_AI_MODEL`) hands off on unavailability before falling back to deterministic. |
| Engine API (actions) | `api/main.py` | Connection lifecycle, scans, finding status/assign/triage, suppressions, compliance read + attest, blast radius, collector control plane. Audit row per mutation, in-transaction; config keys only in audit detail. |
| Queue worker | `worker.py`, `vectasec worker` | Unchanged: drains `pgmq.vectasec_scans`, adopts rows, poison-message cap, stuck-`running` reaper. |
| CLI | `cli.py` | As before, plus Vault-aware `connections add`/`test`/`rm` (secrets split to Vault, merged in memory, deleted with the connection). |
| Console | `apps/web/app/**` | Routes: `/`, `/findings(/[id])`, `/assets(/[id])`, `/identities`, `/connections`, `/scans`, `/compliance`, `/login`. **Gap #6b (JS row-count cap) is closed and pushed**: `assets/page.tsx` and `connections/page.tsx` now use `LIST_LIMIT` pages + `count: 'exact'` head-counts with visible truncation, never an unbounded select tallied in JS. |
| Collector code | `services/collector/**` | Outbound-only design, local credentials, `redact()` boundary, `preview`. The code, and both endpoint ends. **Not an observed round trip** — see Known gaps. |
| Tests | `services/engine/tests/`, `services/collector/tests/` | Offline unit suites (see "Verified today" for the observed pass on this date; this document still refuses to hardcode a count as a claim). New since 07-17: auth (JWT + collector token + engine token), creds/Vault, AWS/K8s connectors + packs from golden fixtures, kafka edges, graph, MCP dual-generation. Still absent: anything integration-level against a real DB — see Known gaps. |
| CI definition | `.github/workflows/ci.yml` | Engine+collector units, web build, live dev-Kafka detectors, migrations-from-empty, adversarial cross-tenant RLS + integrity triggers. **Green on GitHub: still never observed** — and the 2026-07-23 work was uncommitted at read time, so CI has, at best, run against a tree that predates most of this document. |

---

## PARTIAL

### Phase 0 — Foundation
**Verdict: done in substance, with two proofs still owed.**

- ✅ Schema (10 migrations), hardened RLS, integrity triggers + hash chain, engine, worker,
  connect→scan→findings from both surfaces, sign-in.
- ✅ Realtime prerequisites now in the schema (006) — the *live console update* itself still
  unobserved.
- ⚠️ **CI has never been seen green on GitHub.** The workflow is real and ran locally; the repo
  is pushed; nothing here verifies an Actions run. Push the working tree, open a PR, look.
- ⚠️ **On-prem exists on paper only.** `deploy/onprem/` (Compose, Caddy, Helm) validates
  (`compose config`, `helm lint`, `kubeconform`) and **has never been booted**. It predates the
  auth changes — its README and Caddy CIDR gate were written for the header-trust engine; re-read
  both before any deploy. On-prem parity is unproven.

### Phase 1 — Core product + first sale
**Verdict: the technical spine is nearly done; everything involving a second party is not started.**

| Item | State |
|---|---|
| Collector round trip | ⚠️ Both ends exist (`collector/main.py` ↔ `/collector/*` in `api/main.py`, HMAC service tokens, tenant-scoped job claiming, raw-free results path). **A real collector completing enroll → poll → scan → push against a live engine has still not been observed.** (Migration 008's header mentions a "collector round-trip's cleanup" surfacing a bug — evidence someone exercised parts of it; the tree contains no artifact proving the full loop, so the claim stays: unproven.) |
| Compliance | ✅ Evaluated per scan; attestation flow exists (006 + `/attest`). No OSCAL export, no Article 28 register, no evidence bundle export. |
| Findings workflow | ✅ Status/assign/suppress-with-expiry/triage via the engine API. |
| Continuous scanning | ✅ DB-side (working tree); cron execution on the live project + the console setter route not verified at read time (see DONE). |
| Alerting / Slack / Jira | **In flight at snapshot time** (an action-layer migration and `notify.py` were landing mid-read). Not assessed here; do not claim it either way until it lands and is verified. |
| SSO + RBAC | ❌ No SSO/SAML/SCIM anywhere. An RBAC surface was **in flight** at snapshot time (`apps/web/lib/role.ts` existed, untracked); not assessed here. |
| SOC 2, design partner, customer | ❌ None. Do not claim any of them anywhere. |
| Onboarding (<10-min cloud) | ⚠️ The console flow is close in practice; nothing measures or guides it. |

### Phases 2–3 — Breadth + identity, MCP + enterprise
The 07-17 verdicts are mostly obsolete in the good direction: mesh posture (via K8s), an
agentless cloud path (AWS), MCP current-spec coverage, and cross-connector NHI all exist now.
Supply chain is now built end to end (SBOM/VEX, the live OSV feed, plugin inventory, and
integration-as-code static analysis), and the agentless runtime half spans four sources
(RabbitMQ, Redis, NATS, PgBouncer). Still absent from those phase lists: iPaaS connectors
(any), NHI usage/staleness telemetry, registry/rug-pull detection, the OPTIONAL in-cluster
runtime sensor, enterprise on-prem hardening, billing/metering (`usage` table still written
by nothing), SIEM export, public read API.

---

## NOT BUILT (claimed somewhere, exists nowhere)

- **Agentless for anything but AWS.** The README's cross-account claim is now true for AWS only.
  There is no Azure/GCP code in the tree at read time (in flight — not assessed), and no managed
  path for any broker outside MSK-via-AWS.
- **SSO / SAML / SCIM, invites, password reset, user directory.** Sign-in is email+password only.
- **Supabase Storage, Edge Functions, `packages/`** (`pnpm-workspace.yaml` still globs two
  directories that don't exist; `apps/web/lib/types.ts` is still hand-maintained — gap #13 lives).
- **The OPTIONAL in-cluster eBPF runtime sensor.** The agentless path is built and covers
  four sources; the sensor was always the second half and remains unstarted. Note eBPF
  cannot recover Kafka topic metadata for TLS-enabled Java clients at all (the JSSE
  `SSLEngine` gap), which is why broker-side is the primary path, not the fallback.
- **SOC 2 (any type), a validated on-prem deploy, a design partner, a customer.**

---

## Known gaps — the specific list

Ranked by hurt. Items from 07-17 that closed are gone from this list (see DONE for #4 compliance,
#5 header trust, #6 blast radius, #6b row caps, #7 realtime, #9 kafka edges, #11b/Vault, #14
model pin, #15 hash chain, #19 assessability); their history is in git.

1. **The 2026-07-23 work is uncommitted, so nothing gates it.** At read time `git status` showed
   the AWS/K8s connectors, Vault creds, scheduler migrations, MCP migration, and the auth
   default-flip all outside `origin/main`. Until committed and pushed, CI covers none of it, and
   **GitHub's `main` still ships header-trust default-ON** (`origin/main`'s `api/main.py` reads
   `VECTASEC_DEV_TRUST_HEADERS` defaulting truthy). Committing and pushing is the single cheapest
   risk reduction available.

2. **The engine still trusts the console-asserted actor (and tenant) under the service token.**
   `principal()` path 1: a caller holding `VECTASEC_ENGINE_TOKEN` asserts `X-VectaSec-Tenant`
   (unless pinned via `VECTASEC_ENGINE_TOKEN_TENANT`) and `X-VectaSec-Actor` freely. That is
   authentication of the *service*, not the user — the console verifies the user before calling,
   but the engine cannot distinguish that from a compromised token-holder forging any actor into
   the audit trail. Transitional by design; the end state is per-user JWTs on every console call.

3. **Collector round trip unobserved; on-prem never booted; CI never seen green on GitHub.**
   Three standing "exists but unproven" items — each is one session of running things, not code.

4. **`verify_ledger()` is never called.** The hash chain is only as good as someone checking it:
   no CLI command, endpoint, or cron invokes it. Add `vectasec doctor --verify-ledger` or a
   scheduled check before telling an auditor the word "tamper-evident".

5. **The model still owns `priority`, and observation text is attacker-controlled.** Unchanged
   from 07-17, and the surface *grew*: MCP scans quote hostile servers, and now AWS policy
   documents and K8s annotations are also attacker-influencable text that lands in observations
   and therefore in the AI prompt. The mitigations hold (observation fencing, char caps,
   tamper-note warning in `SYSTEM`; `findings/data.ts` sorts on deterministic severity, never AI
   priority — a steered finding is misdescribed, not hidden). The product decision — take
   `priority` from the model, or refuse downgrades of critical/high — remains deliberately
   unmade. Decide it **before** anything routes, alerts, or SLAs on `priority`; the in-flight
   action layer is exactly such a surface, so this gap is about to stop being theoretical.

6. **The posture formula now exists in two places that must change together.**
   `snapshot_posture()` (migration `20260723000001`) mirrors `apps/web/lib/posture.ts`
   weight-for-weight. Nothing enforces the lockstep. A drift means the sparkline and the live
   score silently disagree — in the one product whose pitch is that its numbers are checkable.
   A shared-fixture test (same counts → same score, JS and SQL) would close this cheaply.

7. **Scheduler correctness is asserted by mirror, not by contract.** `queue_due_scans()`
   reproduces `_enqueue_scan`'s payload shape by hand; `worker.py::parse_job` archives anything
   else as poison. A payload-shape change in Python that forgets the SQL twin turns every
   scheduled scan into archived poison, silently. Same fix shape as #6: one test that feeds the
   SQL-built payload to `parse_job`.

8. **Test coverage is offline-only where it is not absent.** Everything runs against fixtures,
   fakes, and `MockTransport`. Not covered by any test: `scan.py`'s transactional spine against a
   real DB, `api/main.py` tenant scoping, the collector against a real engine, the scheduler
   against real pg_cron, any live AWS account or K8s cluster. The integrity/RLS guarantees are
   exercised only by the CI SQL jobs (never yet observed on GitHub).

9. **Stale env/config examples.** `.env.example` and `apps/web/.env.example` predate the auth
   change: neither mentions `VECTASEC_ENGINE_TOKEN` (which the console's `engine.ts` now sends)
   or `VECTASEC_DEV_TRUST_HEADERS`, and the web example still claims the console has exactly two
   variables. A new operator following them gets a 401 from the engine with no hint why.

10. **Old structural items, still true:** hand-maintained `types.ts` (no `packages/contracts-ts`);
    collector state file is write-only (restart = re-enroll, new id — a wire-protocol decision if
    continuity ever matters); collector client tested against a fake server only; `usage` table
    written by nothing; assets/connections pagination is honest now but the inventory still has
    no way to *page through* beyond the first `LIST_LIMIT` rows.

---

## What to do next (opinionated)

1. **Commit and push the tree, and watch CI go green on GitHub** (gap #1, and the standing
   Phase-0 proof). Everything else in this list assumes the work survives.
2. **Run the collector round trip once, for real** (gap #3). Both ends exist; observe
   enroll → poll → scan → push and write down what broke.
3. **Verify the scheduler end-to-end on the live project**: set a cadence (via SQL if the PATCH
   route hasn't landed), watch `queue_due_scans()` fire on the cron tick, watch the worker drain
   it, watch a `posture_snapshots` row appear.
4. **Add the two lockstep tests** (gaps #6, #7) — cheap, and they guard the only two places where
   SQL silently mirrors application code.
5. **Wire `verify_ledger()` to a surface** (gap #4) before using "tamper-evident" with anyone.
6. **Boot on-prem once.** Its README predates JWT auth and Vault; booting it will surface the
   config drift now rather than in a customer's network.
