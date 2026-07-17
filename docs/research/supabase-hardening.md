# Hardening a Multi-Tenant Supabase/Postgres Control Plane for VectaSec

**Researched:** 2026-07-17
**Scope:** RLS hardening + performance, SECURITY DEFINER, pgmq, pg_cron, Vault, Realtime, API keys.
**Grounding:** Supabase official docs + PostgreSQL official docs. Every claim below is tagged with a confidence level; anything not directly verified against a fetched source is marked explicitly.

> **Reading note.** VectaSec is a *security product*. The threat model is not "a bug leaks a row" — it is "one tenant reads another tenant's findings, and we are the vendor who told them we'd catch that." Everything here is written to that standard: the database enforces isolation, not the application layer.

---

## 0. Executive summary — the non-negotiables

| # | Control | Why |
|---|---------|-----|
| 1 | `ENABLE` **and** `FORCE ROW LEVEL SECURITY` on every tenant table | `ENABLE` alone still lets the **table owner** bypass every policy |
| 2 | App connects as a **non-superuser, non-owner, non-`BYPASSRLS`** role | `FORCE` does *not* stop superusers or `BYPASSRLS` roles |
| 3 | Separate policies per `SELECT`/`INSERT`/`UPDATE`/`DELETE` | `FOR ALL` collapses four different questions into one expression |
| 4 | Every `UPDATE` policy has an **explicit `WITH CHECK`** | Otherwise cross-tenant row hijack — see §3, the real footgun |
| 5 | A **`RESTRICTIVE`** tenant guard on every tenant table | Permissive policies are `OR`-ed; one bad `USING (true)` opens everything |
| 6 | `(select auth.uid())`, not `auth.uid()` | ~180ms → ~9ms; per-row call → cached initplan |
| 7 | `SECURITY DEFINER` helpers pin `search_path` | Otherwise it is a privilege-escalation vector |
| 8 | Engine workers use `pgmq` schema directly; **never** expose `pgmq_public` | Queue is backend-only; don't put it on the Data API at all |
| 9 | Secret keys (`sb_secret_...`) never reach a browser | They authorize as `service_role`, which is `BYPASSRLS` |
| 10 | Adversarial cross-tenant tests in CI | The only proof the above actually holds |

---

## 1. RLS hardening: `FORCE ROW LEVEL SECURITY`

### 1.1 What `ENABLE` alone actually does — and doesn't

```sql
alter table public.findings enable row level security;
```

This makes policies apply to *ordinary* roles. It does **not** apply them to:

- **superusers** — always bypass
- roles with the **`BYPASSRLS`** attribute — always bypass
- the **table owner** — bypasses by default

That third one is the trap. PostgreSQL documents it plainly: superusers and `BYPASSRLS` roles always bypass row security, and *table owners normally bypass row security as well*, though an owner can choose to be subject to it via `ALTER TABLE ... FORCE ROW LEVEL SECURITY`. ([PostgreSQL — Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)) — **Confidence: high.**

So if your migrations run as `postgres` and `postgres` owns `public.findings`, then anything connecting as `postgres` sees **every tenant's findings with RLS silently inert**. No error. No warning. Just a full table scan across all tenants.

### 1.2 What `FORCE` changes

```sql
alter table public.findings force row level security;
```

`FORCE` subjects the **table owner** to the table's policies. That is its entire job. — **Confidence: high** (PostgreSQL docs, above).

**What `FORCE` does *not* do — and this matters:**

- It does **not** constrain a **superuser**.
- It does **not** constrain a role with **`BYPASSRLS`** (which includes Supabase's `service_role`).

`FORCE` is therefore necessary but insufficient. It closes the owner hole only. The superuser/`BYPASSRLS` hole is closed by *connection hygiene* (§2), not by DDL.

### 1.3 Apply it everywhere, mechanically

```sql
-- Run for every tenant-scoped table. Do not hand-maintain this list.
do $$
declare t record;
begin
  for t in
    select c.relname
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relkind = 'r'
      and exists (
        select 1 from pg_attribute a
        where a.attrelid = c.oid
          and a.attname = 'tenant_id'
          and not a.attisdropped
      )
  loop
    execute format('alter table public.%I enable row level security', t.relname);
    execute format('alter table public.%I force  row level security', t.relname);
  end loop;
end $$;
```

**CI assertion — fail the build if any `tenant_id` table is unprotected:**

```sql
-- Must return zero rows.
select c.relname, c.relrowsecurity, c.relforcerowsecurity
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind = 'r'
  and exists (
    select 1 from pg_attribute a
    where a.attrelid = c.oid and a.attname = 'tenant_id' and not a.attisdropped
  )
  and (c.relrowsecurity = false or c.relforcerowsecurity = false);
```

`pg_class.relrowsecurity` / `relforcerowsecurity` are the catalog columns backing `ENABLE`/`FORCE`. — **Confidence: high** (standard catalog; consistent with the documented feature split).

---

## 2. Why the app must not connect as superuser or table owner

### 2.1 The rule

The application's runtime role must be **none of**: superuser, `BYPASSRLS`, or the owner of the tenant tables.

Rationale, restated from §1: RLS is bypassed by all three. `FORCE` fixes only the owner case. If your app connects as the owner *and* you forgot `FORCE`, RLS is decorative.

### 2.2 Supabase's roles, and where the danger is

- **`anon`** — unauthenticated Data API. Subject to RLS.
- **`authenticated`** — logged-in user. Subject to RLS.
- **`service_role`** — **has the `BYPASSRLS` attribute** and full access to project data. ([Supabase — Understanding API keys](https://supabase.com/docs/guides/getting-started/api-keys)) — **Confidence: high.**
- **`postgres`** — the Supabase project superuser-equivalent/owner. Migrations only.

Supabase is explicit that service keys bypass RLS entirely and must never be exposed to browsers or customers. ([Supabase — Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)) — **Confidence: high.**

> **One documented subtlety worth knowing:** Supabase notes that it will adhere to the RLS policy of the *signed-in user* even when the client library is initialized with a service key — i.e. if you pass a user JWT on the request, the user's policies apply. ([Supabase — RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)) — **Confidence: medium.** Do **not** build on this. It is a property of how the client attaches the `Authorization` header, and it is far too subtle to be a security control. Treat "secret key present" as "RLS is off."

### 2.3 The VectaSec engine role

The engine (scanner/detector workers) needs to write findings across tenants. The lazy answer is `service_role`. **Reject it.** A `BYPASSRLS` role for the component that parses untrusted collector input is exactly backwards — that is the component *most* likely to be exploited.

Recommended: a dedicated, RLS-subject role whose tenant scope is set per unit of work.

```sql
-- Dedicated engine role: NOT owner, NOT superuser, NOT bypassrls.
create role vectasec_engine nologin;
grant usage on schema public to vectasec_engine;
grant select, insert, update on public.findings, public.resources to vectasec_engine;
-- No DDL, no ownership, no BYPASSRLS. Explicitly:
alter role vectasec_engine nobypassrls;

-- The engine declares which tenant it is acting for, per transaction.
-- set_config(..., true) = transaction-scoped, so it cannot leak across pooled connections.
create or replace function public.engine_tenant()
returns uuid
language sql
stable
set search_path = ''
as $$
  select nullif(current_setting('vectasec.tenant_id', true), '')::uuid;
$$;

create policy engine_tenant_isolation on public.findings
  as restrictive
  to vectasec_engine
  using (tenant_id = public.engine_tenant())
  with check (tenant_id = public.engine_tenant());
```

The worker then does, inside its transaction:

```sql
select set_config('vectasec.tenant_id', $1, true);  -- true => transaction-local
```

**Why `true` (transaction-local) is load-bearing:** with a connection pooler, a session-local setting survives into the *next* tenant's work on that same connection. Transaction-local `set_config` is reset at commit/rollback. This is a real cross-tenant bug class under PgBouncer/Supavisor. — **Confidence: high** on `set_config` semantics (standard Postgres); **medium** on pooler interaction specifics for Supavisor, which we have not verified against docs here.

**Caveat, stated honestly:** this pattern means a compromised engine that can call `set_config` arbitrarily can pivot tenants. It is strictly better than `BYPASSRLS` (which needs no pivot at all) but it is not a hard boundary. The hard boundary for the engine is process/network isolation plus the fact that the collector holds credentials, not us. Flagging rather than overselling.

---

## 3. `USING` vs `WITH CHECK` — the actual footgun

This is the single highest-value section in this document. Read it twice.

### 3.1 The semantics

| Clause | Evaluated against | Applies to |
|--------|-------------------|------------|
| `USING` | the **existing** row | `SELECT`, `UPDATE`, `DELETE` |
| `WITH CHECK` | the **new / proposed** row | `INSERT`, `UPDATE` |

- `SELECT` and `DELETE` take **`USING` only** — there is no new row to check.
- `INSERT` takes **`WITH CHECK` only** — there is no existing row to filter.
- `UPDATE` takes **both**, and they answer *different questions*:
  - `USING` → "may you touch this row **as it is now**?"
  - `WITH CHECK` → "may this row exist **as you are about to write it**?"

— **Confidence: high** ([PostgreSQL — Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html); [Supabase — RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)).

### 3.2 The default that saves you — and the one that kills you

**The default is safe.** When `WITH CHECK` is omitted, PostgreSQL uses the `USING` expression for it. Supabase states this directly for `UPDATE`: with only `USING` defined, that expression determines both which rows are visible and which new rows are allowed. — **Confidence: high** (both sources).

```sql
-- SAFE (by default). Omitted WITH CHECK inherits USING.
create policy findings_update on public.findings
  for update to authenticated
  using (tenant_id = (select public.current_tenant_id()));
-- => WITH CHECK is implicitly (tenant_id = current_tenant_id())
-- => you cannot move a row to another tenant. Good.
```

**The kill shot is writing `WITH CHECK` *wrong*, not omitting it.**

```sql
-- ☠️ CATASTROPHIC. This is the footgun.
create policy findings_update on public.findings
  for update to authenticated
  using      (tenant_id = (select public.current_tenant_id()))
  with check (true);
```

Read what that permits. `USING` says: you may only touch rows belonging to your tenant — sounds airtight. `WITH CHECK (true)` says: **and you may rewrite that row into any shape at all, including `tenant_id = <someone else's>`.**

So Tenant A runs:

```sql
update findings set tenant_id = '<tenant-B-uuid>' where id = '<a-finding-A-owns>';
```

`USING` passes (A owns the row *now*). `WITH CHECK (true)` passes (everything passes). The row is **teleported into Tenant B's account**. In VectaSec terms: **Tenant A just injected a forged security finding into Tenant B's console.** For a security product, that is not a data leak — it is an integrity compromise of the product's core claim. The inverse (`tenant_id` of B's row set to A) is the exfiltration direction, reachable the same way if `USING` is ever loosened.

**Why does anyone write `with check (true)`?** Because they hit a "new row violates row-level security policy" error on a legitimate update, and `with check (true)` makes the error go away. It is the single most likely way this bug enters the codebase — a developer silencing an error they didn't read. Treat `with check (true)` as a **CI-blocking pattern**.

### 3.3 The second footgun: permissive policies are `OR`-ed

Multiple **permissive** policies (the default) combine with **`OR`**. Multiple **restrictive** policies combine with **`AND`**. The full expression is:

```
(permissive1 OR permissive2 OR ...) AND restrictive1 AND restrictive2 AND ...
```

— **Confidence: high** ([PostgreSQL — Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)).

Consequence: **any single careless permissive policy defeats every other permissive policy on that table.** Someone adds `create policy debug_temp on findings for select using (true);` during an incident, forgets to drop it, and every tenant now reads every finding — while all your careful tenant policies still sit there looking correct.

**Defense: a `RESTRICTIVE` tenant guard.** It is `AND`-ed, so it cannot be `OR`-ed away.

```sql
-- The floor. No permissive policy can override this.
create policy tenant_isolation_guard on public.findings
  as restrictive
  to authenticated
  using      (tenant_id = (select public.current_tenant_id()))
  with check (tenant_id = (select public.current_tenant_id()));
```

Then permissive policies express *feature* logic (role-based read/write) and are free to be liberal, because the restrictive guard still floors them at the tenant boundary. This is a defense-in-depth posture appropriate to a security product. — **Confidence: high** on mechanics; the architectural recommendation is our synthesis.

### 3.4 Separate policies per command vs `FOR ALL`

`FOR ALL` is the default and covers `SELECT`/`INSERT`/`UPDATE`/`DELETE` with one expression pair. — **Confidence: high** (PostgreSQL docs).

**Don't use it on tenant tables.** Reasons:

1. **The four questions differ.** A viewer may `SELECT` but not `DELETE`; an analyst may `UPDATE` status but not `INSERT` forged findings. `FOR ALL` forces one expression to answer all four, so it degrades to the loosest one that makes the app work.
2. **It obscures the `USING`/`WITH CHECK` split.** Under `FOR ALL`, `USING` silently becomes the `INSERT` `WITH CHECK` too. That coupling is invisible at the call site and breaks the moment you split the policy later.
3. **Auditability.** A reviewer (or a customer's auditor) reading `for delete to authenticated using (...)` can verify one claim. Reading `for all` requires simulating four code paths.

VectaSec's own build plan already commits to this: "separate policies per `SELECT`/`INSERT`/`UPDATE`/`DELETE`" (`vectasec-build-plan.md`, line 258). Good — keep it.

```sql
-- The explicit four, plus the restrictive guard from §3.3.
create policy findings_select on public.findings
  for select to authenticated
  using (tenant_id = (select public.current_tenant_id()));

create policy findings_insert on public.findings
  for insert to authenticated
  with check (tenant_id = (select public.current_tenant_id()));

create policy findings_update on public.findings
  for update to authenticated
  using      (tenant_id = (select public.current_tenant_id()))
  with check (tenant_id = (select public.current_tenant_id()));  -- explicit, not inherited

create policy findings_delete on public.findings
  for delete to authenticated
  using (
    tenant_id = (select public.current_tenant_id())
    and (select public.has_role('owner','admin'))
  );
```

Note `findings_update` writes `WITH CHECK` **explicitly** even though the inherited default would be identical. Rationale: the default is invisible, and a later edit to `USING` silently changes `WITH CHECK`. Explicit is auditable.

> **`RETURNING` requires a `SELECT` policy.** `insert ... returning *` (which is what supabase-js `.insert().select()` does) needs a `SELECT` policy to return the row. Supabase notes a corresponding `SELECT` policy is required for `UPDATE`. A missing `SELECT` policy shows up as a confusing empty/errored response on an insert that *did* succeed. — **Confidence: medium-high.**

### 3.5 CI: adversarial cross-tenant tests

Policies are code. Untested code is broken code. This is the control that actually proves §1–§3.

```sql
-- tests/rls_cross_tenant.sql — must pass in CI, run as a NON-owner role.
begin;

set local role authenticated;
set local request.jwt.claims = '{"sub":"<user-in-tenant-A>","role":"authenticated"}';

-- 1. Cannot SEE tenant B.
do $$ begin
  if exists (select 1 from public.findings where tenant_id = '<tenant-B>') then
    raise exception 'FAIL: cross-tenant SELECT leak';
  end if;
end $$;

-- 2. Cannot INSERT into tenant B.
do $$ begin
  begin
    insert into public.findings (tenant_id, title) values ('<tenant-B>', 'forged');
    raise exception 'FAIL: cross-tenant INSERT allowed';
  exception when insufficient_privilege then null;  -- expected
  end;
end $$;

-- 3. THE FOOTGUN TEST: cannot TELEPORT own row into tenant B.
do $$ declare n int; begin
  update public.findings set tenant_id = '<tenant-B>'
   where tenant_id = '<tenant-A>';
  get diagnostics n = row_count;
  if n > 0 then raise exception 'FAIL: WITH CHECK allows tenant teleport'; end if;
exception when insufficient_privilege then null;  -- also acceptable
end $$;

rollback;
```

Test #3 is the one that catches §3.2. **It must exist.** Also add a static check that rejects `with check (true)` on any `tenant_id` table:

```sql
-- Must return zero rows.
select polrelid::regclass as tbl, polname
from pg_policy
where pg_get_expr(polwithcheck, polrelid) = 'true'
  and polrelid in (
    select attrelid from pg_attribute
    where attname = 'tenant_id' and not attisdropped
  );
```

---

## 4. RLS performance

RLS policies are injected as an implicit `WHERE` clause on every query. Written naively, they run **per row**. Supabase publishes benchmarks for each fix.

### 4.1 Wrap `auth.uid()` in `(select ...)` — the big one

```sql
-- Slow: auth.uid() is called once PER ROW.
using ( auth.uid() = user_id )

-- Fast: evaluated ONCE per statement, cached as an initPlan.
using ( (select auth.uid()) = user_id )
```

The `(select ...)` wrapper lets the planner hoist the call into an **initPlan** — evaluated once per statement rather than once per row. Supabase's published numbers:

| Change | Before | After | Improvement |
|--------|--------|-------|-------------|
| `(select auth.uid())` wrapper | 179 ms | 9 ms | **94.97%** |
| Same, multi-function policy | 11,000 ms | 10 ms | **99.91%** |
| Index on policy column | 171 ms | <0.1 ms | **99.94%** |
| Add matching client-side filter | 171 ms | 9 ms | **94.74%** |
| `SECURITY DEFINER` helper (vs join) | 178,000 ms | 12 ms | **99.993%** |
| Rewrite to avoid join | 9,000 ms | 20 ms | **99.78%** |
| Specify `TO authenticated` (anon access) | 170 ms | <0.1 ms | **99.78%** |

— **Confidence: high** that these figures are Supabase's published benchmarks ([Supabase — RLS Performance](https://supabase.com/docs/guides/database/postgres/row-level-security)). **Confidence: low** that they transfer to VectaSec's workload — they are synthetic, on Supabase's test tables, at unstated row counts and hardware. Use them for *ranking* the optimizations, not for capacity planning. Measure our own.

The technique generalizes: wrap **any** stable function call in a policy — `(select public.current_tenant_id())`, `(select public.has_role(...))` — for the same initPlan caching.

### 4.2 Index `tenant_id` — always

Every VectaSec tenant table is filtered by `tenant_id` on literally every query. Unindexed, each policy evaluation degrades to a seq scan.

```sql
create index concurrently if not exists findings_tenant_id_idx
  on public.findings using btree (tenant_id);

-- Better: composite, matching real access patterns.
-- The console lists findings by tenant, newest first, filtered by severity.
create index concurrently if not exists findings_tenant_severity_seen_idx
  on public.findings using btree (tenant_id, severity, last_seen desc);
```

Put `tenant_id` **first** in composite indexes — it is the highest-selectivity, always-present predicate, and a leading `tenant_id` serves both the policy and the query. — **Confidence: high** on the indexing principle; the specific composite is a design suggestion to validate against real query plans.

Use `concurrently` for indexes added to populated tables to avoid taking a write lock. (Note: `create index concurrently` cannot run inside a transaction block, which matters for migration tooling.) — **Confidence: high.**

### 4.3 Specify `TO <role>` on every policy

```sql
-- Without TO, this policy is evaluated even for anon users who can never pass it.
create policy findings_select on public.findings
  for select
  to authenticated          -- <-- prevents evaluation for anon entirely
  using ( tenant_id = (select public.current_tenant_id()) );
```

Supabase reports 170 ms → <0.1 ms for anon access on a policy that added `TO authenticated`. — **Confidence: high** (source); the mechanism is that Postgres skips policies whose role doesn't match.

### 4.4 Avoid joins inside policies

Rewrite so the policy filters the *target* table's column against a subquery on the *source* table, rather than joining the two:

```sql
-- Slow: correlates against the row being filtered (a join per row).
using (
  (select auth.uid()) in (
    select user_id from tenant_members where tenant_members.tenant_id = tenant_id
  )
)

-- Fast: build the set once, test membership.
using (
  tenant_id in (
    select tenant_id from tenant_members where user_id = (select auth.uid())
  )
)
```

Supabase reports 9,000 ms → 20 ms. — **Confidence: high** (source).

Note the first form also has a subtle **column-ambiguity bug**: bare `tenant_id` inside the subquery resolves to `tenant_members.tenant_id`, not the outer table's, making the predicate a tautology (`tenant_members.tenant_id = tenant_members.tenant_id`). This is a *correctness* bug that reads as a *performance* smell — **always qualify columns in policies**. — **Confidence: high** on Postgres name-resolution rules (inner scope wins).

### 4.5 Add redundant client-side filters

Even though RLS enforces the tenant, have the client *also* send it:

```ts
const { data } = await supabase
  .from('findings')
  .select('*')
  .eq('tenant_id', tenantId)   // redundant for security, valuable for the planner
  .order('last_seen', { ascending: false })
```

171 ms → 9 ms in Supabase's benchmark. The filter gives the planner an index-usable predicate up front instead of relying on it to push the policy expression down. This is a **performance** measure only — never a security one; the RLS policy remains the enforcement. — **Confidence: high**.

---

## 5. `SECURITY DEFINER` functions

### 5.1 The `search_path` injection vector

A `SECURITY DEFINER` function runs with the **owner's** privileges. If its `search_path` is attacker-influenced, the attacker chooses *which objects the function touches* — and those touches happen as the owner (often `postgres`).

PostgreSQL is blunt about the mechanism: `search_path` should exclude schemas writable by untrusted users, which prevents malicious users from creating objects that **mask** objects intended to be used by the function. The temporary schema `pg_temp` is the sharp edge — it is searched first by default and is normally **writable by anyone**. ([PostgreSQL — CREATE FUNCTION](https://www.postgresql.org/docs/current/sql-createfunction.html)) — **Confidence: high.**

**The concrete attack.** Given an unpinned `SECURITY DEFINER` function owned by `postgres` that reads `tenant_members`:

```sql
-- Attacker, as a lowly authenticated user:
create temp table tenant_members (user_id uuid, tenant_id uuid);
insert into tenant_members values (auth.uid(), '<every-tenant-uuid>');
-- Now call the helper. It resolves `tenant_members` to pg_temp.tenant_members
-- (searched first), reads the attacker's fabricated rows, and returns
-- "you are a member of every tenant" — computed with postgres's privileges.
```

Every RLS policy built on that helper now authorizes the attacker for every tenant. **This escalates a normal user to full cross-tenant read.** For VectaSec that is a company-ending bug, and it is caused by one missing clause.

### 5.2 The fix — pin `search_path`

Two accepted forms:

**Form A — Supabase's convention: empty `search_path` + fully-qualified names.**

```sql
create or replace function public.current_tenant_id()
returns uuid
language sql
stable
security definer
set search_path = ''          -- <-- nothing is implicitly resolvable
as $$
  select u.tenant_id
  from public.users u          -- <-- MUST be schema-qualified now
  where u.id = (select auth.uid());
$$;
```

Supabase's own RBAC guide uses exactly this shape: `language plpgsql stable security definer set search_path = ''`. ([Supabase — Custom Claims & RBAC](https://supabase.com/docs/guides/database/postgres/custom-claims-and-role-based-access-control-rbac)) — **Confidence: high.**

With `search_path = ''`, **every** object reference must be schema-qualified (including `public.`, and types). It fails loudly at creation time if you forget — which is precisely why it's the better default: the failure mode is a broken migration, not a silent breach.

**Form B — PostgreSQL's documented form: trusted schemas, `pg_temp` last.**

```sql
... security definer
    set search_path = admin, pg_temp;
```

PostgreSQL's guidance: force the temporary schema to be searched **last** by writing `pg_temp` as the final entry. It warns that without the `SET` clause — *or with one mentioning only `admin`* — the function can be subverted by creating a temporary table shadowing the intended one. ([PostgreSQL — CREATE FUNCTION](https://www.postgresql.org/docs/current/sql-createfunction.html)) — **Confidence: high.**

> Subtle and worth internalizing: `set search_path = admin` (without `pg_temp`) is **still vulnerable**, because `pg_temp` is *implicitly* searched first when not named. You must name it explicitly to demote it. **Prefer Form A** (`= ''`) for VectaSec — it has no implicit anything.

### 5.3 Lock down execution

`SECURITY DEFINER` functions are `EXECUTE`-able by `PUBLIC` by default. Revoke, then grant narrowly — PostgreSQL recommends doing this in the **same transaction** as creation, so there is no window where the function exists and is world-executable:

```sql
begin;
create function public.current_tenant_id() ... security definer set search_path = '';
revoke all on function public.current_tenant_id() from public;
grant execute on function public.current_tenant_id() to authenticated;
commit;
```

— **Confidence: high** ([PostgreSQL — CREATE FUNCTION](https://www.postgresql.org/docs/current/sql-createfunction.html)).

Supabase's RBAC guide shows the same discipline for its auth hook: `grant execute ... to supabase_auth_admin; revoke execute ... from authenticated, anon, public;`. — **Confidence: high** (source).

**Additionally: keep definer helpers out of exposed schemas.** Supabase's guidance is to never create security-definer functions in schemas exposed to the API. Put VectaSec's helpers in a `private` schema that PostgREST cannot see:

```sql
create schema if not exists private;
revoke all on schema private from anon, authenticated;
-- Helpers live here; policies reference private.fn(), but no one can CALL them over the API.
```

Note the nuance: a policy can call `private.fn()` even though the caller can't invoke it directly over PostgREST, because the policy executes server-side. That is the point. — **Confidence: high** on the Supabase guidance; **medium** on the exact grant mechanics for policy-internal calls (policies run as the querying role, so the role still needs `EXECUTE`; the protection is that the *schema* isn't exposed to PostgREST, not that execute is denied). Verify in implementation.

### 5.4 The `function_search_path_mutable` linter

Supabase ships a database linter with a `0011_function_search_path_mutable` check that flags functions without a pinned `search_path`. — **Confidence: medium.** The lint exists in the advisor list, but the detail page did not render its remediation text when fetched, so the exact wording is unverified. **Action:** wire `supabase db lint` (or the Advisors tab / `get_advisors` MCP tool) into CI and treat this lint as **blocking**. Independent of the lint, enforce it ourselves:

```sql
-- Must return zero rows: every SECURITY DEFINER function must pin search_path.
select n.nspname, p.proname
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef                                  -- SECURITY DEFINER
  and n.nspname not in ('pg_catalog','information_schema')
  and not exists (
    select 1 from unnest(coalesce(p.proconfig, '{}')) cfg
    where cfg like 'search_path=%'
  );
```

---

## 6. The `tenant_members` recursion trap

### 6.1 The trap

You want a policy on the membership table itself: "you may see membership rows for tenants you belong to."

```sql
-- ☠️ INFINITE RECURSION
create policy members_select on public.tenant_members
  for select to authenticated
  using (
    tenant_id in (
      select tenant_id from public.tenant_members   -- <-- reads the SAME table
      where user_id = (select auth.uid())
    )
  );
```

Evaluating the policy on `tenant_members` requires querying `tenant_members`, which triggers the policy, which queries `tenant_members`… Postgres aborts with **`infinite recursion detected in policy for relation "tenant_members"`**.

This is one of the most commonly reported Supabase RLS failures, and the community-confirmed cause is exactly this: a policy whose lookup is itself subject to the policy — typically a `SELECT` policy that selects from its own table. ([supabase/discussions#3328](https://github.com/orgs/supabase/discussions/3328), [#1138](https://github.com/orgs/supabase/discussions/1138), [#33689](https://github.com/orgs/supabase/discussions/33689)) — **Confidence: high** on the phenomenon and cause; **medium** on wording, since these are community discussions rather than reference docs.

**Why this bites VectaSec specifically:** it appears the moment you move from the current schema (`users(id, tenant_id, ...)` — one tenant per user, per `vectasec-build-plan.md` line 284) to a many-to-many `tenant_members`, which MSSP/partner tenants and "consultant sees 5 client orgs" will force. It also bites *today* on `public.users` if you ever write a `users` policy that queries `users`.

### 6.2 The fix — a `SECURITY DEFINER` helper

The helper runs as its owner and is **not** subject to `tenant_members`' policies, so the recursion is cut. This is the community-recommended fix and matches Supabase's documented performance guidance for definer helpers in policies.

```sql
-- Returns the caller's tenant ids. SECURITY DEFINER => bypasses tenant_members RLS
-- => no recursion. Takes NO arguments: derives identity from the JWT internally,
-- so a caller cannot ask "what are SOMEONE ELSE's tenants?"
create or replace function private.user_tenant_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select tm.tenant_id
  from public.tenant_members tm
  where tm.user_id = (select auth.uid());
$$;

revoke all on function private.user_tenant_ids() from public;
grant execute on function private.user_tenant_ids() to authenticated;

-- Now the policy on the members table does NOT recurse:
create policy members_select on public.tenant_members
  for select to authenticated
  using ( tenant_id in (select private.user_tenant_ids()) );
```

**Three design rules, each load-bearing:**

1. **Take no arguments.** Derive the user from `auth.uid()` *inside* the function. A helper like `user_tenant_ids(p_user_id uuid)` is an enumeration oracle — any user passes any UUID and reads that user's tenants, executed with owner privileges. The community guidance is explicit: don't pass anything in; use `auth.uid()` inside.
2. **Pin `search_path`** (§5). A definer helper without it is the escalation vector, and this one is *reachable from every policy on the system*.
3. **Wrap calls in `(select ...)`** in policies for initPlan caching (§4.1).

### 6.3 When to use a helper vs. an inline subquery

| Situation | Use |
|-----------|-----|
| Policy on `tenant_members` itself | **Helper** (mandatory — subquery recurses) |
| Policy on `findings`/`resources` referencing `tenant_members` | **Either**; subquery is fine and simpler |
| Same membership logic across 15+ tables | **Helper** — one definition to audit and fix |
| Policy needs to read a table the user can't read | **Helper** (definer is the point) |
| Hot path, membership subquery is slow | **Helper** — Supabase benchmarks 178,000 ms → 12 ms |
| Simple, single-table, self-contained predicate | **Subquery** — don't reach for definer reflexively |

**The judgment call:** a `SECURITY DEFINER` helper is a *privilege boundary crossing*. Every one you add is a thing that runs as `postgres` and must be audited. Use them where they're **necessary** (recursion, cross-privilege reads) or **decisively better** (one audited definition vs. 15 copy-pasted subqueries), and not as a reflex. For VectaSec, given `tenant_id` appears on ~10+ tables, **one** well-audited `private.user_tenant_ids()` is the right call — it centralizes the thing most likely to be wrong.

```sql
-- Downstream tables then read cleanly:
create policy findings_select on public.findings
  for select to authenticated
  using ( tenant_id in (select private.user_tenant_ids()) );
```

---

## 7. pgmq (Supabase Queues)

### 7.1 What it is

A Postgres-native durable message queue built on the **pgmq** extension, with guaranteed delivery: a message is delivered exactly once to a consumer **within a customizable visibility window**, and messages can be archived for analytics/compliance. ([Supabase — Queues](https://supabase.com/docs/guides/queues)) — **Confidence: high.**

### 7.2 Enabling it

Dashboard → **Integrations** → **Queues** → enable the `pgmq` extension. Requires Postgres **15.6.1.143 or later**. ([Supabase — Queues Quickstart](https://supabase.com/docs/guides/queues/quickstart)) — **Confidence: high.**

Or in a migration:

```sql
create extension if not exists pgmq;
```

**Confidence: medium** on this exact form for Supabase (docs lead with the Dashboard flow). Verify; prefer whichever the CLI/migration path supports so it's reproducible for the on-prem build.

### 7.3 Queue types

- **Basic** — durable, logged table.
- **Unlogged** — transient, better performance, **may lose messages**.

([Supabase — Queues Quickstart](https://supabase.com/docs/guides/queues/quickstart)) — **Confidence: high.**

Upstream pgmq also documents **partitioned** queues; **confidence: low** on their availability/support on Supabase — not verified.

> **For VectaSec: use Basic (logged).** A dropped scan job means a tenant's connector silently never gets scanned and the console shows stale posture. Silent staleness is the worst failure mode a security product has — it looks identical to "you're secure." The perf win from unlogged is not worth it.

### 7.4 The API

**Underlying `pgmq` schema** ([pgmq/pgmq](https://github.com/pgmq/pgmq)) — **Confidence: high**:

| Function | Purpose |
|----------|---------|
| `pgmq.create(queue_name)` | Create a queue |
| `pgmq.send(queue_name, msg, [delay])` | Enqueue one message |
| `pgmq.send_batch(queue_name, msgs)` | Enqueue an array |
| `pgmq.read(queue_name, vt, qty)` | Read up to `qty`, hide for `vt` seconds |
| `pgmq.pop(queue_name)` | Read + delete immediately |
| `pgmq.delete(queue_name, msg_id)` | Delete (successful processing) |
| `pgmq.archive(queue_name, msg_id)` | Move to archive table |

Tables created: **`pgmq.q_<queue_name>`** (active) and **`pgmq.a_<queue_name>`** (archive). — **Confidence: high.**

`pgmq.set_vt` and `pgmq.read_with_poll` exist upstream (`read_with_poll` long-polls instead of busy-looping, which is what you want for workers) — **confidence: low** on exact signatures; not verified. Check before use.

### 7.5 Visibility timeout — the semantics that matter

The visibility timeout (`vt`) is the window during which a read message is **invisible to other consumers**. If it is **not deleted or archived within `vt`, it becomes visible again** and can be read by another consumer. ([pgmq/pgmq](https://github.com/pgmq/pgmq)) — **Confidence: high.**

This is the entire crash-safety mechanism: a worker that dies mid-scan never deletes its message, `vt` expires, another worker picks it up. It also means delivery is **at-least-once across failures** ("exactly once" holds only *within* the visibility window) — so **VectaSec's scan handlers must be idempotent.** Re-running a scan must upsert resources/findings on a stable natural key, not blind-insert, or a worker timeout produces duplicate findings in the console.

**Set `vt` > worst-case scan duration.** If a Kafka scan can take 4 minutes and `vt` is 60s, the job is redelivered while still running → concurrent duplicate scans → duplicate findings and doubled load on the customer's brokers. Either set `vt` generously or extend it via `set_vt` heartbeats for long scans.

```sql
-- Enqueue (engine side)
select pgmq.send('vectasec_scans', jsonb_build_object(
  'tenant_id',     '<uuid>',
  'connection_id', '<uuid>',
  'kind',          'kafka'
));

-- Worker: read 5 messages, hide them for 600s (> worst-case scan)
select * from pgmq.read('vectasec_scans', 600, 5);

-- On success:
select pgmq.archive('vectasec_scans', <msg_id>);  -- keep for the evidence ledger
```

Prefer **`archive` over `delete`** for VectaSec: the archive table is an audit trail of what was scanned and when, which feeds the evidence/compliance story. Trade-off: `pgmq.a_*` grows unboundedly — pair it with a `pg_cron` retention job (§8).

### 7.6 RLS and exposure — the important call

Queues are **not** on the Data API by default. Enabling **Queues → Settings → Expose Queues via PostgREST** creates a **`pgmq_public`** schema of safe wrappers: `send`, `send_batch`, `read`, `pop`, `archive`, `delete` — and deliberately **not** queue create/drop. If you expose them, you **must enable RLS on all queue tables**. Default grants: `authenticated` = select/insert/update/delete, `anon` = none, `service_role` = full. Supabase warns never to expose `postgres` / `service_role` client-side. ([Supabase — Queues Quickstart](https://supabase.com/docs/guides/queues/quickstart), [Queues API](https://supabase.com/docs/guides/queues/api)) — **Confidence: high.**

> ### Recommendation for VectaSec: **do not enable `pgmq_public` at all.**
>
> Nothing in the browser should touch the scan queue. The console's job is to *request* a scan; the engine's job is to enqueue and consume. Exposing the queue to `authenticated` means a tenant's browser session can `read()` messages — and `read()` is **destructive to other consumers' liveness** (it hides messages for `vt` seconds). A malicious or buggy client could repeatedly `read()` with a long `vt` and **stall the entire scan pipeline for every tenant** — a cross-tenant denial of service with no cross-tenant *read* required. RLS on `pgmq.q_*` would have to be perfect to prevent it, and there is no reason to take that risk.
>
> **Instead:** console → `POST /scans` (Edge Function / engine API) → authorize the tenant → enqueue server-side via the `pgmq` schema. Queue access stays on a trusted backend role. Leave "Expose Queues via PostgREST" **off**, and assert it stays off:
>
> ```sql
> -- Must return zero rows.
> select nspname from pg_namespace where nspname = 'pgmq_public';
> ```
>
> — **Confidence: high** on the mechanics; the recommendation is our architectural judgment.

If you ever *do* expose it, note that the wrapper functions are `SECURITY DEFINER` over the `pgmq` schema, so RLS on `pgmq.q_*` is the only thing standing between tenants — and per §7.6 above, `read()` remains a liveness hazard regardless of RLS.

---

## 8. pg_cron

### 8.1 Enabling and basics

Available as a Postgres extension on Supabase; jobs can run **from every second to once a year**, created via SQL or Dashboard → Integrations → Cron. Jobs run SQL snippets/functions, or make HTTP requests (e.g. invoking an Edge Function). It creates the **`cron`** schema with **`cron.job`** (all jobs) and **`cron.job_run_details`** (per-run status). ([Supabase — Cron](https://supabase.com/docs/guides/cron)) — **Confidence: high.**

```sql
create extension if not exists pg_cron;
```

**Confidence: medium** on this exact invocation for Supabase (the dedicated extension docs page is now a stub redirecting to the Cron guide, which leads with the Dashboard). Verify against the Dashboard/CLI.

### 8.2 Supabase's operational limits

- **Max ~8 concurrent jobs** recommended for good performance.
- Individual jobs limited to a **10-minute** execution window.

([Supabase — Cron](https://supabase.com/docs/guides/cron)) — **Confidence: medium-high** (stated in the guide; "recommended" vs. hard-enforced is not fully clear).

> **This directly shapes VectaSec's design.** A 10-minute cap means **cron must never run a scan**. Cron's only job is to *enqueue* work into pgmq; the workers (which have no such cap) do the scanning. This happens to be the right architecture anyway — it decouples scheduling from execution and lets `vt` handle worker crashes — but note the limit makes it *mandatory*, not optional.

### 8.3 Syntax

```sql
-- Named job, standard 5-field cron.
select cron.schedule(
  'vectasec-enqueue-scans',
  '*/15 * * * *',
  $$ select public.enqueue_due_scans() $$
);

-- Sub-minute: interval syntax, '[1-59] seconds'. Cannot be combined with cron fields.
select cron.schedule('fast-tick', '30 seconds', $$ select public.tick() $$);

-- Remove:
select cron.unschedule('vectasec-enqueue-scans');   -- by name
select cron.unschedule(<job_id>);                   -- by id

-- Modify in place:
select cron.alter_job(<job_id>, schedule := '*/30 * * * *');
```

Signatures: `cron.schedule(schedule text, command text) returns bigint` and `cron.schedule(job_name text, schedule text, command text) returns bigint`. ([citusdata/pg_cron](https://github.com/citusdata/pg_cron)) — **Confidence: high.** **Always use the named form** — anonymous jobs are painful to manage idempotently across migrations.

### 8.4 The one-database constraint

**The pg_cron background worker connects to a single database per cluster** — by default `postgres`, configured via `cron.database_name`. pg_cron may only be *installed* to one database in a cluster. ([citusdata/pg_cron](https://github.com/citusdata/pg_cron)) — **Confidence: high.**

`cron.schedule_in_database(job_name, schedule, command, database, [username], [active])` exists to target *other* databases from the cron database. — **Confidence: high** (source).

**Implications for VectaSec:**

- On Supabase this is a non-issue in practice — you get one database (`postgres`) and that's where cron lives.
- It **is** an issue for the **on-prem/self-hosted** path (Docker Compose + Helm, per the build plan). If an on-prem deployment ever puts VectaSec's schema in a database other than the cron database, `cron.schedule` silently schedules jobs that run in the *wrong* database and fail. Use `schedule_in_database`, or standardize on one database. **Document this in the Helm chart.**
- **Multi-region (US + EU, per the build plan) means separate Supabase projects → separate clusters → independent cron.** Each region schedules its own tenants. Don't build a cross-region scheduler; there isn't one.

### 8.5 Permissions

pg_cron uses RLS on its own catalog: jobs can only be seen and modified by the user that created them, unless that user is a superuser or has `bypassrls`. Grant access via `grant usage on schema cron to <user>`. ([citusdata/pg_cron](https://github.com/citusdata/pg_cron)) — **Confidence: high.**

This is a useful property: schedule VectaSec's jobs as a dedicated role and other roles cannot enumerate or tamper with them.

### 8.6 `job_run_details` grows forever

Records in `cron.job_run_details` are **not cleaned automatically**. The upstream-recommended fix is to schedule the cleanup with pg_cron itself:

```sql
select cron.schedule('purge-cron-history', '0 12 * * *',
  $$ delete from cron.job_run_details where end_time < now() - interval '7 days' $$);
```

— **Confidence: high** ([citusdata/pg_cron](https://github.com/citusdata/pg_cron)). Logging can be disabled entirely with `cron.log_run = off`, but **don't** — for a security product, scheduler run history is audit evidence. Purge on a retention schedule instead of disabling.

### 8.7 Jitter — avoiding the :00 stampede

**No source found for built-in jitter in pg_cron; it does not appear to exist.** Everything below is **our engineering guidance — confidence: low-medium**, and should be validated by load testing.

The build plan already identifies the problem (line 390): schedule recurring scans "**plus jitter** so tenants don't stampede at :00." The failure mode: 500 tenants scheduled `0 * * * *` all fire simultaneously → thundering herd against the DB, the engine, and the customers' brokers.

**Don't** create one cron job per tenant. That blows the ~8-concurrent-job guidance (§8.2) instantly and makes `cron.job` a tenant table.

**Recommended: one dispatcher job, jitter computed in SQL.** Deterministic per-tenant offset via a hash, so a tenant's scan lands at a stable minute (predictable for support, no drift):

```sql
create or replace function public.enqueue_due_scans()
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  r record;
begin
  for r in
    select c.id, c.tenant_id
    from public.connections c
    where c.status = 'active'
      -- Deterministic per-connection slot in a 60-minute window.
      -- hashtextextended is stable across sessions (unlike random()).
      and (abs(hashtextextended(c.id::text, 0)) % 60)
          = extract(minute from now())::int
      and (c.last_scanned_at is null
           or c.last_scanned_at < now() - interval '55 minutes')
  loop
    perform pgmq.send('vectasec_scans', jsonb_build_object(
      'tenant_id', r.tenant_id, 'connection_id', r.id));
  end loop;
end $$;

-- ONE cron job. Runs every minute; each minute enqueues ~1/60th of the fleet.
select cron.schedule('vectasec-dispatch', '* * * * *',
  $$ select public.enqueue_due_scans() $$);
```

**Why `hashtextextended` and not `random()`:** deterministic. A tenant scans at a consistent minute; reruns/restarts don't re-roll the schedule; support can answer "when does my scan run?" Add a small `random()` component only if hash collisions cluster badly in practice.

**Layer two — per-tenant in-flight concurrency cap** (also in the build plan, line 390). Jitter spreads *enqueue*; it does not bound *concurrent work per tenant*. A tenant with 200 connections still floods. Enforce the cap at the **worker** (count in-flight jobs per `tenant_id` before pulling), since pgmq has no native per-key concurrency limit. — **Confidence: low**; design work, not researched.

**Layer three — the 10-minute cap (§8.2) means the dispatcher itself must stay fast.** The loop above is fine for thousands of connections but should be batched (`send_batch`) rather than row-by-row `perform` at real scale.

---

## 9. Supabase Vault

### 9.1 What it is

A Postgres extension plus Supabase UI for storing **encrypted secrets** in the database — API keys, environment variables, credentials — usable from SQL (functions, triggers, webhooks), and staying encrypted in **backups and replication streams**. ([Supabase — Vault](https://supabase.com/docs/guides/database/vault)) — **Confidence: high.**

### 9.2 How it protects secrets

- **AEAD** (Authenticated Encryption with Associated Data), based on **libsodium**.
- Encrypted on disk with an **external root key managed by Supabase** — **keys are never stored in the database**; Supabase holds a unique key per project in secured backend systems.
- **Signatures prevent tampering** — invalid signatures are rejected *before* decryption.
- **Associated data**: other columns can be bound into the signature, preventing a secret from being **swapped between rows**.

— **Confidence: high** (source).

> That last property is quietly important for VectaSec. Associated data means an attacker with `UPDATE` on a `connections` row cannot swap Tenant A's `creds_ref`-backed secret into Tenant B's row and have it decrypt. The tenant binding is cryptographic, not just relational.

### 9.3 Current API

```sql
-- Create
select vault.create_secret('<secret_value>', '<unique_name>', '<description>');

-- Update
select vault.update_secret('<uuid>', '<new_secret>', '<name>', '<description>');

-- Read: decrypts on the fly; remains encrypted on disk.
select decrypted_secret from vault.decrypted_secrets where name = '<unique_name>';
```

Access to `vault.decrypted_secrets` should be **restricted via SQL privileges**. ([Supabase — Vault](https://supabase.com/docs/guides/database/vault)) — **Confidence: high.**

### 9.4 Usage in VectaSec

The build plan's `connections.creds_ref` (line 293) — "Vault ref (cloud) or NULL (collector holds them)" — is the right shape. Notes:

1. **`vault.decrypted_secrets` must never be reachable from `anon`/`authenticated`.** It is a view; it has no tenant concept. Anyone who can select it reads **every tenant's secrets**. This is the highest-value target in the control plane.

   ```sql
   revoke all on vault.decrypted_secrets from anon, authenticated;
   -- Verify: must return zero rows.
   select grantee, privilege_type
   from information_schema.role_table_grants
   where table_schema = 'vault' and grantee in ('anon','authenticated');
   ```

2. **Never join `connections` to `decrypted_secrets` in a view the API can see.** An RLS-protected `connections` joined to an unprotected secrets view leaks through the join. Resolve `creds_ref` → secret **only** inside the engine, server-side.

3. **The agentless path stores cross-account role config, not long-lived keys** (build plan lines 196, 247: read-only role + External ID, "no long-lived key stored"). Vault should hold the *role ARN / External ID*, not credentials. Keep it that way — it is a genuinely stronger story than "we encrypt your keys."

4. **No documented pg_cron/pg_net integration guidance** was found on the Vault page. The common pattern (storing a service key in Vault and reading it inside a cron job that calls `pg_net`) is widely used but **unverified here — confidence: low.** If VectaSec needs cron → Edge Function calls, verify the current recommended pattern before building.

**Deprecations:** none noted on the Vault page. — **Confidence: medium** (absence of evidence; the Vault API has churned historically, so re-check `create_secret` before relying on it).

---

## 10. Realtime

### 10.1 Two ways to stream table changes

1. **Postgres Changes** — client subscribes to WAL changes directly. Simple, but each client's subscription is checked against RLS individually, which is the scaling limit.
2. **Broadcast from the Database** — a trigger calls `realtime.broadcast_changes()`; messages route through `realtime.messages`. **This is the recommended path.**

Supabase's stated advantage for Broadcast: better scalability, because messages route via the `realtime.messages` table rather than per-client WAL subscriptions, reducing per-client overhead when many users watch the same changes. ([Supabase — Broadcast](https://supabase.com/docs/guides/realtime/broadcast)) — **Confidence: high** on the recommendation; **medium** on the precise mechanism wording.

### 10.2 The authorization model (current)

Authorization centers on the **`realtime.messages`** table in the `realtime` schema. **You write RLS policies on `realtime.messages`** to control access to channel topics. Validation happens when the client establishes the **WebSocket connection**, checking RLS policies, the auth JWT claims, request headers, and the topic being joined. ([Supabase — Realtime Authorization](https://supabase.com/docs/guides/realtime/authorization)) — **Confidence: high.**

Key pieces:

- **`realtime.topic()`** — helper returning the topic the user is trying to join; use it in policies, e.g. `(select realtime.topic()) = 'room-1'`.
- **`realtime.messages.extension`** — identifies message type: `'broadcast'` or `'presence'`. Lets you authorize features separately.
- **Private channels** — client must set `private: true`. To *enforce* private channels, **disable "Allow public access" in Realtime Settings**.
- **Policy caching** — policies are **cached for the duration of the connection**; they refresh only when the client subscribes or sends a new JWT via an `access_token` message.

— **Confidence: high** (source).

> ### The caching caveat is a security issue for VectaSec
>
> Because policies are cached per connection and only re-evaluated on subscribe / new JWT, **revoking a user's access does not close their open WebSocket.** An offboarded analyst with a live console tab keeps receiving that tenant's findings until their connection drops or their JWT refreshes.
>
> This compounds with the documented JWT-staleness problem: Supabase notes that removing a user from a team is not reflected via `auth.jwt()` until the JWT is refreshed ([Supabase — RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)) — **confidence: high**.
>
> **Therefore: do not derive tenant membership from JWT claims for Realtime authorization.** Query `tenant_members` (via the §6.2 helper) so revocation takes effect at the next policy evaluation — and keep access-token lifetimes short so cached policies turn over quickly. For a security product where "revoke this analyst now" is a headline feature, the difference between "revoked" and "revoked when their token expires" is a support incident. **Confidence: medium** — the mitigation is our reasoning; test the actual revocation latency.

### 10.3 The VectaSec pattern: live findings in the console

```sql
-- 1. Policy on realtime.messages: only members of tenant <uuid> may read
--    the private topic 'tenant:<uuid>'.
create policy findings_stream_read on realtime.messages
  for select to authenticated
  using (
    (select realtime.messages.extension) in ('broadcast')
    and exists (
      select 1
      from unnest(array(select private.user_tenant_ids())) as t(tenant_id)
      where (select realtime.topic()) = 'tenant:' || t.tenant_id::text
    )
  );
```

**Confidence: medium** on this exact policy shape — the topic-matching idiom is our construction from the documented primitives (`realtime.topic()`, `extension`), not copied from a doc example. Validate against a live project.

Note we grant **`select` only** — the browser must never `insert` into `realtime.messages` for this topic. Findings originate from the engine, full stop. If a client could broadcast to `tenant:<uuid>`, a tenant member could **fabricate findings in their own org's console** — hiding a real finding behind noise, or faking a clean bill of health. For a security product, client-writable finding streams are disqualifying.

```sql
-- 2. Trigger: broadcast finding changes to the tenant's private topic.
create or replace function public.broadcast_finding()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform realtime.broadcast_changes(
    'tenant:' || coalesce(new.tenant_id, old.tenant_id)::text,  -- topic
    tg_op,                                                       -- event
    tg_op,                                                       -- operation
    tg_table_name,
    tg_table_schema,
    new,
    old
  );
  return coalesce(new, old);
end $$;

create trigger findings_broadcast
  after insert or update or delete on public.findings
  for each row execute function public.broadcast_finding();
```

`realtime.broadcast_changes(topic, event, operation, table_name, schema_name, new_record, old_record)`, wrapped in a `SECURITY DEFINER` trigger function using `TG_OP`/`TG_TABLE_NAME`/`NEW`/`OLD`, fired from an `AFTER ... FOR EACH ROW` trigger. Realtime Authorization is **required and enabled by default** for this. ([Supabase — Broadcast](https://supabase.com/docs/guides/realtime/broadcast)) — **Confidence: medium-high** on the signature/arg order — **verify parameter order against the live function before shipping**; our fetch summarized it rather than quoting the SQL signature.

Note the trigger function is `SECURITY DEFINER` — so per §5 it gets `set search_path = ''`. It also uses `coalesce(new.tenant_id, old.tenant_id)` because `NEW` is null on `DELETE`.

```ts
// 3. Client: private channel, subscribe to the tenant topic.
const channel = supabase
  .channel(`tenant:${tenantId}`, { config: { private: true } })
  .on('broadcast', { event: 'INSERT' }, ({ payload }) => addFinding(payload))
  .on('broadcast', { event: 'UPDATE' }, ({ payload }) => updateFinding(payload))
  .subscribe()
```

**Also: disable "Allow public access" in Realtime Settings.** Without it, `private: true` is a client-side suggestion rather than an enforced boundary. — **Confidence: high** (source).

---

## 11. API keys — the 2025 migration

### 11.1 Current recommended naming

| Legacy (JWT-based) | Current | Prefix | Where it goes |
|---|---|---|---|
| `anon` | **Publishable key** | `sb_publishable_...` | Safe to expose: web pages, mobile/desktop apps, GitHub Actions, CLIs, source code |
| `service_role` | **Secret key** | `sb_secret_...` | Backend only: servers, Edge Functions, microservices, admin tools |

— **Confidence: high** ([Supabase — Understanding API keys](https://supabase.com/docs/guides/getting-started/api-keys)).

### 11.2 Do legacy keys still work?

**Yes.** Both key types work simultaneously; creating publishable/secret keys adds them **alongside** existing `anon` and `service_role` keys without affecting them — legacy keys keep working. They remain valid until **explicitly disabled** in Dashboard → Settings → API Keys, which is a separate, **reversible** step. — **Confidence: high** ([Supabase — API keys](https://supabase.com/docs/guides/getting-started/api-keys), [Migrating to new API keys](https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys)).

### 11.3 Is there a deadline? — read this carefully

**The current documentation pages state no deprecation or removal date.** Both the API keys guide and the migration guide are silent on timing; the migration guide's position is effectively "legacy keys work today; deactivate them when your migration completes." — **Confidence: high** (verified: fetched both pages specifically looking for dates).

**However**, Supabase's official announcement discussion (posted 2024-09-12, last updated **2025-06-17**) does give a timeline:

- **November 2025** — monthly migration reminders begin; *projects restored from 1 November 2025 will no longer be restored with legacy keys*.
- **Late 2026 (TBC)** — *legacy API keys will be deleted and removed from the Docs / Dashboard*.

([supabase/discussions#29260](https://github.com/orgs/supabase/discussions/29260)) — **Confidence: medium.** It is an official Supabase channel, but: it is marked **"TBC"** (to be confirmed), it was last updated over a year ago (2025-06-17), and — notably — **the timeline is not reflected in the current documentation**, which may mean it slipped, was dropped, or simply isn't documented.

> ### ⚠️ Action for VectaSec — this is time-sensitive
>
> **Today is 2026-07-17. "Late 2026" is one quarter away.** Even discounted for "TBC," the asymmetry is stark: migrating now is a config change; being wrong means every VectaSec deployment loses database access. Some search snippets asserted a firmer "end of 2026, your app will break" framing than the primary sources support — **do not** treat that as verified; the only sourced statement is the TBC discussion above.
>
> **Recommendation: build on `sb_publishable_...` / `sb_secret_...` from day one.** VectaSec is greenfield (Phase 0) — there is no migration cost, only a naming choice. Choosing legacy keys today means adopting a known-deprecated mechanism with a plausible near-term removal date for a product whose entire value proposition is telling customers to fix their security posture. **Confirm the current status in the Dashboard before launch** — it is the authoritative source and the docs are stale on this point.

### 11.4 Security properties worth knowing

- **Secret keys authorize through the `service_role` Postgres role**, which has full access to project data via the **`BYPASSRLS`** attribute. — **Confidence: high.**
- Secret keys improve on the legacy `service_role` JWT: they **return HTTP 401 if used in a browser**, must be **explicitly created** (they don't exist by default), support **instant revocation** and **zero-downtime rotation**, and are hidden in the Dashboard behind an explicit reveal event. — **Confidence: high** (docs + announcement).
- **Rotation:** create a new secret key, migrate components to it, delete the old one — **deletion is irreversible**. — **Confidence: high.**
- **Use one secret key per backend component** so a leak from one component is independently revocable. New keys are created under the name `default`; add named keys to rotate independently. — **Confidence: high.**

### 11.5 VectaSec key plan

| Component | Key | Notes |
|---|---|---|
| Next.js console (browser) | `sb_publishable_...` | RLS is the *only* thing protecting tenant data here |
| Engine / scan workers | **dedicated non-`BYPASSRLS` DB role** (§2.3) | **Not** a secret key. Direct Postgres connection |
| Edge Functions (admin ops) | `sb_secret_...` — named `edge-functions` | Own key, independently revocable |
| CI / migrations | `sb_secret_...` — named `ci` | Separate key; rotate on contributor offboarding |
| Collector | neither | Enrolls via its own token (`enroll_token_hash`, build plan line 290) |

The point of the per-component split: when a key leaks, you revoke *one* component, not the whole platform. That is the story you want to be able to tell a customer during an incident.

---

## 12. Consolidated CI gate

Every check below is a `must return zero rows` assertion. Wire them all into CI as blocking.

```sql
-- 1. Every tenant table has ENABLE + FORCE RLS.
select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname='public' and c.relkind='r'
  and exists (select 1 from pg_attribute a where a.attrelid=c.oid
              and a.attname='tenant_id' and not a.attisdropped)
  and (not c.relrowsecurity or not c.relforcerowsecurity);

-- 2. No tenant table has a WITH CHECK (true) policy.  [§3.2 — the footgun]
select polrelid::regclass, polname from pg_policy
where pg_get_expr(polwithcheck, polrelid)='true'
  and polrelid in (select attrelid from pg_attribute
                   where attname='tenant_id' and not attisdropped);

-- 3. Every SECURITY DEFINER function pins search_path.  [§5]
select n.nspname, p.proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace
where p.prosecdef and n.nspname not in ('pg_catalog','information_schema')
  and not exists (select 1 from unnest(coalesce(p.proconfig,'{}')) cfg
                  where cfg like 'search_path=%');

-- 4. The queue is not exposed to the Data API.  [§7.6]
select nspname from pg_namespace where nspname='pgmq_public';

-- 5. Vault secrets are not readable by API roles.  [§9.4]
select grantee, privilege_type from information_schema.role_table_grants
where table_schema='vault' and grantee in ('anon','authenticated');

-- 6. No tenant table is missing a tenant_id index.  [§4.2 — perf, not security]
select c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace
where n.nspname='public' and c.relkind='r'
  and exists (select 1 from pg_attribute a where a.attrelid=c.oid
              and a.attname='tenant_id' and not a.attisdropped)
  and not exists (
    select 1 from pg_index i join pg_attribute ia
      on ia.attrelid=c.oid and ia.attnum=i.indkey[0]
    where i.indrelid=c.oid and ia.attname='tenant_id');
```

Plus the **adversarial cross-tenant tests** from §3.5 — run as a non-owner role, including the tenant-teleport test. And run **Supabase's own linter/advisors** (`function_search_path_mutable`, plus the RLS-disabled and exposed-view checks) as a blocking step.

---

## 13. Open items to verify before building

| # | Item | § | Confidence |
|---|------|---|-----------|
| 1 | `realtime.broadcast_changes()` exact parameter **order** | §10.3 | medium-high — verify against live function |
| 2 | `create extension pgmq` / `pg_cron` via migration vs. Dashboard-only | §7.2, §8.1 | medium — matters for reproducible on-prem |
| 3 | Legacy API key removal date — **check the Dashboard** | §11.3 | medium — docs silent, announcement says "late 2026 (TBC)", it is now Jul 2026 |
| 4 | `function_search_path_mutable` lint remediation text | §5.4 | medium — page didn't render; our own check (§12.3) covers it regardless |
| 5 | `pgmq.read_with_poll` / `set_vt` signatures | §7.4 | low — unverified; wanted for efficient workers + long-scan heartbeats |
| 6 | pgmq **partitioned** queue support on Supabase | §7.3 | low — unverified |
| 7 | Vault + pg_cron/pg_net pattern | §9.4 | low — no docs guidance found |
| 8 | Supavisor + transaction-local `set_config` behavior | §2.3 | medium — verify tenant context can't leak across pooled connections |
| 9 | Realtime revocation latency (cached policies) | §10.2 | medium — measure it; it's a product claim |
| 10 | Per-tenant in-flight concurrency cap design | §8.7 | low — design work, not researched |

---

## Sources

All URLs below were fetched directly during this research (2026-07-17).

**PostgreSQL official**
- [Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) — FORCE RLS, owner/superuser/BYPASSRLS bypass, USING vs WITH CHECK, permissive/restrictive combination
- [CREATE FUNCTION](https://www.postgresql.org/docs/current/sql-createfunction.html) — SECURITY DEFINER, search_path injection, pg_temp, REVOKE/GRANT pattern

**Supabase official docs**
- [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) — policies, performance benchmarks, service_role bypass, JWT staleness
- [Custom Claims & RBAC](https://supabase.com/docs/guides/database/postgres/custom-claims-and-role-based-access-control-rbac) — `security definer set search_path = ''`, grant/revoke
- [Queues](https://supabase.com/docs/guides/queues) — overview, delivery guarantees
- [Queues Quickstart](https://supabase.com/docs/guides/queues/quickstart) — enabling, queue types, pgmq_public, RLS, grants
- [Queues API](https://supabase.com/docs/guides/queues/api) — pgmq_public wrapper functions
- [Cron](https://supabase.com/docs/guides/cron) — enabling, cron.job/job_run_details, 8-job / 10-minute limits
- [Vault](https://supabase.com/docs/guides/database/vault) — AEAD/libsodium, external root key, create_secret/decrypted_secrets
- [Realtime Authorization](https://supabase.com/docs/guides/realtime/authorization) — realtime.messages RLS, realtime.topic(), private channels, policy caching
- [Realtime Broadcast](https://supabase.com/docs/guides/realtime/broadcast) — broadcast_changes trigger pattern
- [Understanding API keys](https://supabase.com/docs/guides/getting-started/api-keys) — sb_publishable_/sb_secret_, BYPASSRLS, rotation
- [Migrating to new API keys](https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys) — migration path (no dates)
- [Database Linter](https://supabase.com/docs/guides/database/database-linter?lint=0011_function_search_path_mutable) — lint exists; detail page did not render

**Upstream projects**
- [citusdata/pg_cron](https://github.com/citusdata/pg_cron) — schedule signatures, seconds syntax, one-database constraint, schedule_in_database, job_run_details cleanup, RLS permissions
- [pgmq/pgmq](https://github.com/pgmq/pgmq) — function signatures, vt semantics, q_/a_ tables

**Supabase community/official discussions** (lower confidence — not reference docs)
- [#29260 Upcoming changes to Supabase API Keys](https://github.com/orgs/supabase/discussions/29260) — Nov 2025 / late 2026 (TBC) timeline
- [#3328](https://github.com/orgs/supabase/discussions/3328), [#1138](https://github.com/orgs/supabase/discussions/1138), [#33689](https://github.com/orgs/supabase/discussions/33689) — RLS infinite recursion + security definer fix

**Internal**
- `/Users/chintu/Documents/GitHub/Zhask/VectaSec/docs/vectasec-build-plan.md` — schema (lines 281–299), RLS commitments (258, 403), scheduling/jitter (390), Phase 0 scope (470)
