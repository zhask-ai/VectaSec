-- 20260717000002_platform_schema.sql
-- VectaSec platform layer: the SaaS operational tables from the data model (§11), the
-- queue + scheduler substrate, RLS hardening, and the two integrity guarantees the
-- product's credibility rests on:
--   1. the citation gate  — an ai_output cannot commit without a linked observation.
--   2. the evidence ledger — an observation's claim can never be rewritten.
--
-- Both are enforced in the DATABASE, not just in application code, because "every AI claim
-- cites stored evidence" is a promise we make to security buyers.
--
-- Trust model note: the engine connects as `postgres` (BYPASSRLS), so it writes freely;
-- the browser connects as `authenticated` (no BYPASSRLS) and is confined by the policies
-- below. FORCE RLS is set as defense-in-depth for any future non-BYPASSRLS owner/app role.

-- ── Substrate: queue + scheduler ──────────────────────────────────────────
create extension if not exists pgmq;
create extension if not exists pg_cron;

-- ── Fix: resources need the connector's stable external id ────────────────
-- Connectors emit Resource.ext_id and Edge.src/dst_ext_id; without storing ext_id there is
-- no reliable way to resolve an edge's endpoints back to rows (name is not stable/unique
-- across kinds). This is the join key for the whole graph.
alter table resources add column if not exists ext_id text;
update resources set ext_id = kind || '-' || name where ext_id is null;
alter table resources alter column ext_id set not null;
create unique index if not exists resources_conn_extid_uniq on resources(connection_id, ext_id);

-- ── Connections: collector + credential-reference + rate limiting ─────────
alter table connections add column if not exists collector_id uuid;
alter table connections add column if not exists creds_ref     text;    -- Vault ref (cloud path) or NULL (Collector holds them locally)
alter table connections add column if not exists rate_limit    jsonb not null default '{}'::jsonb;

-- ── Collectors (customer-side agents) ─────────────────────────────────────
create table if not exists collectors (
  id                uuid primary key default gen_random_uuid(),
  tenant_id         uuid not null references tenants(id) on delete cascade,
  name              text not null,
  status            text not null default 'pending',   -- pending|active|degraded|offline
  version           text,
  last_heartbeat    timestamptz,
  enroll_token_hash text,                              -- sha256 of the enrollment token; never the token itself
  created_at        timestamptz not null default now()
);

do $$ begin
  alter table connections add constraint connections_collector_fk
    foreign key (collector_id) references collectors(id) on delete set null;
exception when duplicate_object then null; end $$;

-- ── API keys ──────────────────────────────────────────────────────────────
create table if not exists api_keys (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    uuid not null references tenants(id) on delete cascade,
  name         text not null,
  hash         text not null,                          -- sha256 of the key; the key itself is shown once
  scopes       jsonb not null default '[]'::jsonb,
  last_used_at timestamptz,
  created_at   timestamptz not null default now(),
  revoked_at   timestamptz
);

-- ── Audit log (append-only) ───────────────────────────────────────────────
create table if not exists audit_log (
  id        uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  actor     text not null,                             -- user uuid | 'engine' | 'collector:<id>'
  action    text not null,
  target    text,
  detail    jsonb not null default '{}'::jsonb,
  at        timestamptz not null default now()
);

-- ── Findings workflow: suppressions with expiry ───────────────────────────
create table if not exists suppressions (
  id         uuid primary key default gen_random_uuid(),
  tenant_id  uuid not null references tenants(id) on delete cascade,
  rule_id    text not null,
  scope      jsonb not null default '{}'::jsonb,       -- {} = tenant-wide; {resource_id|kind|name_glob}
  reason     text not null,                            -- required: an exception without a reason is not an exception
  expires_at timestamptz,                              -- NULL = permanent (discouraged; surfaced in UI)
  created_by uuid,
  created_at timestamptz not null default now()
);

-- ── Compliance ────────────────────────────────────────────────────────────
create table if not exists controls (
  id                  uuid primary key default gen_random_uuid(),
  tenant_id           uuid not null references tenants(id) on delete cascade,
  framework           text not null,                   -- PCI_DSS_4_0_1|DORA|HIPAA|NIS2
  control_id          text not null,
  title               text not null,
  requirement         text,
  status              text not null default 'unknown', -- pass|fail|unknown|not_applicable
  failing_finding_ids jsonb not null default '[]'::jsonb,
  evaluated_at        timestamptz,
  unique (tenant_id, framework, control_id)
);

-- ── Grounded AI + the citation gate ───────────────────────────────────────
create table if not exists ai_outputs (
  id          uuid primary key default gen_random_uuid(),
  tenant_id   uuid not null references tenants(id) on delete cascade,
  scan_id     uuid references scans(id) on delete set null,
  finding_id  uuid references findings(id) on delete cascade,
  kind        text not null,                           -- triage|remediate|answer|summary
  content     text not null,
  fingerprint text not null,                           -- cache key: same fingerprint => reuse, keeps LLM cost flat
  model       text,
  created_at  timestamptz not null default now(),
  unique (tenant_id, kind, fingerprint)
);

create table if not exists ai_output_evidence (
  ai_output_id   uuid not null references ai_outputs(id) on delete cascade,
  observation_id uuid not null references observations(id) on delete cascade,
  primary key (ai_output_id, observation_id)
);

-- ── Integrations & billing ────────────────────────────────────────────────
create table if not exists integrations (
  id         uuid primary key default gen_random_uuid(),
  tenant_id  uuid not null references tenants(id) on delete cascade,
  type       text not null,                            -- slack|jira|servicenow|webhook|siem
  name       text not null,
  config     jsonb not null default '{}'::jsonb,       -- secrets live in Vault; this holds refs
  enabled    boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists routing_rules (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid not null references tenants(id) on delete cascade,
  match          jsonb not null default '{}'::jsonb,   -- {severity:[..], rule_id_prefix:'KAFKA.'}
  integration_id uuid references integrations(id) on delete cascade,
  created_at     timestamptz not null default now()
);

create table if not exists usage (
  id        uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  metric    text not null,                             -- connections|assets|scans|llm_tokens
  value     numeric not null default 0,
  period    text not null,                             -- 'YYYY-MM'
  unique (tenant_id, metric, period)
);

-- ── Integrity guarantee 1: the citation gate ──────────────────────────────
-- A DEFERRED constraint trigger: the row may be inserted, evidence linked, and the check
-- runs at COMMIT. So an ai_output physically cannot exist in a committed transaction
-- without citing at least one observation. This is the product claim, enforced by Postgres.
create or replace function enforce_citation_gate() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from ai_output_evidence e where e.ai_output_id = new.id) then
    raise exception 'citation gate: ai_output % (kind=%) has no linked observation; uncited AI output is rejected',
      new.id, new.kind using errcode = 'check_violation';
  end if;
  return null;
end $$;

drop trigger if exists ai_outputs_citation_gate on ai_outputs;
create constraint trigger ai_outputs_citation_gate
  after insert on ai_outputs
  deferrable initially deferred
  for each row execute function enforce_citation_gate();

-- ── Integrity guarantee 2: the evidence ledger is append-only ─────────────
-- An observation's claim can never be rewritten — that is what makes it evidence.
-- DELETE is deliberately still permitted so tenant offboarding and FK cascades work;
-- retention is a policy concern, mutation is an integrity concern.
create or replace function reject_update() returns trigger
language plpgsql as $$
begin
  raise exception '% is append-only: UPDATE is not permitted (attempted on row %)',
    tg_table_name, old.id using errcode = 'insufficient_privilege';
end $$;

drop trigger if exists observations_append_only on observations;
create trigger observations_append_only before update on observations
  for each row execute function reject_update();

drop trigger if exists audit_log_append_only on audit_log;
create trigger audit_log_append_only before update on audit_log
  for each row execute function reject_update();

-- ── Indexes (tenant_id first: every RLS policy filters on it) ─────────────
create index if not exists collectors_tenant_idx    on collectors(tenant_id);
create index if not exists api_keys_tenant_idx      on api_keys(tenant_id);
create index if not exists audit_log_tenant_at_idx  on audit_log(tenant_id, at desc);
create index if not exists suppressions_tenant_idx  on suppressions(tenant_id, rule_id);
create index if not exists controls_tenant_idx      on controls(tenant_id, framework);
create index if not exists ai_outputs_tenant_idx    on ai_outputs(tenant_id);
create index if not exists ai_outputs_finding_idx   on ai_outputs(finding_id);
create index if not exists ai_out_ev_obs_idx        on ai_output_evidence(observation_id);
create index if not exists integrations_tenant_idx  on integrations(tenant_id);
create index if not exists routing_rules_tenant_idx on routing_rules(tenant_id);
create index if not exists usage_tenant_idx         on usage(tenant_id);
create index if not exists connections_tenant_idx   on connections(tenant_id);
create index if not exists scans_tenant_idx         on scans(tenant_id);
create index if not exists edges_tenant_idx         on edges(tenant_id);
create index if not exists edges_dst_idx            on edges(dst_resource_id);
create index if not exists observations_tenant_idx  on observations(tenant_id);
create index if not exists resources_conn_idx       on resources(connection_id);
create index if not exists findings_status_idx      on findings(tenant_id, status, severity);

-- ── RLS: enable + FORCE on every tenant table ─────────────────────────────
do $$
declare t text;
begin
  foreach t in array array[
    'tenants','tenant_members','connections','resources','edges','scans','findings',
    'observations','collectors','api_keys','audit_log','suppressions','controls',
    'ai_outputs','ai_output_evidence','integrations','routing_rules','usage'
  ] loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
  end loop;
end $$;

-- ── The tenant-membership helper ──────────────────────────────────────────
-- SECURITY DEFINER + pinned search_path (an unpinned search_path here is an injection vector).
-- Owned by postgres (BYPASSRLS), so it reads tenant_members without re-entering that table's
-- policy — which is what prevents infinite policy recursion.
create or replace function app_tenant_ids()
returns setof uuid
language sql stable security definer set search_path = public, auth
as $$
  select tenant_id from tenant_members where user_id = (select auth.uid())
$$;

revoke all on function app_tenant_ids() from public;
grant execute on function app_tenant_ids() to authenticated;

-- ── Policies ──────────────────────────────────────────────────────────────
-- Read-only for the browser, scoped `to authenticated` (anon gets nothing at all).
-- All mutations go through the engine API, which authenticates the actor, writes an
-- audit_log row, and connects with a BYPASSRLS role. No INSERT/UPDATE/DELETE policy is
-- granted to `authenticated` anywhere — least privilege by construction.
do $$
declare t text;
begin
  foreach t in array array[
    'tenants','tenant_members','connections','resources','edges','scans','findings',
    'observations','collectors','api_keys','audit_log','suppressions','controls',
    'ai_outputs','ai_output_evidence','integrations','routing_rules','usage'
  ] loop
    execute format('drop policy if exists %I on %I', t || '_read', t);
    execute format('drop policy if exists %I on %I', t || '_select', t);
  end loop;
  -- legacy policy names from migration 001
  foreach t in array array['tenants','connections','resources','edges','scans','findings','observations'] loop
    execute format('drop policy if exists %I on %I', t || '_read', t);
  end loop;
  drop policy if exists members_read on tenant_members;
end $$;

-- tenants: you can see a tenant you belong to.
create policy tenants_select on tenants for select to authenticated
  using (id in (select app_tenant_ids()));

-- tenant_members: NON-RECURSIVE by construction — this policy must never call
-- app_tenant_ids(), which itself reads tenant_members. You see your own membership rows.
create policy tenant_members_select on tenant_members for select to authenticated
  using (user_id = (select auth.uid()));

-- api_keys: the hash column is not a secret, but keys are admin-surface; still tenant-scoped.
-- Every remaining tenant table: plain tenant_id scoping.
do $$
declare t text;
begin
  foreach t in array array[
    'connections','resources','edges','scans','findings','observations','collectors',
    'api_keys','audit_log','suppressions','controls','ai_outputs','integrations',
    'routing_rules','usage'
  ] loop
    execute format(
      'create policy %I on %I for select to authenticated using (tenant_id in (select app_tenant_ids()))',
      t || '_select', t
    );
  end loop;
end $$;

-- ai_output_evidence has no tenant_id of its own: scope it through its parent output.
create policy ai_output_evidence_select on ai_output_evidence for select to authenticated
  using (exists (
    select 1 from ai_outputs o
    where o.id = ai_output_evidence.ai_output_id
      and o.tenant_id in (select app_tenant_ids())
  ));

-- ── The scan queue ────────────────────────────────────────────────────────
do $$ begin
  perform pgmq.create('vectasec_scans');
exception when others then null;  -- already exists
end $$;

-- ── Seed the compliance control catalogue for the demo tenant ─────────────
-- (rule -> control mapping lives in the engine; this is the catalogue it evaluates against)
comment on table controls is 'Compliance controls evaluated from findings; see engine compliance/map.py';
comment on table observations is 'Immutable evidence ledger. Every AI claim must cite a row here (see ai_output_evidence).';
comment on function app_tenant_ids() is 'Tenant ids of the current JWT user. SECURITY DEFINER + pinned search_path.';
