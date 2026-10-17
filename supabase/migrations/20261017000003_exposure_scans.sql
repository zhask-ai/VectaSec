-- 20261017000003_exposure_scans.sql
-- Free external exposure scan (strategy 2026-10 §2 "Free entry", §4 item 5).
--
-- Two tables. `exposure_targets` is a domain / IP / CIDR a tenant has CLAIMED, with the token
-- they must publish as a DNS TXT record to prove it; `verified_at` is the ownership gate — the
-- engine refuses to probe a target whose verified_at is null. `exposure_scans` is one run against
-- a verified target, carrying the PUBLIC-SAFE report (product/version/port, CVE and EOL facts;
-- never banners, never credentials — see services/engine/src/vectasec/exposure.py).
--
-- Access model matches every other tenant table: the console reads under RLS via PostgREST;
-- every write goes through the engine (service_role, BYPASSRLS) so the token is issued server-side
-- and verified_at can only be set by a verification the engine actually performed. No insert /
-- update / delete policy exists on purpose — under RLS, no policy means no rows for those verbs.

create table if not exists exposure_targets (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid not null references tenants(id) on delete cascade,
  kind           text not null check (kind in ('domain','ip','cidr')),
  value          text not null,
  -- The verification token. Visible to the tenant's own members (they have to publish it); the
  -- select policy below is what keeps it from anyone else.
  token          text not null,
  verified_at    timestamptz,
  verify_method  text check (verify_method is null or verify_method in ('dns_txt','ptr','a_record')),
  created_by     uuid,
  created_at     timestamptz not null default now(),
  unique (tenant_id, kind, value)
);

create table if not exists exposure_scans (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    uuid not null references tenants(id) on delete cascade,
  target_id    uuid not null references exposure_targets(id) on delete cascade,
  status       text not null check (status in ('queued','running','done','error')),
  started_at   timestamptz,
  finished_at  timestamptz,
  report       jsonb not null default '{}'::jsonb,
  error        text
);

create index if not exists exposure_targets_tenant on exposure_targets (tenant_id, created_at desc);
create index if not exists exposure_scans_target   on exposure_scans   (target_id, started_at desc);
-- The per-tenant rate limit (1 running, 10 per day) is a count over this index.
create index if not exists exposure_scans_tenant   on exposure_scans   (tenant_id, started_at desc);

-- ── RLS, matching every other tenant table ────────────────────────────────
alter table exposure_targets enable row level security;
alter table exposure_targets force  row level security;
alter table exposure_scans   enable row level security;
alter table exposure_scans   force  row level security;

drop policy if exists exposure_targets_select on exposure_targets;
create policy exposure_targets_select on exposure_targets for select to authenticated
  using (tenant_id in (select app_tenant_ids()));

drop policy if exists exposure_scans_select on exposure_scans;
create policy exposure_scans_select on exposure_scans for select to authenticated
  using (tenant_id in (select app_tenant_ids()));

-- Defence in depth: the browser roles never write these tables, so the write grants Supabase
-- hands out by default are revoked outright. Guarded because the roles do not exist on stock
-- Postgres (CI). Same pattern as 20260804000001_definer_grants_and_indexes.sql.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on exposure_targets, exposure_scans from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke insert, update, delete, truncate, references, trigger on exposure_targets, exposure_scans from authenticated';
    execute 'grant select on exposure_targets, exposure_scans to authenticated';
  end if;
end $$;

comment on table exposure_targets is
  'Domains / IPs / CIDRs a tenant has claimed for the free external exposure scan. verified_at is '
  'the ownership gate: the engine never probes a target with verified_at null. Written only by '
  'the engine.';
comment on table exposure_scans is
  'One external exposure scan run. report is public-safe by construction (product/version/port, '
  'CVE + EOL facts, short evidence; never banners or credentials). Written only by the engine.';
