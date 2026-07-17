-- 20260717000001_core_schema.sql
-- VectaSec core spine (Phase 0): tenancy + inventory + graph + scans + findings + evidence.
-- Row-Level Security is ON for every tenant table. Server-side writes use the postgres/
-- service_role connection (which bypasses RLS); the browser (anon/authenticated) is gated
-- to its own tenant by the read policies below.

create extension if not exists pgcrypto;

-- ── Tenancy ──────────────────────────────────────────────────────────────
create table if not exists tenants (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  plan        text not null default 'free',
  region      text,
  created_at  timestamptz not null default now()
);

create table if not exists tenant_members (
  tenant_id   uuid not null references tenants(id) on delete cascade,
  user_id     uuid not null,                     -- = auth.users(id)
  role        text not null default 'admin',     -- owner|admin|analyst|viewer
  created_at  timestamptz not null default now(),
  primary key (tenant_id, user_id)
);

-- ── Connections (a connected middleware system) ──────────────────────────
create table if not exists connections (
  id              uuid primary key default gen_random_uuid(),
  tenant_id       uuid not null references tenants(id) on delete cascade,
  type            text not null,                 -- kafka|kong|rabbitmq|istio|mulesoft|mcp...
  name            text not null,
  mode            text not null default 'collector',  -- collector|cloud
  status          text not null default 'active',
  config          jsonb not null default '{}',
  created_at      timestamptz not null default now(),
  last_scanned_at timestamptz
);

-- ── Inventory + graph ────────────────────────────────────────────────────
create table if not exists resources (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenants(id) on delete cascade,
  connection_id uuid references connections(id) on delete cascade,
  kind          text not null,                   -- broker|topic|route|service|acl...
  name          text not null,
  namespace     text,
  labels        jsonb not null default '{}',
  raw           jsonb not null default '{}',
  first_seen    timestamptz not null default now(),
  last_seen     timestamptz not null default now(),
  stale         boolean not null default false,
  unique (connection_id, kind, name)
);

create table if not exists edges (
  id              uuid primary key default gen_random_uuid(),
  tenant_id       uuid not null references tenants(id) on delete cascade,
  src_resource_id uuid not null references resources(id) on delete cascade,
  dst_resource_id uuid not null references resources(id) on delete cascade,
  kind            text not null,
  labels          jsonb not null default '{}'
);

-- ── Scans, findings, evidence ────────────────────────────────────────────
create table if not exists scans (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenants(id) on delete cascade,
  connection_id uuid references connections(id) on delete set null,
  status        text not null default 'queued',  -- queued|running|done|error
  started_at    timestamptz not null default now(),
  finished_at   timestamptz,
  stats         jsonb not null default '{}'
);

create table if not exists findings (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenants(id) on delete cascade,
  scan_id       uuid references scans(id) on delete set null,
  resource_id   uuid references resources(id) on delete cascade,
  rule_id       text not null,
  fingerprint   text not null,                   -- dedups the same issue across scans
  title         text not null,
  severity      text not null,                   -- critical|high|medium|low|info
  status        text not null default 'open',    -- open|triaged|in_progress|resolved|suppressed|accepted
  assignee      uuid,
  due_at        timestamptz,
  remediation   text,
  detail        text,
  first_seen    timestamptz not null default now(),
  last_seen     timestamptz not null default now(),
  unique (tenant_id, fingerprint)
);

create table if not exists observations (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenants(id) on delete cascade,
  finding_id    uuid references findings(id) on delete cascade,
  resource_id   uuid references resources(id) on delete set null,
  claim         text not null,                   -- the exact evidence the finding cites
  source_ref    jsonb not null default '{}',
  observed_at   timestamptz not null default now()
);

-- ── Indexes ──────────────────────────────────────────────────────────────
create index if not exists resources_tenant_idx    on resources(tenant_id);
create index if not exists findings_tenant_idx     on findings(tenant_id);
create index if not exists findings_scan_idx       on findings(scan_id);
create index if not exists observations_find_idx   on observations(finding_id);
create index if not exists edges_src_idx           on edges(src_resource_id);

-- ── Row-Level Security ────────────────────────────────────────────────────
-- Which tenants does the current logged-in user belong to?
create or replace function app_tenant_ids()
returns setof uuid
language sql stable security definer set search_path = public, auth
as $$
  select tenant_id from tenant_members where user_id = auth.uid()
$$;

alter table tenants        enable row level security;
alter table tenant_members enable row level security;
alter table connections    enable row level security;
alter table resources      enable row level security;
alter table edges          enable row level security;
alter table scans          enable row level security;
alter table findings       enable row level security;
alter table observations   enable row level security;

drop policy if exists tenants_read      on tenants;
drop policy if exists members_read      on tenant_members;
drop policy if exists connections_read  on connections;
drop policy if exists resources_read    on resources;
drop policy if exists edges_read        on edges;
drop policy if exists scans_read        on scans;
drop policy if exists findings_read     on findings;
drop policy if exists observations_read on observations;

create policy tenants_read      on tenants        for select using (id in (select app_tenant_ids()));
create policy members_read      on tenant_members for select using (tenant_id in (select app_tenant_ids()));
create policy connections_read  on connections    for select using (tenant_id in (select app_tenant_ids()));
create policy resources_read    on resources      for select using (tenant_id in (select app_tenant_ids()));
create policy edges_read        on edges          for select using (tenant_id in (select app_tenant_ids()));
create policy scans_read        on scans          for select using (tenant_id in (select app_tenant_ids()));
create policy findings_read     on findings       for select using (tenant_id in (select app_tenant_ids()));
create policy observations_read on observations   for select using (tenant_id in (select app_tenant_ids()));

-- ── Seed a demo tenant for Phase 0 ────────────────────────────────────────
insert into tenants (id, name, plan, region)
values ('00000000-0000-0000-0000-000000000001', 'Demo', 'free', 'ca-central-1')
on conflict (id) do nothing;
