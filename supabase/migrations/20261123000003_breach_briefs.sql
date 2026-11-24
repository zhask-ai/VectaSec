-- 20261123000003_breach_briefs.sql
-- Breach-day mode (engine code: src/vectasec/breach.py).
--
-- "Product X has an exploited vulnerability" or "vendor X was breached": the engine answers
-- from the inventory it ALREADY holds, with no rescan: which connected or discovered systems
-- run it, whether the recorded version is in the affected range, which machine identities that
-- system accepts and in what order to rotate them, and which third-party credentials the tool
-- holds that must be rotated at their destination.
--
-- One row per brief. `summary` is the whole computed brief (breach.build_brief output), stored
-- so the answer given on the day is the record of what was known on the day: a later scan does
-- not rewrite it. Nothing in it is secret: names, versions, counts, labels.
--
-- RLS: enabled AND forced, SELECT-only for `authenticated`, the engine is the only writer.

create table if not exists breach_briefs (
  id          uuid primary key default gen_random_uuid(),
  tenant_id   uuid not null references tenants(id) on delete cascade,
  title       text not null,
  product     text not null,
  kind        text not null default 'vulnerability',
  affected    text,                                  -- version spec as entered, e.g. "<1.121.0"
  reference   text,                                  -- advisory URL, if given
  summary     jsonb not null default '{}'::jsonb,
  created_by  text,
  created_at  timestamptz not null default now(),
  constraint breach_briefs_kind_chk check (kind in ('vulnerability', 'vendor_breach'))
);

create index if not exists breach_briefs_tenant_idx on breach_briefs(tenant_id, created_at desc);

comment on table breach_briefs is
  'One row per Breach-day brief (breach.py): an advisory or vendor breach matched against the '
  'stored inventory, with affected systems and a rotation order. summary is frozen at creation.';

alter table breach_briefs enable row level security;
alter table breach_briefs force row level security;

drop policy if exists breach_briefs_select on breach_briefs;
create policy breach_briefs_select on breach_briefs
  for select to authenticated
  using (tenant_id in (select app_tenant_ids()));

do $do$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on breach_briefs from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke insert, update, delete, truncate, references, trigger on breach_briefs from authenticated';
    execute 'grant select on breach_briefs to authenticated';
  end if;
end $do$;
