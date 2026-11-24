-- 20261123000001_resource_changes.sql
-- The Time machine (engine code: src/vectasec/timemachine.py).
--
-- WHAT THIS IS
-- `resources` holds only the LATEST state a scan returned: each scan overwrites `raw` and
-- `labels`, and a vanished resource is marked stale. That answers "what is true now" and
-- nothing else. This table is the history: one append-only row every time a scan sees a
-- resource appear, disappear, come back, or change configuration, with the changed fields as
-- before/after pairs. It is what lets the console answer "what changed, and between which two
-- scans", "what did this estate look like on 3 October", and "when did this exposure open" for
-- systems whose own audit log is missing, short-lived or sold only on the top plan.
--
-- WHAT IT IS NOT
-- It is not the system's audit log. A scanner that polls can prove WHAT changed and the window
-- it changed in (`prev_seen_at` .. `observed_at`); it knows WHO only where the system's API
-- exposes an author field, which lands in `actor` and is NULL otherwise. The console says so.
--
-- WHAT IS STORED
-- `fields` is a bounded list of {path, before, after}. Values under secret-looking keys are
-- masked by the engine before they are written (timemachine.py), volatile telemetry (counters,
-- timestamps, connection lists) is filtered out so a busy broker does not look like a changed
-- one, and long values are truncated. `field_count` is the true number of changed fields even
-- when `fields` was capped.
--
-- The first scan of a connection writes nothing: everything would be "added", which is the
-- inventory, not a change. `resources.first_seen` already records it.
--
-- RLS: the same posture as every tenant table — enabled AND forced, SELECT-only for
-- `authenticated` scoped by app_tenant_ids(), no write policy. The engine (BYPASSRLS) is the
-- only writer. Idempotent and safe to re-run.

create table if not exists resource_changes (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenants(id) on delete cascade,
  connection_id uuid references connections(id) on delete cascade,
  -- SET NULL, not CASCADE: history must outlive the row it describes. kind/name/ext_id are
  -- copied here for that reason.
  resource_id   uuid references resources(id) on delete set null,
  scan_id       uuid references scans(id) on delete set null,
  kind          text not null,
  name          text not null,
  ext_id        text not null,
  change        text not null,
  fields        jsonb not null default '[]'::jsonb,   -- [{path, before, after}]
  field_count   int  not null default 0,
  actor         text,                                 -- only where the system exposes an author
  prev_seen_at  timestamptz,                          -- last scan that saw the previous state
  observed_at   timestamptz not null default now(),   -- the scan that saw the new state
  constraint resource_changes_change_chk
    check (change in ('added', 'removed', 'modified', 'returned'))
);

create index if not exists resource_changes_tenant_at_idx
  on resource_changes(tenant_id, observed_at desc);
create index if not exists resource_changes_resource_idx
  on resource_changes(resource_id, observed_at desc) where resource_id is not null;
create index if not exists resource_changes_conn_at_idx
  on resource_changes(connection_id, observed_at desc);

comment on table resource_changes is
  'Append-only configuration history (timemachine.py): one row each time a scan sees a '
  'resource added, removed, returned or modified. prev_seen_at..observed_at is the window the '
  'change happened in. Not an audit log: actor is set only where the system exposes one.';
comment on column resource_changes.fields is
  'Changed fields as [{path, before, after}], secret-looking values masked, telemetry '
  'filtered, capped; field_count is the uncapped total.';

alter table resource_changes enable row level security;
alter table resource_changes force row level security;

drop policy if exists resource_changes_select on resource_changes;
create policy resource_changes_select on resource_changes
  for select to authenticated
  using (tenant_id in (select app_tenant_ids()));
-- No INSERT/UPDATE/DELETE policy for authenticated — the engine (BYPASSRLS) is the only writer.

-- Defence in depth, same as 20261017000003: Supabase hands the browser roles full table
-- privileges by default. RLS already refuses every write (no policy), but the grants are revoked
-- outright too. Guarded because the roles do not exist on stock Postgres (CI).
do $do$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on resource_changes from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke insert, update, delete, truncate, references, trigger on resource_changes from authenticated';
    execute 'grant select on resource_changes to authenticated';
  end if;
end $do$;
