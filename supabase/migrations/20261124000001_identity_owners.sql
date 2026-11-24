-- 20261124000001_identity_owners.sql
-- Confirmed owners for machine identities (engine: api/extra.py POST /access/owner).
--
-- The loudest operator pain in the forum research is ownership: nobody can say who owns a key,
-- so nobody dares remove it ("scream test"). Scans can only INFER an owner from tags, creators
-- and annotations. This table records what a human CONFIRMED, and when it was last confirmed,
-- so "owner" and "last verified" can be shown next to every credential and handed to an auditor.
--
-- Keyed by the identity's ext_id (stable across rescans of the same connection), not the
-- resource row id, so a confirmation survives a resource being re-created. One row per
-- identity; every change is also written to audit_log by the API, which is the history.
--
-- RLS: enabled AND forced, SELECT-only for `authenticated`, the engine is the only writer.

create table if not exists identity_owners (
  id               uuid primary key default gen_random_uuid(),
  tenant_id        uuid not null references tenants(id) on delete cascade,
  identity_ext_id  text not null,
  owner            text not null,
  note             text not null default '',
  verified_by      text,
  verified_at      timestamptz not null default now(),
  created_at       timestamptz not null default now(),
  unique (tenant_id, identity_ext_id)
);

comment on table identity_owners is
  'Human-confirmed owner per machine identity (by ext_id) and when it was last confirmed. '
  'Changes are audited in audit_log (action access.owner_confirmed).';

alter table identity_owners enable row level security;
alter table identity_owners force row level security;

drop policy if exists identity_owners_select on identity_owners;
create policy identity_owners_select on identity_owners for select to authenticated
  using (tenant_id in (select app_tenant_ids()));

do $do$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on identity_owners from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke insert, update, delete, truncate, references, trigger on identity_owners from authenticated';
    execute 'grant select on identity_owners to authenticated';
  end if;
end $do$;
