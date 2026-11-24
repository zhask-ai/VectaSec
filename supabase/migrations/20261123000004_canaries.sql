-- 20261123000004_canaries.sql
-- Canaries (engine code: src/vectasec/canary.py).
--
-- A canary is a decoy URL that nothing legitimate ever calls. It is placed where an intruder
-- reads: a workflow definition, an environment file, a wiki page next to real credentials, the
-- description of an unused connection. Anyone who finds it and tries it has announced that
-- they were reading there. The integration layer is where trusted accounts run unwatched for
-- a day (the token-theft breaches of 2025-26); a canary is the alarm for that.
--
-- canaries      one row per decoy. The token itself is shown ONCE at creation and never
--               stored: only its SHA-256 (`token_hash`) and a short prefix for display.
-- canary_hits   one row per request that reached a live canary: when, from where, how.
--
-- A hit stores the caller's IP, user agent, method and query-string LENGTH. It never stores
-- request bodies or headers: an intruder's request can carry stolen secrets, and those must
-- not land in a tenant-readable table.
--
-- RLS: enabled AND forced, SELECT-only for `authenticated`. The engine is the only writer;
-- the public hit endpoint writes through the engine's own connection.

create table if not exists canaries (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenants(id) on delete cascade,
  name          text not null,
  placed_in     text not null default '',           -- where the human put it, in their words
  finding_id    uuid references findings(id) on delete set null,
  token_hash    text not null unique,
  token_prefix  text not null,
  created_by    text,
  created_at    timestamptz not null default now(),
  revoked_at    timestamptz,
  last_hit_at   timestamptz,
  hit_count     int not null default 0
);

create table if not exists canary_hits (
  id          uuid primary key default gen_random_uuid(),
  tenant_id   uuid not null references tenants(id) on delete cascade,
  canary_id   uuid not null references canaries(id) on delete cascade,
  at          timestamptz not null default now(),
  source_ip   text,
  user_agent  text,
  method      text,
  query_len   int not null default 0
);

create index if not exists canaries_tenant_idx on canaries(tenant_id, created_at desc);
create index if not exists canary_hits_canary_idx on canary_hits(canary_id, at desc);
create index if not exists canary_hits_tenant_idx on canary_hits(tenant_id, at desc);

comment on table canaries is
  'Decoy URLs (canary.py). Only the SHA-256 of the token is stored; the token is shown once.';
comment on table canary_hits is
  'Requests that reached a live canary. IP, user agent, method only — never bodies or headers.';

alter table canaries enable row level security;
alter table canaries force row level security;
alter table canary_hits enable row level security;
alter table canary_hits force row level security;

drop policy if exists canaries_select on canaries;
create policy canaries_select on canaries for select to authenticated
  using (tenant_id in (select app_tenant_ids()));
drop policy if exists canary_hits_select on canary_hits;
create policy canary_hits_select on canary_hits for select to authenticated
  using (tenant_id in (select app_tenant_ids()));

do $do$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on canaries, canary_hits from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke insert, update, delete, truncate, references, trigger on canaries, canary_hits from authenticated';
    execute 'grant select on canaries, canary_hits to authenticated';
    -- token_hash is not a secret (it is a hash of 192 random bits) but the browser has no use
    -- for it, so it is not readable there.
    execute 'revoke select on canaries from authenticated';
    execute 'grant select (id, tenant_id, name, placed_in, finding_id, token_prefix, created_by, created_at, revoked_at, last_hit_at, hit_count) on canaries to authenticated';
  end if;
end $do$;
