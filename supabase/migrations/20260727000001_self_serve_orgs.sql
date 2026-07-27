-- 20260727000001_self_serve_orgs.sql
-- Self-serve multi-tenancy: anyone signs up (email or OAuth), names an organization, and is
-- its admin; org admins invite members (the engine's POST /members already handles that);
-- platform operators (super admins) see every org and every user, and may act as admin in
-- any tenant (the engine recognises super_admins in its role resolution).
--
-- Trust model, same as migration 002: the browser is `authenticated` under FORCE RLS; the
-- engine is `postgres` (BYPASSRLS). Everything the browser must do ACROSS tenants — create a
-- tenant it is not yet a member of, read the platform-wide org list — goes through a
-- SECURITY DEFINER function owned by postgres that does its own authorization, exactly like
-- app_tenant_ids().

-- ── Profiles: the readable mirror of auth.users ───────────────────────────
-- auth.users is not readable by `authenticated`, so anything the console shows about a user
-- (email in the admin panel, presence) needs a public mirror. Kept by trigger; no client
-- writes except through touch_last_seen().
--
-- No FK to auth.users(id) — same deliberate omission as tenant_members.user_id (migration
-- 001): CI applies these migrations to stock postgres, where the auth schema is a shim with
-- auth.uid() and NO users table. Everything that touches auth.users itself (the mirror
-- trigger, the backfill, the seeds) is guarded on the table actually existing.
create table if not exists profiles (
  user_id      uuid primary key,                -- = auth.users(id)
  email        text not null,
  full_name    text,
  avatar_url   text,
  last_seen_at timestamptz,
  created_at   timestamptz not null default now()
);

create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (user_id, email, full_name, avatar_url)
  values (
    new.id,
    coalesce(new.email, ''),
    nullif(coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name'), ''),
    nullif(new.raw_user_meta_data->>'avatar_url', '')
  )
  on conflict (user_id) do update
    set email = excluded.email,
        full_name  = coalesce(excluded.full_name, profiles.full_name),
        avatar_url = coalesce(excluded.avatar_url, profiles.avatar_url);
  return new;
end $$;

do $$ begin
  if to_regclass('auth.users') is not null then
    execute 'drop trigger if exists on_auth_user_created on auth.users';
    execute 'create trigger on_auth_user_created
               after insert or update of email, raw_user_meta_data on auth.users
               for each row execute function handle_new_user()';
    -- Backfill for users that predate this migration (the demo user).
    execute $backfill$
      insert into profiles (user_id, email, full_name)
      select id, coalesce(email, ''), nullif(raw_user_meta_data->>'full_name', '')
      from auth.users
      on conflict (user_id) do nothing
    $backfill$;
  end if;
end $$;

-- ── Super admins: platform operators ──────────────────────────────────────
-- A row here IS the privilege. No client path writes this table — rows are granted by the
-- operator (SQL / engine host), which is the point: the platform's own admin surface must
-- not be creatable from the product's browser session.
create table if not exists super_admins (
  user_id    uuid primary key,                  -- = auth.users(id); FK-less, see profiles
  created_at timestamptz not null default now()
);

-- True for the CALLER. Definer-owned so it can read super_admins regardless of RLS; safe to
-- expose because it answers only about auth.uid(), never about an arbitrary user.
create or replace function is_super_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from super_admins where user_id = (select auth.uid()))
$$;
grant execute on function is_super_admin() to authenticated;

-- ── RLS ────────────────────────────────────────────────────────────────────
alter table profiles     enable row level security;
alter table profiles     force  row level security;
alter table super_admins enable row level security;
alter table super_admins force  row level security;

drop policy if exists profiles_select on profiles;
create policy profiles_select on profiles for select to authenticated
  using (
    user_id = (select auth.uid())                       -- yourself
    or is_super_admin()                                 -- platform operators: everyone
    or user_id in (                                     -- people in your tenants (member list)
      select m.user_id from tenant_members m
      where m.tenant_id in (select app_tenant_ids())
    )
  );

drop policy if exists super_admins_select on super_admins;
create policy super_admins_select on super_admins for select to authenticated
  using (user_id = (select auth.uid()));   -- you may ask only "am I one?"

-- ── Presence ───────────────────────────────────────────────────────────────
-- The console heartbeats this once a minute. "Live" in the admin panel = last_seen_at within
-- a couple of minutes; it is presence-by-polling, consistent with the console's liveness
-- model (AutoRefresh), not a realtime channel.
create or replace function touch_last_seen() returns void
language sql security definer set search_path = public as $$
  update profiles set last_seen_at = now() where user_id = (select auth.uid())
$$;
grant execute on function touch_last_seen() to authenticated;

-- ── Org provisioning: signup → name your organization → you are its admin ──
alter table tenants add column if not exists created_by uuid;

create or replace function create_org(org_name text) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := (select auth.uid());
  tid uuid;
  trimmed text := btrim(coalesce(org_name, ''));
begin
  if uid is null then
    raise exception 'not authenticated';
  end if;
  if length(trimmed) < 2 or length(trimmed) > 80 then
    raise exception 'organization name must be 2-80 characters';
  end if;
  -- One org per creator by default: self-serve signup is "create YOUR workspace", and an
  -- unbounded loop here would let one session mint tenants forever. Membership in other
  -- orgs (by invite) is unlimited; creating more orgs is an operator action for now.
  if exists (select 1 from tenants t where t.created_by = uid) then
    raise exception 'you already created an organization; ask us to enable more';
  end if;
  insert into tenants (name, plan, created_by) values (trimmed, 'free', uid) returning id into tid;
  insert into tenant_members (tenant_id, user_id, role) values (tid, uid, 'admin');
  return tid;
end $$;
grant execute on function create_org(text) to authenticated;

-- ── The platform view: what super admins see ──────────────────────────────
-- Definer-owned aggregates instead of blanket "super admins read every tenant table"
-- policies: the admin surface needs COUNTS and identities, not a standing licence to read
-- every tenant's findings from the browser role.

create or replace function admin_orgs()
returns table (
  id uuid, name text, plan text, created_at timestamptz, created_by_email text,
  members bigint, connections bigint, open_findings bigint, last_scan timestamptz
)
language plpgsql security definer stable set search_path = public as $$
begin
  if not is_super_admin() then
    raise exception 'super admins only';
  end if;
  return query
  select t.id, t.name, t.plan, t.created_at,
         (select p.email from profiles p where p.user_id = t.created_by),
         (select count(*) from tenant_members m where m.tenant_id = t.id),
         (select count(*) from connections c where c.tenant_id = t.id),
         (select count(*) from findings f where f.tenant_id = t.id and f.status = 'open'),
         (select max(s.finished_at) from scans s where s.tenant_id = t.id)
  from tenants t
  order by t.created_at desc;
end $$;
grant execute on function admin_orgs() to authenticated;

create or replace function admin_users()
returns table (
  user_id uuid, email text, full_name text, created_at timestamptz, last_seen_at timestamptz,
  is_super boolean, memberships jsonb
)
language plpgsql security definer stable set search_path = public as $$
begin
  if not is_super_admin() then
    raise exception 'super admins only';
  end if;
  return query
  select p.user_id, p.email, p.full_name, p.created_at, p.last_seen_at,
         exists (select 1 from super_admins sa where sa.user_id = p.user_id),
         coalesce(
           (select jsonb_agg(jsonb_build_object('tenant_id', m.tenant_id, 'tenant', t.name, 'role', m.role)
                             order by t.name)
            from tenant_members m join tenants t on t.id = m.tenant_id
            where m.user_id = p.user_id),
           '[]'::jsonb)
  from profiles p
  order by p.created_at desc;
end $$;
grant execute on function admin_users() to authenticated;

create or replace function admin_org_members(org uuid)
returns table (user_id uuid, email text, full_name text, role text, last_seen_at timestamptz, joined_at timestamptz)
language plpgsql security definer stable set search_path = public as $$
begin
  if not is_super_admin() then
    raise exception 'super admins only';
  end if;
  return query
  select m.user_id, p.email, p.full_name, m.role, p.last_seen_at, m.created_at
  from tenant_members m left join profiles p on p.user_id = m.user_id
  where m.tenant_id = org
  order by m.created_at;
end $$;
grant execute on function admin_org_members(uuid) to authenticated;

-- ── Seed: the demo user operates the platform in dev ──────────────────────
do $$ begin
  if to_regclass('auth.users') is not null then
    execute $seed$
      insert into super_admins (user_id)
      select id from auth.users where lower(email) = 'demo@vectasec.local'
      on conflict (user_id) do nothing
    $seed$;
    -- The demo tenant predates created_by; attribute it so create_org's one-org rule sees it.
    execute $seed$
      update tenants t
      set created_by = (select id from auth.users where lower(email) = 'demo@vectasec.local')
      where t.id = '00000000-0000-0000-0000-000000000001' and t.created_by is null
    $seed$;
  end if;
end $$;

comment on table profiles is 'Readable mirror of auth.users (trigger-kept). last_seen_at is the presence heartbeat.';
comment on table super_admins is 'Platform operators. Row = privilege; granted by the operator, never from the browser.';
