-- 20260801000001_lock_schema_migrations.sql
-- Close the one CRITICAL finding on Supabase's own security advisor: `rls_disabled_in_public`
-- on public.schema_migrations.
--
-- WHAT WAS EXPOSED
-- Every table in the `public` schema is served by PostgREST at /rest/v1/<table>, reachable by
-- anyone holding the anon key — which is public by design (it ships inlined in the browser
-- bundle; RLS is what protects the data, not the secrecy of that key). RLS is therefore the
-- ONLY thing standing between a public-schema table and the internet, and this table had none:
-- `select`, `insert`, `update` and `delete` were all open to anon.
--
-- WHY THE TABLE IS HERE AT ALL
-- Nothing in this repo creates it — no migration in supabase/migrations, no engine DDL. It is
-- bookkeeping left behind by migration tooling (the CLI's own ledger lives in
-- supabase_migrations.schema_migrations; this stray public copy is the artifact). It holds
-- version strings, not tenant data, so the disclosure risk was low — but the WRITE grant was
-- not: an anon caller could delete or forge rows in it and desynchronise future migration
-- runs against the production database.
--
-- THE FIX, IN TWO LAYERS
-- 1. Enable RLS with NO policies. Under RLS, "no policy" means "no rows" — PostgREST returns an
--    empty set to anon/authenticated and rejects every write. This is deliberate: a table
--    nobody should reach through the API needs no policy, and adding a permissive one just to
--    have one would re-open exactly what we are closing.
-- 2. Revoke the grants outright, so the request fails at the privilege check before RLS is even
--    consulted. Defence in depth: if a later migration re-enables a policy by accident, the
--    missing grant still holds the door.
--
-- `postgres` and `service_role` BYPASSRLS, so migration tooling keeps working untouched. This
-- migration is idempotent and safe to re-run.

-- The table is not created by us, so never assume it exists — a hard reference would break
-- `supabase db reset` on a clean database, where the stray table has never been made.
do $$
begin
  if to_regclass('public.schema_migrations') is not null then
    execute 'alter table public.schema_migrations enable row level security';
    -- FORCE so even the table's owner is subject to RLS; without it an owner-context query
    -- silently bypasses the very guarantee this migration exists to make.
    execute 'alter table public.schema_migrations force row level security';
    execute 'revoke all on public.schema_migrations from anon, authenticated';
  end if;
end
$$;
