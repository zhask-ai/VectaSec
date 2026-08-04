-- Three defects found by a data-layer audit on 2026-08-03. All reproduced against the live
-- database before this file was written.
--
-- 1. SECURITY DEFINER functions were callable by `anon`. The previous migration's
--    `revoke all on function queue_due_scans() from public` removed nothing, because Supabase
--    grants EXECUTE **directly** to the anon/authenticated/service_role roles rather than via
--    PUBLIC — so the revoke targeted a grant that was not the one in force. Both functions sit
--    in `public`, which PostgREST exposes at /rest/v1/rpc/<name>. Verified as `anon`:
--      select queue_due_scans()             -> ran, returning (0,)
--      select count(*) from verify_ledger() -> ran, returning every tenant's rows
--    queue_due_scans writes `scans` rows, sends pgmq messages and updates connections
--    ACROSS EVERY TENANT as postgres; verify_ledger with its default null tenant returns every
--    tenant's finding and observation ids to an unauthenticated caller. RLS was never the
--    control here — a definer function runs as its owner.
--
-- 2. `observations.finding_id` was nullable, and the ledger's two halves disagree about NULL.
--    The append trigger finds a predecessor with `where o.finding_id = new.finding_id`, and
--    NULL = NULL is UNKNOWN, so every NULL-finding row starts a fresh chain. The verifier
--    groups with `is distinct from`, under which NULL and NULL are the SAME group, so it
--    expects the chain to continue. Proven: three inserted NULL-finding rows produced 4
--    reported "tamper" breaks on an honest ledger. No writer does this today, which is exactly
--    why it should be made impossible now — this is the surviving twin of the bug that
--    migration 20260727000003 was written to end, and its failure mode is crying wolf across
--    every tenant.
--
-- 3. Missing indexes on the hottest queries. `scans` had no index on connection_id or status,
--    so the worker's reaper (every ~5s) and pg_cron's due-scan check (every minute) were both
--    sequential scans, and four cascading foreign keys had no index on the referencing column —
--    deleting one connection with 5k resources cost 5k sequential scans of `findings`.

-- verify_ledger stays callable by a signed-in user, because "has my own evidence been tampered
-- with" is a legitimate question for a tenant to ask. It must answer only for tenants that
-- caller belongs to — the default `p_tenant => null` previously meant "every tenant", and a
-- definer function does not get RLS applied to it, so the check has to be written out.
--
-- The loop body below is unchanged from 20260727000003; only the authorization preamble is new.
create or replace function verify_ledger(p_tenant uuid default null)
returns table (finding_id uuid, observation_id uuid, reason text)
language plpgsql security definer set search_path = public, extensions as $$
declare
  r record;
  expected text;
  prev text;
  last_finding uuid;
  caller uuid;
begin
  -- The engine connects as the table owner and has no auth.uid(); it is trusted and may ask
  -- about everything. A request arriving through PostgREST always carries one, and may ask
  -- only about tenants it belongs to.
  begin
    caller := auth.uid();
  exception when others then
    caller := null;                      -- no auth schema (self-hosted/CI) => owner context
  end;
  if caller is not null then
    if p_tenant is null then
      raise exception 'verify_ledger requires an explicit tenant';
    end if;
    if not exists (select 1 from tenant_members m
                    where m.tenant_id = p_tenant and m.user_id = caller) then
      raise exception 'not a member of that tenant';
    end if;
  end if;

  last_finding := null;
  for r in
    select o.id, o.finding_id, o.tenant_id, o.claim, o.prev_hash, o.row_hash
    from observations o
    where (p_tenant is null or o.tenant_id = p_tenant) and o.row_hash is not null
    order by o.finding_id, o.seq          -- the ONLY ordering; matches ledger_chain()
  loop
    -- `is distinct from` treats NULL and NULL as the SAME group while the append trigger's
    -- `=` treats them as different chains. finding_id is NOT NULL as of this migration, so
    -- the two can no longer disagree; the guard stays as belt and braces.
    if r.finding_id is distinct from last_finding or r.finding_id is null then
      prev := null;
      last_finding := r.finding_id;
    end if;
    if r.prev_hash is distinct from prev then
      finding_id := r.finding_id; observation_id := r.id;
      reason := 'prev_hash break (deleted or reordered predecessor)';
      return next;
    end if;
    expected := encode(
      digest(coalesce(prev,'') || '|' || r.tenant_id::text || '|' ||
             coalesce(r.finding_id::text,'') || '|' || r.claim, 'sha256'), 'hex');
    if r.row_hash is distinct from expected then
      finding_id := r.finding_id; observation_id := r.id;
      reason := 'row_hash mismatch (claim rewritten)';
      return next;
    end if;
    prev := r.row_hash;
  end loop;
end $$;

-- ── 1. Definer functions are not public API ─────────────────────────────────
-- AFTER the create-or-replace above, deliberately: replacing a function resets its ACL to the
-- default, which grants EXECUTE to PUBLIC. Revoking first and defining second silently undoes
-- the revoke — the first attempt at this migration did exactly that and left the function open.
--
-- PUBLIC is the grantee that matters. The previous migration revoked only `from public` and
-- was reported as ineffective because Supabase ALSO grants directly to anon/authenticated;
-- the truth is both are needed, since `has_function_privilege('anon', …)` is satisfied by
-- either. Revoke both, then re-grant precisely.
do $$
begin
  execute 'revoke all on function public.queue_due_scans() from public';
  execute 'revoke all on function public.verify_ledger(uuid) from public';
  execute 'revoke all on function public.ledger_chain() from public';
  -- These roles exist on Supabase; on stock Postgres (CI) they do not, and a revoke against a
  -- missing role is a hard error rather than a no-op.
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on function public.queue_due_scans() from anon';
    execute 'revoke all on function public.verify_ledger(uuid) from anon';
    execute 'revoke all on function public.ledger_chain() from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    -- The scheduler is the database's own job (pg_cron runs it as the owner) and ledger_chain
    -- is a trigger helper; no signed-in user has a reason to call either. verify_ledger is
    -- re-granted because a tenant asking about its OWN evidence is legitimate — it now
    -- authorizes the caller itself.
    execute 'revoke all on function public.queue_due_scans() from authenticated';
    execute 'revoke all on function public.ledger_chain() from authenticated';
    execute 'grant execute on function public.verify_ledger(uuid) to authenticated';
  end if;
end $$;

-- ── 2. An observation without a finding cannot be chained ───────────────────
do $$
begin
  if not exists (select 1 from observations where finding_id is null) then
    alter table observations alter column finding_id set not null;
  end if;
end $$;

-- ── 3. Indexes for the queries actually issued ──────────────────────────────
-- Not CONCURRENTLY: migrations run in a transaction, and these tables are small at the scale
-- this migration lands. Revisit if either grows past a few million rows.
create index if not exists scans_connection_status_idx on scans (connection_id, status);
create index if not exists scans_running_started_idx on scans (started_at) where status = 'running';
create index if not exists findings_resource_id_idx on findings (resource_id);
create index if not exists observations_resource_id_idx on observations (resource_id);
create index if not exists runtime_evidence_connection_idx on runtime_evidence (connection_id);
