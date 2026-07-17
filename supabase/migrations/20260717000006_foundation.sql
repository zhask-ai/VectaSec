-- 20260717000006_foundation.sql
-- Foundation for the gap-fix pass. Four independent things the rest of the work needs:
--   1. control_attestations   — a "pass" needs a human signature, never a clean scan (decision 1).
--   2. findings.assessment    — a rule that CANNOT read its evidence says so as a state, not prose (decision 3).
--   3. Realtime publication    — the console's live-findings island needs findings on the wire (gap 7).
--   4. observation hash-chain — the ledger becomes tamper-EVIDENT, not just UPDATE-blocked (gap 15).
--
-- Idempotent: safe to re-run.

-- ── 1. Compliance attestations ────────────────────────────────────────────
-- The honest model: a finding can prove a control FAILS. Nothing an automated scan sees can
-- prove a control PASSES — only that we looked and found no violation, over whatever slice we
-- actually covered. A pass therefore requires a person to attest it, with scope and a reason,
-- and that attestation is what compliance.evaluate() reads. A live failing finding always
-- beats an attestation (you cannot sign away a broken control), so this can only ever turn an
-- otherwise-clean control from 'unknown' into 'pass'.
create table if not exists control_attestations (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    uuid not null references tenants(id) on delete cascade,
  framework    text not null,
  control_id   text not null,
  attested_by  uuid not null,                        -- auth.users(id) of the human who signed
  scope        text not null,                         -- what was attested (which systems/period) — required
  note         text,
  evidence_ref jsonb not null default '{}'::jsonb,    -- pointer to the out-of-band proof, if any
  created_at   timestamptz not null default now(),
  expires_at   timestamptz                            -- attestations lapse; a permanent one is discouraged
);
create index if not exists control_attestations_lookup
  on control_attestations(tenant_id, framework, control_id);

alter table control_attestations enable row level security;
alter table control_attestations force row level security;
drop policy if exists control_attestations_select on control_attestations;
create policy control_attestations_select on control_attestations for select to authenticated
  using (tenant_id in (select app_tenant_ids()));

-- ── 2. Assessability: the third outcome ────────────────────────────────────
-- A detector has three honest answers, not two: this is wrong (a finding), this is fine (no
-- finding), or I could not tell (Kafka redacts the very config the rule needs). The third had
-- nowhere to live except `detail` prose that no filter, count, or compliance map can read — so
-- "we could not check" was indistinguishable from "we checked and it's clean". This column is
-- that missing axis. A 'not_assessable' finding is a COVERAGE GAP, not a vulnerability: the
-- console renders it distinctly and compliance maps it to 'unknown', never 'fail'.
alter table findings add column if not exists assessment text not null default 'assessed';
alter table findings add column if not exists assessment_reason text;
do $$ begin
  alter table findings add constraint findings_assessment_chk
    check (assessment in ('assessed', 'not_assessable'));
exception when duplicate_object then null; end $$;
create index if not exists findings_assessment_idx on findings(tenant_id, assessment);

-- ── 3. Realtime ─────────────────────────────────────────────────────────────
-- The console's LiveFindings island subscribes to postgres_changes on findings. That needs the
-- table in the supabase_realtime publication; without it the subscription is silently inert.
-- RLS still governs what a subscriber actually receives — Realtime replays a change to a client
-- only if that client's role could SELECT the row, so this does not widen exposure.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    -- add findings + scans if not already members
    if not exists (
      select 1 from pg_publication_tables
      where pubname='supabase_realtime' and schemaname='public' and tablename='findings'
    ) then
      execute 'alter publication supabase_realtime add table public.findings';
    end if;
    if not exists (
      select 1 from pg_publication_tables
      where pubname='supabase_realtime' and schemaname='public' and tablename='scans'
    ) then
      execute 'alter publication supabase_realtime add table public.scans';
    end if;
  end if;
  -- If the publication does not exist (self-hosted without Realtime), do nothing — the console
  -- degrades silently, which is the documented behaviour.
end $$;

-- ── 4. Tamper-EVIDENT evidence ledger ───────────────────────────────────────
-- migration 002 blocks UPDATE on observations; migration 005 blocks DELETEs that would orphan
-- an ai_output. Neither stops a holder of the DB credential from `delete`ing an *uncited*
-- observation and re-`insert`ing different text — rewriting a finding's evidence without ever
-- issuing an UPDATE (STATUS.md gap 15). The only defence that survives a hostile credential
-- holder is to make the tamper DETECTABLE: chain each observation's hash over the previous one
-- for the same finding. Any delete, reinsert, or reorder breaks the chain, and verify_ledger()
-- finds the break. We do not block DELETE — offboarding and FK cascades need it — we make its
-- misuse impossible to hide.
alter table observations add column if not exists prev_hash text;
alter table observations add column if not exists row_hash  text;

create or replace function ledger_chain() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare
  prev text;
begin
  -- Link over the most recent prior observation for THIS finding (NULL-safe for the first).
  select o.row_hash into prev
  from observations o
  where o.finding_id = new.finding_id
  order by o.observed_at desc, o.id desc
  limit 1;

  new.prev_hash := prev;
  -- The hash commits to the evidence content and its position in the chain. digest() is from
  -- pgcrypto (migration 001). encode(...,'hex') keeps it comparable from any client.
  new.row_hash := encode(
    digest(
      coalesce(prev, '') || '|' || new.tenant_id::text || '|' ||
      coalesce(new.finding_id::text, '') || '|' || new.claim,
      'sha256'
    ),
    'hex'
  );
  return new;
end $$;

drop trigger if exists observations_ledger_chain on observations;
create trigger observations_ledger_chain before insert on observations
  for each row execute function ledger_chain();

-- Recompute the chain and report the first break per finding. A caller (CI, a nightly check, an
-- auditor) runs this and expects zero rows. SECURITY DEFINER so an auditor role without table
-- access can still verify; it only ever READS.
create or replace function verify_ledger(p_tenant uuid default null)
returns table (finding_id uuid, observation_id uuid, reason text)
language plpgsql security definer set search_path = public, extensions as $$
declare
  r record;
  expected text;
  prev text;
  last_finding uuid;
begin
  last_finding := null;
  -- Only rows written AFTER this migration carry a hash. Pre-chain rows (row_hash IS NULL)
  -- are honestly out of scope — they existed before tamper-evidence did and cannot be verified
  -- retroactively; excluding them is why each finding's first hashed row correctly starts from
  -- prev = NULL, matching what the INSERT trigger computed.
  for r in
    select o.id, o.finding_id, o.tenant_id, o.claim, o.prev_hash, o.row_hash
    from observations o
    where (p_tenant is null or o.tenant_id = p_tenant) and o.row_hash is not null
    order by o.finding_id, o.observed_at, o.id
  loop
    if r.finding_id is distinct from last_finding then
      prev := null;                       -- new finding => chain restarts
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

comment on function verify_ledger(uuid) is
  'Recomputes the observation hash-chain; returns one row per detected tamper. Expect zero rows.';
comment on column findings.assessment is
  'assessed | not_assessable — a rule that could not read its evidence is a coverage gap, not a pass.';
comment on table control_attestations is
  'Human sign-off that a control is met. compliance.evaluate() reads this; a live failing finding overrides it.';
