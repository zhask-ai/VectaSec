-- 20260727000003_ledger_ordering.sql
-- Fix a real defect in the evidence ledger's tamper-evidence: the hash chain was built in one
-- order and verified in another, so verify_ledger() reported tampering on honest data.
--
-- HOW IT BROKE
-- `observations.observed_at` defaults to now(), and Postgres' now() is TRANSACTION start time —
-- so every observation written by one scan carries an identical timestamp. Both the chain
-- trigger and the verifier broke that tie on `id`, which is gen_random_uuid(): random, not
-- monotonic. The trigger linked each new row to whichever sibling happened to sort highest by
-- random uuid, while the verifier walked the same rows in ascending uuid order. On any finding
-- with two observations in one transaction the two orders disagree, and the verifier reported
-- `prev_hash break` and `row_hash mismatch` against data nobody had touched.
--
-- This was invisible because nothing ever called verify_ledger() (STATUS.md gap 4). The first
-- thing that ran it — `vectasec doctor --verify-ledger` — found 36 "tampers" across 268 honest
-- observations. A tamper-evidence mechanism that cries wolf on clean data is worse than none:
-- the first auditor to run it would be told the evidence had been rewritten.
--
-- THE FIX
-- Give the chain a monotonic order of its own (`seq`, a bigserial) and make BOTH the trigger and
-- the verifier use it. A sequence is monotonic within and across transactions, so there is
-- exactly one canonical order and the two sides cannot disagree.
--
-- HONESTY ABOUT THE REBUILD
-- Existing hashes were computed under the broken ordering, so they cannot verify under the
-- correct one. This migration RECOMPUTES them in the new canonical order. That necessarily
-- resets the tamper-evidence baseline: hashes written before this migration prove nothing about
-- what happened before it. That is the same honest limit migration 006 already declared for
-- pre-chain rows, and it is recorded here so nobody claims a guarantee that predates the
-- mechanism actually working.

-- ── 1. A monotonic sequence for chain order ───────────────────────────────
alter table observations add column if not exists seq bigint;

create sequence if not exists observations_seq_seq owned by observations.seq;

-- Backfill deterministically. For rows that share a timestamp the true insertion order is
-- unknowable after the fact, so we DECLARE one — (observed_at, id) — and rebuild the chain to
-- match it. Going forward the sequence removes the ambiguity entirely.
do $$
begin
  if exists (select 1 from observations where seq is null) then
    with ordered as (
      select id, row_number() over (order by observed_at, id) as rn from observations
    )
    update observations o set seq = ordered.rn from ordered where ordered.id = o.id;
  end if;
end $$;

select setval('observations_seq_seq', coalesce((select max(seq) from observations), 0) + 1, false);

alter table observations alter column seq set default nextval('observations_seq_seq');
alter table observations alter column seq set not null;

create unique index if not exists observations_seq_uniq on observations (seq);
-- The verifier's walk is (finding_id, seq); this is the index that makes it a range scan
-- instead of a sort over the whole table.
create index if not exists observations_finding_seq on observations (finding_id, seq);

-- ── 2. Chain on seq, not on a random uuid ─────────────────────────────────
-- Column defaults are evaluated BEFORE a BEFORE-ROW trigger fires, so new.seq is already
-- populated here and can scope the lookup to strictly-earlier rows.
create or replace function ledger_chain() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare
  prev text;
begin
  select o.row_hash into prev
  from observations o
  where o.finding_id = new.finding_id and o.seq < new.seq
  order by o.seq desc
  limit 1;

  new.prev_hash := prev;
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

-- ── 3. Verify in the same order the chain was built ───────────────────────
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
  for r in
    select o.id, o.finding_id, o.tenant_id, o.claim, o.prev_hash, o.row_hash
    from observations o
    where (p_tenant is null or o.tenant_id = p_tenant) and o.row_hash is not null
    order by o.finding_id, o.seq          -- the ONLY ordering; matches ledger_chain()
  loop
    if r.finding_id is distinct from last_finding then
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

-- ── 4. Rebuild the existing chain in the canonical order ──────────────────
-- observations is append-only by trigger, which is exactly the guarantee we are here to make
-- verifiable — so the rebuild disables that guard for the length of this statement and puts it
-- straight back. Claims themselves are NOT touched: only prev_hash/row_hash are rewritten, from
-- the claim text already stored.
do $$
declare
  r record;
  prev text;
  last_finding uuid;
begin
  alter table observations disable trigger observations_append_only;

  last_finding := null;
  prev := null;
  for r in
    select id, finding_id, tenant_id, claim
      from observations
     where row_hash is not null
     order by finding_id, seq
  loop
    if r.finding_id is distinct from last_finding then
      prev := null;
      last_finding := r.finding_id;
    end if;
    prev := encode(
      digest(coalesce(prev,'') || '|' || r.tenant_id::text || '|' ||
             coalesce(r.finding_id::text,'') || '|' || r.claim, 'sha256'), 'hex');
    update observations
       set prev_hash = (select o2.row_hash from observations o2
                         where o2.finding_id = r.finding_id and o2.seq <
                               (select o3.seq from observations o3 where o3.id = r.id)
                         order by o2.seq desc limit 1),
           row_hash = prev
     where id = r.id;
  end loop;

  alter table observations enable trigger observations_append_only;
end $$;

comment on column observations.seq is
  'Monotonic chain order. The hash chain is built and verified in (finding_id, seq) order — '
  'observed_at cannot serve because now() is transaction time, so one scan writes many rows '
  'with an identical timestamp and the tie-break on a random uuid made the two sides disagree.';

comment on function verify_ledger(uuid) is
  'Recomputes the observation hash-chain in (finding_id, seq) order; returns one row per '
  'detected tamper. Expect zero rows. Hashes written before migration 20260727000003 were '
  'rebuilt by it, so tamper-evidence is only meaningful from that migration forward.';
