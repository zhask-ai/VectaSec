-- 20260723000001_scheduler_trend.sql
-- VectaSec goes continuous: scheduled recurring scans + posture history.
--
-- Two features, both DB-side on purpose — the engine's queue contract (api/main.py
-- `_enqueue_scan` ↔ worker.py `parse_job`) is reproduced here, not modified:
--
--   1. SCHEDULER. `connections.scan_interval_minutes` (NULL = not scheduled) and a
--      pg_cron job that runs `queue_due_scans()` every minute. For each ACTIVE
--      connection whose interval has elapsed it inserts the same 'queued' scans row
--      POST /scans writes and — cloud mode only — sends the same pgmq message on
--      `vectasec_scans`. Collector-mode connections get ONLY the queued row, which the
--      enrolled collector claims via GET /collector/jobs (same rule as the API: pgmq
--      would hand a cloud worker a job whose target it cannot reach).
--
--   2. POSTURE HISTORY. `posture_snapshots` records the tenant's posture each time a
--      scan transitions to 'done' (throttled to one snapshot per tenant per 5 minutes).
--      The formula is EXACTLY apps/web/lib/posture.ts so the sparkline and the live
--      score agree: weighted = 10·crit + 4·high + 1.5·med + 0.5·low over OPEN findings
--      (info excluded — notes, not risk); score = 100 when weighted = 0, else
--      max(1, round(100·(1 − weighted/(weighted+40)))).
--
-- Trust model: same as every migration since 002. The scheduler function and the
-- trigger run as postgres (BYPASSRLS); the browser gets a SELECT-only policy on
-- posture_snapshots and can execute nothing here. FORCE RLS as defense-in-depth.

-- ── Connections: the schedule knob ────────────────────────────────────────
alter table connections add column if not exists scan_interval_minutes int;
alter table connections add column if not exists last_queued_at timestamptz;

do $do$ begin
  alter table connections add constraint connections_scan_interval_chk
    check (scan_interval_minutes is null or scan_interval_minutes > 0);
exception when duplicate_object then null; end $do$;

comment on column connections.scan_interval_minutes is
  'Recurring-scan cadence in minutes; NULL = not scheduled. Consumed by queue_due_scans().';
comment on column connections.last_queued_at is
  'When queue_due_scans() last queued a scan for this connection (manual scans do not set it).';

-- ── The scheduler ─────────────────────────────────────────────────────────
-- Runs from pg_cron as the scheduling role (postgres — BYPASSRLS, like the engine).
-- The scans row and the pgmq payload must match api/main.py::_enqueue_scan exactly,
-- because worker.py::parse_job validates that shape and archives anything else as
-- poison: required scan_id/type/tenant_id, plus config (object), name, requested_by.
--
-- Due = interval elapsed since the LATER of last_queued_at (a scheduled queue) and
-- last_scanned_at (a completed scan, however it was started — so a manual "Scan now"
-- resets the clock). Double-queue guard: skip while any scan for the connection is
-- already queued/running. FOR UPDATE SKIP LOCKED keeps two overlapping cron ticks from
-- queueing the same connection twice.
create or replace function queue_due_scans() returns integer
language plpgsql security definer set search_path = public
as $$
declare
  c record;
  new_scan_id uuid;
  n_queued integer := 0;
begin
  for c in
    select id, tenant_id, type, name, mode, config, scan_interval_minutes
      from connections
     where status = 'active'
       and scan_interval_minutes is not null
       and coalesce(greatest(last_queued_at, last_scanned_at), timestamptz '-infinity')
             <= now() - make_interval(mins => scan_interval_minutes)
       and not exists (
             select 1 from scans s
              where s.connection_id = connections.id
                and s.status in ('queued', 'running')
           )
       for update skip locked
  loop
    insert into scans (tenant_id, connection_id, status)
    values (c.tenant_id, c.id, 'queued')
    returning id into new_scan_id;

    if c.mode <> 'collector' then
      perform pgmq.send('vectasec_scans', jsonb_build_object(
        'scan_id',      new_scan_id::text,
        'type',         c.type,
        'config',       coalesce(c.config, '{}'::jsonb),
        'tenant_id',    c.tenant_id::text,
        'name',         c.name,
        'requested_by', 'scheduler'
      ));
    end if;

    update connections set last_queued_at = now() where id = c.id;
    n_queued := n_queued + 1;
  end loop;

  return n_queued;
end $$;

comment on function queue_due_scans() is
  'pg_cron entrypoint (vectasec-queue-due-scans, every minute): queue scans for active '
  'connections whose scan_interval_minutes has elapsed. Payload shape mirrors '
  'api/main.py::_enqueue_scan; collector-mode rows are left for GET /collector/jobs.';

-- Scheduler-only: the browser must not be able to queue work by calling this.
revoke all on function queue_due_scans() from public;

-- cron.schedule upserts by name in recent pg_cron, but unschedule-first keeps this
-- idempotent on any version. $do$/$job$ tags: nested dollar-quoting.
do $do$ begin
  perform cron.unschedule('vectasec-queue-due-scans');
exception when others then null; end $do$;

select cron.schedule('vectasec-queue-due-scans', '* * * * *', $job$select queue_due_scans()$job$);

-- ── Posture history ───────────────────────────────────────────────────────
create table if not exists posture_snapshots (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid not null references tenants(id) on delete cascade,
  taken_at       timestamptz not null default now(),
  score          int not null,
  weighted       numeric not null,
  critical_count int not null default 0,
  high_count     int not null default 0,
  medium_count   int not null default 0,
  low_count      int not null default 0,
  findings_total int not null default 0   -- ALL open findings, info included (the Overview's denominator)
);

create index if not exists posture_snapshots_tenant_at_idx
  on posture_snapshots(tenant_id, taken_at desc);

comment on table posture_snapshots is
  'Posture score over time, one row per completed scan (throttled: max one per tenant '
  'per 5 minutes). Formula matches apps/web/lib/posture.ts exactly; written only by the '
  'scans_posture_snapshot trigger.';

-- Same posture as every tenant table: RLS enabled + FORCED, SELECT-only for
-- authenticated members, no write policy anywhere (the trigger writes as postgres).
alter table posture_snapshots enable row level security;
alter table posture_snapshots force row level security;

drop policy if exists posture_snapshots_select on posture_snapshots;
create policy posture_snapshots_select on posture_snapshots for select to authenticated
  using (tenant_id in (select app_tenant_ids()));

-- ── The snapshot trigger ──────────────────────────────────────────────────
-- Every path to a finished scan is an UPDATE to status='done' (scan.py for inline and
-- worker scans, api/main.py collector_results for pushed ones), so AFTER UPDATE OF
-- status catches them all. Rounding note: SQL round(numeric) and JS Math.round both
-- round half away from zero for positive inputs, so the score matches posture.ts
-- digit-for-digit.
create or replace function snapshot_posture() returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  v_crit     integer;
  v_high     integer;
  v_med      integer;
  v_low      integer;
  v_total    integer;
  v_weighted numeric;
  v_score    integer;
begin
  -- Cap: one snapshot per tenant per 5 minutes, so a burst of scans (a scheduler tick
  -- across many connections) records one honest point, not a spike of duplicates.
  if exists (
    select 1 from posture_snapshots p
     where p.tenant_id = new.tenant_id
       and p.taken_at > now() - interval '5 minutes'
  ) then
    return null;
  end if;

  select count(*) filter (where severity = 'critical'),
         count(*) filter (where severity = 'high'),
         count(*) filter (where severity = 'medium'),
         count(*) filter (where severity = 'low'),
         count(*)
    into v_crit, v_high, v_med, v_low, v_total
    from findings
   where tenant_id = new.tenant_id
     and status = 'open';

  v_weighted := 10 * v_crit + 4 * v_high + 1.5 * v_med + 0.5 * v_low;
  v_score := case
    when v_weighted = 0 then 100
    else greatest(1, round(100 * (1 - v_weighted / (v_weighted + 40)))::int)
  end;

  insert into posture_snapshots
    (tenant_id, score, weighted, critical_count, high_count, medium_count, low_count, findings_total)
  values
    (new.tenant_id, v_score, v_weighted, v_crit, v_high, v_med, v_low, v_total);

  return null;
end $$;

drop trigger if exists scans_posture_snapshot on scans;
create trigger scans_posture_snapshot
  after update of status on scans
  for each row
  when (new.status = 'done' and old.status is distinct from new.status)
  execute function snapshot_posture();
