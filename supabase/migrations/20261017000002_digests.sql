-- 20261017000002_digests.sql
-- Weekly digest bookkeeping (engine code: src/vectasec/digest.py).
--
-- One row per digest run for a tenant: the window it summarised, where it went (one entry per
-- destination, sent or failed — a failed Slack hook is recorded, never raised) and the summary
-- that was rendered, so the console can show "what did we send last Monday" and the next run
-- can start its window where the last one ended (`period_end` is the cursor).
--
-- RLS: the same posture as every tenant table — enabled AND forced (20260801000001 explains
-- why FORCE matters: without it an owner-context query bypasses the guarantee), SELECT-only
-- for `authenticated` scoped by app_tenant_ids(), no write policy anywhere. The engine's
-- BYPASSRLS role is the only writer. Nothing in `summary` is secret: counts, titles,
-- rule ids, a posture score.

create table if not exists digests (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenants(id) on delete cascade,
  period_start  timestamptz,
  period_end    timestamptz,
  delivered_to  jsonb not null default '[]'::jsonb,   -- [{integration_id, name, type, status, error}]
  summary       jsonb not null default '{}'::jsonb,   -- digest.compose_digest output
  created_at    timestamptz not null default now()
);

create index if not exists digests_tenant_period_idx
  on digests(tenant_id, period_end desc);

comment on table digests is
  'One row per weekly digest run (digest.py). period_end is the cursor the next run starts '
  'from; delivered_to records every destination attempt, failures included.';

alter table digests enable row level security;
alter table digests force row level security;

drop policy if exists digests_select on digests;
create policy digests_select on digests
  for select to authenticated
  using (tenant_id in (select app_tenant_ids()));
-- No INSERT/UPDATE/DELETE policy for authenticated — the engine (BYPASSRLS) is the only writer.
