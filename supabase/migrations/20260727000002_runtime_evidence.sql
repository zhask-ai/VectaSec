-- 20260727000002_runtime_evidence.sql
-- Runtime evidence: an accumulating record of which principals were actually SEEN using the
-- estate, so the product can eventually say "this grant has not been exercised in 90 days".
--
-- Why a table and not just observations: the evidence ledger is append-only and per-finding —
-- perfect for justifying a claim, useless for asking "when did we last see X?". This table is
-- the opposite shape: one row per (connection, principal, resource), upserted, carrying
-- first_seen / last_seen / a count. It is derived state, rebuildable from scans, and it is the
-- ONLY place that can answer a question about absence.
--
-- The honesty problem this schema exists to solve: absence of evidence is not evidence of
-- absence. A principal we never saw might be idle, or might run nightly while we sample
-- hourly, or might have been active during a week the connector was broken. So the window is
-- always bounded by `observation_started_at` on the connection — the first moment we could
-- have seen anything at all — and no rule may reason past it.

-- ── Per-connection: when did runtime observation actually begin? ───────────
-- Without this a fresh connection would instantly report every grant as "never used", which
-- is true and useless. A claim about 90 days of silence requires 90 days of listening.
alter table connections add column if not exists runtime_observation_started_at timestamptz;

-- ── The accumulating evidence ─────────────────────────────────────────────
create table if not exists runtime_evidence (
  id              uuid primary key default gen_random_uuid(),
  tenant_id       uuid not null references tenants(id) on delete cascade,
  connection_id   uuid not null references connections(id) on delete cascade,
  -- WHO. Null when the source could not attribute the activity (Redis before ACLs).
  principal       text,
  -- WHAT they were seen using: a resource ext_id where we can name one (a vhost, a topic),
  -- else null for "seen on this connection at all".
  resource_ext    text,
  -- HOW we know. 'rabbitmq-management-api' | 'redis-client-list' | 'sensor' | …
  source          text not null,
  peer_host       text,
  first_seen      timestamptz not null default now(),
  last_seen       timestamptz not null default now(),
  -- How many scans saw it. NOT a traffic count: this product samples, it does not meter.
  observed_scans  integer not null default 1,
  detail          jsonb not null default '{}'::jsonb
);

create unique index if not exists runtime_evidence_uniq
  on runtime_evidence (tenant_id, connection_id, coalesce(principal, ''),
                       coalesce(resource_ext, ''), source, coalesce(peer_host, ''));

create index if not exists runtime_evidence_tenant_seen
  on runtime_evidence (tenant_id, last_seen desc);

-- ── RLS, matching every other tenant table ────────────────────────────────
alter table runtime_evidence enable row level security;
alter table runtime_evidence force  row level security;

drop policy if exists runtime_evidence_select on runtime_evidence;
create policy runtime_evidence_select on runtime_evidence for select to authenticated
  using (tenant_id in (select app_tenant_ids()));

comment on table runtime_evidence is
  'Accumulating record of principals observed using each connection. Sampled, not metered: '
  'observed_scans counts scans that saw the activity, never messages. Absence of a row means '
  'we did not observe it, which is not the same as it not happening — see '
  'connections.runtime_observation_started_at for the earliest moment any claim may reference.';
