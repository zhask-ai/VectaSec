-- 20261123000002_finding_proofs.sql
-- Proof mode (engine code: src/vectasec/proof.py).
--
-- WHAT THIS IS
-- A finding says a system is misconfigured. A proof says the misconfiguration is reachable
-- right now: the engine performs ONE bounded, read-only, pre-authentication action against the
-- finding's own target (the handshake any client makes before it logs in), and records what
-- came back. One row per attempt, so "proven open at 14:02 → fixed → not reproduced at 14:20"
-- is a readable trail on the finding page.
--
-- WHAT A PROOF NEVER DOES (proof.py enforces it; discover/probes.py states the same law)
-- No credential is sent, guessed or defaulted. Nothing is written, published or deleted. The
-- target is never taken from the request: it is derived from the tenant's own connection or
-- the resource a scan of that connection returned.
--
-- verdict:
--   proven          the unauthenticated action succeeded; `transcript` is what was read
--   not_reproduced  the target answered and demanded authentication (or the open door is gone)
--   unreachable     the engine could not reach the target from where it runs (private network,
--                   collector-mode connection, host down) — says nothing about exploitability
--   unsupported     no safe proof exists for this rule
--
-- `transcript` holds facts read from the wire, already bounded by the probes (product,
-- version, handshake fields). Never payload data, never secrets.
--
-- RLS: enabled AND forced, SELECT-only for `authenticated` scoped by app_tenant_ids(), no
-- write policy. The engine (BYPASSRLS) is the only writer. Idempotent.

create table if not exists finding_proofs (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenants(id) on delete cascade,
  finding_id    uuid not null references findings(id) on delete cascade,
  rule_id       text not null,
  verdict       text not null,
  action        text not null,                         -- what was done, in one sentence
  target        text,                                  -- host:port that was contacted
  transcript    jsonb not null default '[]'::jsonb,    -- [string] facts read from the wire
  signals       jsonb not null default '{}'::jsonb,
  reason        text,                                  -- why unreachable / unsupported
  duration_ms   int  not null default 0,
  requested_by  text,
  created_at    timestamptz not null default now(),
  constraint finding_proofs_verdict_chk
    check (verdict in ('proven', 'not_reproduced', 'unreachable', 'unsupported'))
);

create index if not exists finding_proofs_finding_idx
  on finding_proofs(finding_id, created_at desc);
create index if not exists finding_proofs_tenant_idx
  on finding_proofs(tenant_id, created_at desc);

comment on table finding_proofs is
  'One row per Proof-mode attempt (proof.py): a single read-only, pre-authentication action '
  'against a finding''s own target and what it returned. No credential is ever sent.';

alter table finding_proofs enable row level security;
alter table finding_proofs force row level security;

drop policy if exists finding_proofs_select on finding_proofs;
create policy finding_proofs_select on finding_proofs
  for select to authenticated
  using (tenant_id in (select app_tenant_ids()));

do $do$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on finding_proofs from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke insert, update, delete, truncate, references, trigger on finding_proofs from authenticated';
    execute 'grant select on finding_proofs to authenticated';
  end if;
end $do$;
