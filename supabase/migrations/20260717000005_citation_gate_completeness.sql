-- 20260717000005_citation_gate_completeness.sql
--
-- Migration 002 declared the citation gate as `after insert on ai_outputs` only. That makes
-- the gate a check on ONE transition into "uncited output", and there are three others:
--
--   1. DELETE the evidence row.        `delete from ai_output_evidence where ai_output_id = X`
--   2. DELETE the cited observation.   ai_output_evidence.observation_id is ON DELETE CASCADE,
--                                      so the citation link vanishes silently — and 002's own
--                                      comment ("DELETE is deliberately still permitted so
--                                      tenant offboarding and FK cascades work") invites exactly
--                                      the retention job that does this.
--   3. INSERT ... ON CONFLICT DO UPDATE. Postgres fires UPDATE triggers on the conflict path,
--                                      not INSERT triggers — and there was no UPDATE trigger.
--                                      This is the engine's OWN write path (ai.py::triage_finding).
--
-- All three reached a committed `ai_outputs` row with zero linked observations, which is the
-- exact state ARCHITECTURE.md §2 claims is unrepresentable. The root cause is that the
-- invariant was enforced on an event rather than on the state, so this migration re-checks it
-- on EVERY transition that can break it, on both sides of the link.
--
-- A fourth hole closed here: nothing required a cited observation to belong to the SAME TENANT
-- as the output. `ai_output_evidence` has no tenant_id of its own, and its RLS policy scopes
-- reads through the parent output — so tenant A's output citing tenant B's observation
-- committed cleanly and rendered in A's console as A's own evidence.
--
-- Why deferred, and why not `on delete restrict`:
--   `restrict` on observation_id would make the cascade order of `delete from tenants` load-
--   bearing (tenants cascades to BOTH observations and ai_outputs; Postgres does not promise
--   which FK action runs first), so offboarding would fail intermittently. A DEFERRABLE
--   INITIALLY DEFERRED constraint trigger has no such ordering problem: at COMMIT the parent
--   ai_output is either gone (offboarding/cascade — nothing to protect, pass) or still there
--   (a selective delete — raise). Retention stays possible; it just has to delete the outputs
--   with the evidence, which is what "the output cites the evidence" means.

-- ── The gate, restated as a state check on ai_outputs ─────────────────────
create or replace function enforce_citation_gate() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  bad_tenant uuid;
begin
  -- The check is deferred to COMMIT, so the row may have been deleted later in the same
  -- transaction. A row that no longer exists cannot be an uncited output; without this guard
  -- an insert+delete in one transaction would fail on a row nobody can observe.
  if not exists (select 1 from ai_outputs where id = new.id) then
    return null;
  end if;

  if not exists (select 1 from ai_output_evidence e where e.ai_output_id = new.id) then
    raise exception 'citation gate: ai_output % (kind=%) has no linked observation; uncited AI output is rejected',
      new.id, new.kind using errcode = 'check_violation';
  end if;

  select o.tenant_id into bad_tenant
    from ai_output_evidence e
    join observations o on o.id = e.observation_id
   where e.ai_output_id = new.id
     and o.tenant_id <> new.tenant_id
   limit 1;
  if found then
    raise exception 'citation gate: ai_output % (tenant %) cites an observation owned by tenant %; cross-tenant citation is rejected',
      new.id, new.tenant_id, bad_tenant using errcode = 'check_violation';
  end if;

  return null;
end $$;

-- UPDATE is added here for the ON CONFLICT DO UPDATE path in ai.py::triage_finding: the
-- conflict path fires UPDATE triggers, so without this the engine's own cache-refresh write
-- was the one write in the system the gate never saw.
drop trigger if exists ai_outputs_citation_gate on ai_outputs;
create constraint trigger ai_outputs_citation_gate
  after insert or update on ai_outputs
  deferrable initially deferred
  for each row execute function enforce_citation_gate();

-- ── The other side of the link: removing evidence re-checks the gate ──────
create or replace function enforce_citation_gate_evidence() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  parent ai_outputs%rowtype;
begin
  -- Evidence removed (or re-pointed at another output): the output it used to cite must still
  -- cite something, unless the output itself is gone by COMMIT (offboarding, FK cascade).
  if tg_op in ('DELETE', 'UPDATE') then
    select * into parent from ai_outputs where id = old.ai_output_id;
    if found and not exists (
      select 1 from ai_output_evidence e where e.ai_output_id = old.ai_output_id
    ) then
      raise exception 'citation gate: ai_output % (kind=%) lost its last linked observation; an uncited AI output cannot remain in committed state',
        parent.id, parent.kind using errcode = 'check_violation';
    end if;
  end if;

  -- Evidence added to an already-committed output never re-fires the ai_outputs gate, so the
  -- cross-tenant check has to live here too.
  if tg_op in ('INSERT', 'UPDATE') then
    if exists (
      select 1
        from ai_outputs a
        join observations o on o.id = new.observation_id
       where a.id = new.ai_output_id
         and o.tenant_id <> a.tenant_id
    ) then
      raise exception 'citation gate: ai_output % cites an observation owned by another tenant; cross-tenant citation is rejected',
        new.ai_output_id using errcode = 'check_violation';
    end if;
  end if;

  return null;
end $$;

drop trigger if exists ai_output_evidence_citation_gate on ai_output_evidence;
create constraint trigger ai_output_evidence_citation_gate
  after insert or update or delete on ai_output_evidence
  deferrable initially deferred
  for each row execute function enforce_citation_gate_evidence();

comment on function enforce_citation_gate() is
  'Citation gate (ai_outputs side): a committed ai_output cites >=1 observation of its own tenant. Deferred to COMMIT.';
comment on function enforce_citation_gate_evidence() is
  'Citation gate (evidence side): removing the last citation from a surviving ai_output is rejected; a citation may not cross tenants. Deferred to COMMIT.';
comment on table ai_output_evidence is
  'Citation links. Both directions are gated at COMMIT (migration 005): an ai_output cannot exist uncited, and cannot cite another tenant''s observation. To delete an observation, delete the ai_outputs citing it first.';
