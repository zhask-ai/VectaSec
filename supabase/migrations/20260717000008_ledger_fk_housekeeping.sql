-- 20260717000008_ledger_fk_housekeeping.sql
-- Fix a latent bug the append-only ledger trigger (migration 002) introduced: it blocks EVERY
-- update to observations, including the ON DELETE SET NULL that Postgres performs on
-- observations.resource_id when a referenced resource is deleted. Result: deleting a resource
-- that any observation points at fails with "observations is append-only", which breaks resource
-- re-collection churn and tenant offboarding. Surfaced by the collector round-trip's cleanup;
-- no test had ever deleted a resource that carried evidence.
--
-- The append-only GUARANTEE is about the evidence — the claim, its provenance, and its hash-chain
-- position — never about the resource_id FK pointer, which is bookkeeping. So: block any update
-- that alters evidence; permit an update that changes ONLY resource_id (the FK SET NULL). Tamper
-- evidence is unchanged: claim/hashes remain immutable under UPDATE, and delete+reinsert is still
-- caught by verify_ledger's hash chain.

create or replace function reject_observation_update() returns trigger
language plpgsql as $$
begin
  if new.claim       is distinct from old.claim
     or new.tenant_id   is distinct from old.tenant_id
     or new.finding_id  is distinct from old.finding_id
     or new.source_ref  is distinct from old.source_ref
     or new.observed_at is distinct from old.observed_at
     or new.row_hash    is distinct from old.row_hash
     or new.prev_hash   is distinct from old.prev_hash then
    raise exception
      'observations is append-only: evidence is immutable (only the resource_id FK pointer may change; attempted to alter row %)',
      old.id using errcode = 'insufficient_privilege';
  end if;
  return new;   -- resource_id-only change (the FK SET NULL on resource delete) is permitted
end $$;

drop trigger if exists observations_append_only on observations;
create trigger observations_append_only before update on observations
  for each row execute function reject_observation_update();

-- audit_log keeps the strict, fully-immutable reject_update() — it has no FK that cascades to it,
-- so it needs no housekeeping exception.
