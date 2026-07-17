-- 20260717000003_pipeline_fixes.sql
-- Three corrections to the scan pipeline's identity and integrity invariants.
--
--   1. resources: drop the legacy unique (connection_id, kind, name) from migration 001.
--   2. findings/ai_outputs: re-fingerprint to include connection_id.
--   3. suppressions: a scope must be a jsonb OBJECT.
--
-- Ordering matters: (2) reads resources, so it must not be blocked by (1)'s constraint, and
-- (1) is what lets a scan write the rows (2) is about in the first place.

-- ── 1. resources: one identity, not two ───────────────────────────────────
-- Migration 001 declared `unique (connection_id, kind, name)`; migration 002 introduced
-- ext_id as THE connector-supplied identity and added `resources_conn_extid_uniq on
-- (connection_id, ext_id)` — but never dropped the older constraint, so both were live.
-- scan.py upserts `on conflict (connection_id, ext_id)`, which only arbitrates the ext_id
-- constraint. Two distinct resources that legitimately share (kind, name) — e.g. Kong's
-- `key-auth` plugin applied to two different routes, which have distinct ext_ids but a null
-- `instance_name` and therefore both name themselves 'key-auth' — took the INSERT path,
-- missed the ON CONFLICT target, and raised unique_violation on the legacy constraint,
-- aborting the entire scan. Every scan of that Kong instance failed, forever.
--
-- (kind, name) is not unique and never was: nothing in the engine, the console or any
-- migration conflicts on it — 002's backfill (ext_id = kind || '-' || name) is the only
-- code that ever assumed a relationship between them, and it has already run.
alter table resources drop constraint if exists resources_connection_id_kind_name_key;

-- ── 2. findings: fingerprints must include the connection ─────────────────
-- fingerprint() was keyed on (tenant_id, rule_id, ext_id), but ext_id is only stable WITHIN
-- a connection. One tenant with `prod-kafka` and `staging-kafka` produces `topic-payments`
-- and `broker-1` from both; RabbitMQ's connector emits the literal ext_id `cluster` for
-- every connection. `findings` is UNIQUE (tenant_id, fingerprint), so those collapsed into
-- ONE row: scanning staging overwrote the production finding's severity/detail and
-- repointed resource_id at the staging asset, while observations from both clusters piled up
-- under a single claim. The engine now hashes (tenant_id, connection_id, rule_id, ext_id);
-- this rewrites rows already in the field so existing triage state (status, assignee,
-- due_at) stays attached to its finding instead of being abandoned to a fresh open row.
--
-- The digest must match scan.fingerprint() EXACTLY: sha256 of the '|'-joined fields, hex,
-- first 32 chars. pgcrypto (migration 001) supplies digest().
update findings f
set fingerprint = substr(
      encode(digest(f.tenant_id::text || '|' || r.connection_id::text || '|' ||
                    f.rule_id || '|' || r.ext_id, 'sha256'), 'hex'), 1, 32)
from resources r
where r.id = f.resource_id
  and r.connection_id is not null;

-- ai_outputs.fingerprint is a CACHE KEY carrying the finding's fingerprint (ai.py looks up
-- `where kind='triage' and fingerprint=%s`). Rekeyed alongside, otherwise every cached
-- triage silently misses and is re-paid for at the LLM.
update ai_outputs a
set fingerprint = substr(
      encode(digest(f.tenant_id::text || '|' || r.connection_id::text || '|' ||
                    f.rule_id || '|' || r.ext_id, 'sha256'), 'hex'), 1, 32)
from findings f
join resources r on r.id = f.resource_id
where a.finding_id = f.id
  and r.connection_id is not null;

-- Findings whose resource_id or connection_id is NULL keep their old fingerprint: there is
-- no connection to hash, so no correct new value exists. They are unreachable by a future
-- scan (which will insert a fresh row under the new key) and are left for retention policy
-- rather than silently deleted here — deleting a finding is not a migration's call.

-- ── 3. suppressions: a scope is an object ─────────────────────────────────
-- `scope jsonb not null default '{}'` accepted any jsonb. scan._is_suppressed read `{}` as
-- tenant-wide, so a jsonb `[]` (a plausible slip: the sibling column `collectors.scopes`
-- defaults to '[]') suppressed a rule across the ENTIRE tenant, and a jsonb string raised
-- AttributeError out of the scan loop. The engine now fails closed on both; this is the
-- defense-in-depth half, because the API's `scope: dict` validator is only the API's, and
-- the DB is what actually holds the invariant against seed scripts, CSV imports and
-- hand-written SQL exceptions.
alter table suppressions drop constraint if exists suppressions_scope_is_object;
alter table suppressions add constraint suppressions_scope_is_object
  check (jsonb_typeof(scope) = 'object') not valid;

-- NOT VALID above so a pre-existing bad row cannot abort this migration; validate it now if
-- the table is in fact clean (it will be, unless someone already wrote one), and warn rather
-- than fail if it is not — the engine's fail-closed guard covers the row either way.
do $$ begin
  alter table suppressions validate constraint suppressions_scope_is_object;
exception when check_violation then
  raise warning 'suppressions.scope has non-object rows; constraint left NOT VALID. '
                'Inspect: select id, scope from suppressions where jsonb_typeof(scope) <> ''object'';';
end $$;
