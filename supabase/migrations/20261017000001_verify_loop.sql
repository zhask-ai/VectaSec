-- 20261017000001_verify_loop.sql
-- The Verify button (docs/vectasec-smb-strategy-2026-10.md §3 "Remediation: Upgrade", §4 item 3).
--
-- WHAT CHANGES
-- An SMB fixes a finding, presses Verify, and the engine rescans the connection and closes the
-- finding only if the detector no longer fires. That needs four facts on the findings row:
--
--   verify_requested_at  when a human asked for verification (NULL = nobody is waiting)
--   verify_requested_by  who asked (auth user id; NULL for service-token callers)
--   verified_at          when a rescan proved the fix
--   verified_scan_id     which scan proved it — the evidence pointer, so "resolved by verify"
--                        is auditable against that scan's ledger entries, not a bare status flip
--
-- WHY THIS IS NOT "AUTO-RESOLVE VANISHED FINDINGS"
-- The scan loop deliberately does NOT resolve a finding whose fingerprint stops being emitted
-- (scan.py: resources go stale, findings keep their status). A finding that vanishes because
-- a listener was renamed, a collector lost permissions, or a probe timed out is not fixed, and
-- silently closing it would be a security product lying quietly. The Verify loop closes ONLY
-- findings a human explicitly asked to be checked, and records the scan that did it. A rescan
-- that still emits the fingerprint clears the request (audit: finding.verify_failed) and leaves
-- the status alone. A scan that ends in error touches nothing.
--
-- RLS: findings already has FORCE RLS and a tenant-scoped select policy (core_schema); new
-- columns inherit it. Writers are the engine (BYPASSRLS) and the API, both tenant-filtering
-- explicitly. findings_facets groups by (tenant, rule, severity, status) and needs no change.
-- No trigger on findings exists. Idempotent and safe to re-run.

alter table findings add column if not exists verify_requested_at timestamptz;
alter table findings add column if not exists verify_requested_by uuid;
alter table findings add column if not exists verified_at         timestamptz;
alter table findings add column if not exists verified_scan_id    uuid references scans(id) on delete set null;

-- The settle step runs once per completed scan and asks "which findings on this connection
-- are waiting for verification?" — a partial index keeps that a handful of rows, never a scan
-- of the tenant's findings.
create index if not exists findings_verify_pending_idx
  on findings (tenant_id, verify_requested_at)
  where verify_requested_at is not null;

create index if not exists findings_verified_scan_idx on findings (verified_scan_id)
  where verified_scan_id is not null;

comment on column findings.verify_requested_at is
  'Set by POST /findings/{id}/verify. The next successful scan of the connection resolves the '
  'finding if its fingerprint is no longer emitted (verified_at, verified_scan_id), or clears '
  'this and audits finding.verify_failed if it still is. NULL = no verification pending.';
comment on column findings.verify_requested_by is
  'auth.users id of the requester when known; NULL for service-token callers.';
comment on column findings.verified_at is
  'When a rescan proved the fix. Only ever set together with verified_scan_id and status=resolved.';
comment on column findings.verified_scan_id is
  'The scan whose results closed the finding. Evidence pointer: that scan''s ledger shows the '
  'fingerprint absent. ON DELETE SET NULL — scan history can be pruned without reopening anything.';
