-- 20260717000007_compliance_unknown.sql
-- controls needs to distinguish "findings that FAIL this control" from "findings that could not
-- be ASSESSED and therefore only make it unknown". Without a separate column, a not_assessable
-- finding would either fake a fail or vanish. Pass provenance is NOT duplicated here — the
-- console reads control_attestations directly (it has an RLS select policy) for who/when.
alter table controls add column if not exists unknown_finding_ids jsonb not null default '[]'::jsonb;
comment on column controls.unknown_finding_ids is
  'Findings mapped here whose assessment is not_assessable — a coverage gap, never a fail.';
