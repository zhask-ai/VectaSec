-- 20260717000004_findings_facets.sql
-- A bounded, exact aggregate for the console's finding counts.
--
-- THE BUG THIS FIXES
-- The console counted findings by selecting every finding row and tallying them in JavaScript
-- (`from('findings').select('severity, status, rule_id')`, no .limit()). PostgREST truncates an
-- unbounded response at the project's Max Rows setting — 1000 on Supabase's hosted default,
-- unlimited on the on-prem PostgREST in deploy/onprem/docker-compose.yml, which is why this only
-- ever bit the SaaS path. The header total on the same screen came from `count: 'exact'`, which
-- is computed server-side and is NOT truncated. So past the cap the two numbers disagreed by
-- construction: "1500 findings match" beside severity facets summing to 1000. Worse on the
-- Overview, where the total and the per-severity counts came from the SAME capped array — they
-- stayed internally consistent and were both silently low. "8 critical open" reading low is a
-- security product lying quietly, which is the only kind of lie that survives review.
--
-- WHY A VIEW AND NOT A LIMIT
-- The result is grouped, so its row count is bounded by (rules x severities x statuses) — tens
-- of rows for a tenant with a million findings. It cannot reach any cap, and it stops shipping
-- O(findings) over the wire, which is the ceiling app/findings/data.ts already documented.
--
-- WHY security_invoker
-- Postgres views default to running as their OWNER. This view is owned by postgres, which has
-- BYPASSRLS: without `security_invoker = true` it would return every tenant's counts to every
-- authenticated caller. That turns a wrong-number bug into a cross-tenant leak — a strictly
-- worse outcome than the defect being fixed. With it, `findings_read`/`findings_select` are
-- evaluated as the caller, exactly as if they had queried `findings` directly. The same trap is
-- why this is a view and not a SECURITY DEFINER aggregate RPC.
create or replace view findings_facets
with (security_invoker = true) as
select
  f.tenant_id,
  f.rule_id,
  f.severity,
  f.status,
  count(*)::bigint as n
from findings f
group by f.tenant_id, f.rule_id, f.severity, f.status;

comment on view findings_facets is
  'Grouped finding counts (tenant, rule, severity, status). security_invoker: RLS on findings '
  'applies to the caller. Read this instead of tallying findings rows client-side — an '
  'unbounded PostgREST select is silently capped at Max Rows and undercounts.';

-- Read-only for the browser, same posture as every table: `authenticated` only, never `anon`.
revoke all on findings_facets from public;
grant select on findings_facets to authenticated;

-- Supports the group-by. findings_status_idx is (tenant_id, status, severity) and does not
-- cover rule_id.
create index if not exists findings_facet_idx on findings(tenant_id, rule_id, severity, status);
