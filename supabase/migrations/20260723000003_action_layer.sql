-- 20260723000003_action_layer.sql
-- The action layer's schema half (engine code: src/vectasec/notify.py + api/main.py).
--
-- `integrations` and `routing_rules` exist since 002 with no code behind them. The engine now
-- writes/reads them, with the same secret discipline as connections (20260723000002):
--
--   • `integrations.config` holds PUBLIC metadata only (Jira base_url/project key, email
--     recipients, …). Anything credential-shaped — Slack/webhook/SIEM URLs (a webhook URL is a
--     bearer credential: whoever holds it can post), Jira API tokens, HMAC signing secrets —
--     goes to Supabase Vault as ONE secret per integration, referenced by `creds_ref` below.
--     The engine splits at write time (notify.split_integration_config) exactly as creds.py
--     does for connections; nothing here needs a backfill because no code ever wrote a row.
--   • `routing_rules.match` keeps its 002 shape (jsonb), interpreted by notify.match_findings:
--     {min_severity, connector_types:[..], rule_prefixes:[..], notify_on:[new_findings|
--     scan_failed]}. `enabled`/`name` are added for the console's rule list.
--
-- `notification_deliveries` is the bookkeeping trail: one row per (rule, integration) delivery
-- attempt after a scan, so the console can show "what did we send, where, and did it arrive".
-- RLS: SELECT-only for `authenticated`, tenant-scoped, like every other tenant table — all
-- writes come from the engine's BYPASSRLS role.

-- ── integrations: the Vault reference ─────────────────────────────────────
alter table integrations add column if not exists creds_ref uuid;

comment on column integrations.creds_ref is
  'vault.secrets.id of this integration''s credential bundle (JSON object of the type''s '
  'declared secret fields — webhook/Slack/SIEM URLs, Jira api_token, HMAC secrets). NULL: '
  'nothing secret stored (email uses SMTP env vars). No FK: vault.secrets is '
  'extension-managed; the engine deletes the secret with the integration row.';

-- ── routing_rules: console conveniences ───────────────────────────────────
alter table routing_rules add column if not exists name    text;
alter table routing_rules add column if not exists enabled boolean not null default true;

comment on column routing_rules.match is
  'Filter evaluated by notify.match_findings against a completed scan''s NEW findings: '
  '{min_severity: info|low|medium|high|critical, connector_types: [kafka,…], '
  'rule_prefixes: ["KAFKA.", …], notify_on: [new_findings, scan_failed]}. {} matches all.';

-- ── notification_deliveries ───────────────────────────────────────────────
create table if not exists notification_deliveries (
  id              uuid primary key default gen_random_uuid(),
  tenant_id       uuid not null references tenants(id) on delete cascade,
  integration_id  uuid references integrations(id) on delete set null,
  routing_rule_id uuid references routing_rules(id) on delete set null,
  scan_id         uuid references scans(id) on delete set null,
  event           text not null,                     -- new_findings|scan_failed|test
  findings_count  int  not null default 0,
  status          text not null,                     -- sent|error
  error           text,                              -- sender error, never a secret/URL value
  created_at      timestamptz not null default now()
);

create index if not exists notif_deliveries_tenant_at_idx
  on notification_deliveries(tenant_id, created_at desc);
create index if not exists notif_deliveries_integration_idx
  on notification_deliveries(integration_id);

-- ── RLS: same posture as every tenant table (002) ─────────────────────────
alter table notification_deliveries enable row level security;
alter table notification_deliveries force row level security;

drop policy if exists notification_deliveries_select on notification_deliveries;
create policy notification_deliveries_select on notification_deliveries
  for select to authenticated
  using (tenant_id in (select app_tenant_ids()));
-- No INSERT/UPDATE/DELETE policy for authenticated — the engine (BYPASSRLS) is the only writer.
