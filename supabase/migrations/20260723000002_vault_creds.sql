-- 20260723000002_vault_creds.sql
--
-- STATUS.md gap #11b: connection credentials lived in plain jsonb `connections.config`. The
-- add-connection form and the CLI accepted passwords/tokens and stored them verbatim, so anyone
-- holding the engine's DB credential — or any future read path over `connections` — read every
-- stored secret. This migration moves them into Supabase Vault (`supabase_vault` 0.3.1, verified
-- present on the live project), which stores values encrypted at rest (libsodium via the
-- project-held key) and decrypts only through the `vault.decrypted_secrets` view, reachable by
-- the engine's server-side role and never exposed over PostgREST.
--
-- The shape, matching the engine code (services/engine/src/vectasec/creds.py):
--   • ONE Vault secret per connection, named `vectasec/connection/<connection_id>`, whose value
--     is a JSON object of the connector's DECLARED secret fields ({"password": "..."} etc. —
--     registry.ConnectorField(secret=True) is the authority on which keys are credentials).
--   • `connections.creds_ref` (typed uuid here; it was a never-used text column from 002) holds
--     the `vault.secrets.id`. NULL means "no secrets stored" (kafka's bootstrap-only config, or
--     a collector-mode connection whose credentials never leave the customer's network).
--   • `connections.config` keeps ONLY non-secret metadata from now on. The engine splits on
--     write (api POST /connections, POST /scans, cli connections add, scan.run_scan) and merges
--     back IN MEMORY at collect time (scan.run_scan, …/test, cli connections test).
--
-- The backfill below migrates EXISTING rows: for each connection whose config carries a
-- declared-secret key, the secret fields move into a Vault secret and are stripped from config.
-- The per-type key map is a snapshot of what the registry declares today (kong: admin_token,
-- rabbitmq: password, redis: password, mcp: token, aws: secret_access_key + session_token,
-- k8s: token; kafka declares none) — future connectors never hit this path because the engine
-- splits at write time from the live registry.
--
-- Audit rows are untouched: they always recorded config KEYS only, never values, so there is
-- nothing to scrub there. pgmq job payloads now carry the public config only (api/main.py);
-- messages enqueued before this migration may still hold secrets in pgmq's archive table —
-- operators purging history should `delete from pgmq.a_vectasec_scans`.

-- ── creds_ref becomes a real uuid ─────────────────────────────────────────
-- Safe cast: the column has been NULL on every row since 002 introduced it (verified live);
-- nullif() keeps the cast safe even against a stray empty string. Guarded so a re-run on an
-- already-migrated database is a no-op rather than a uuid-vs-'' comparison error.
do $$
begin
  if exists (select 1 from information_schema.columns
              where table_schema = 'public' and table_name = 'connections'
                and column_name = 'creds_ref' and data_type <> 'uuid') then
    alter table connections
      alter column creds_ref type uuid using nullif(creds_ref, '')::uuid;
  end if;
end $$;

comment on column connections.creds_ref is
  'vault.secrets.id of this connection''s credential bundle (JSON object of the connector''s '
  'declared secret fields). NULL: nothing secret stored (or the Collector holds credentials '
  'locally). No FK: vault.secrets is extension-managed; the engine deletes the secret in the '
  'same transaction as the connection row.';

-- ── Backfill: move existing plaintext secrets into Vault ──────────────────
do $$
declare
  secret_map constant jsonb := '{
    "kong":     ["admin_token"],
    "rabbitmq": ["password"],
    "redis":    ["password"],
    "mcp":      ["token"],
    "aws":      ["secret_access_key", "session_token"],
    "k8s":      ["token"],
    "azure":    ["client_secret"],
    "gcp":      ["access_token", "service_account_key"]
  }';
  rec      record;
  k        text;
  secrets  jsonb;
  pub      jsonb;
  ref      uuid;
  migrated int := 0;
begin
  for rec in
    select id, type, config, creds_ref
      from connections
     where config is not null and secret_map ? type
     for update
  loop
    secrets := '{}'::jsonb;
    pub     := rec.config;
    for k in select jsonb_array_elements_text(secret_map -> rec.type) loop
      -- Only non-empty values are worth vaulting; either way the key leaves config.
      if pub ? k then
        if coalesce(pub ->> k, '') <> '' then
          secrets := secrets || jsonb_build_object(k, pub ->> k);
        end if;
        pub := pub - k;
      end if;
    end loop;

    if pub = rec.config then
      continue;  -- nothing secret stored on this row
    end if;

    if secrets <> '{}'::jsonb then
      if rec.creds_ref is not null
         and exists (select 1 from vault.secrets where id = rec.creds_ref) then
        perform vault.update_secret(rec.creds_ref, secrets::text);
        ref := rec.creds_ref;
      else
        ref := vault.create_secret(
          secrets::text,
          'vectasec/connection/' || rec.id::text,
          'VectaSec connection credentials (engine-managed; JSON of declared secret fields)');
      end if;
    else
      ref := rec.creds_ref;  -- keys present but empty-valued: strip them, vault nothing
    end if;

    update connections set config = pub, creds_ref = ref where id = rec.id;
    migrated := migrated + 1;
  end loop;

  raise notice 'vault_creds backfill: % connection row(s) had secret fields moved to Vault', migrated;
end $$;
