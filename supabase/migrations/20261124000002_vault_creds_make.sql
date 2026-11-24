-- 20261124000002_vault_creds_make.sql
-- Extend the Vault credential backfill (20260723000002_vault_creds.sql) to the Make connector.
--
-- WHY A NEW FILE. 20260723000002 is applied; applied migrations are never edited (a change
-- there would be a silent no-op on every database that already ran it). Its `secret_map`
-- literal is a per-type snapshot of ConnectorField(secret=True) that SQL cannot read from the
-- Python registry, so each connector added later carries its own extension with the SAME
-- backfill body and a map holding only the new type(s). tests/test_creds.py::
-- test_migration_secret_map_matches_registry_declarations unions every `*_vault_creds*.sql`
-- snapshot and fails if the union drifts from what the connectors declare.
--
-- WHAT IT DOES. For any `connections` row of type 'make' whose plain `config` still holds the
-- declared secret field(s), move them into vault.secrets and strip them from config — exactly
-- the 20260723000002 procedure. On a database where the engine has only ever written through
-- creds.py (every row since 2026-07-23) the loop finds nothing and the migration is a no-op.
-- Idempotent and safe to re-run.

do $$
declare
  -- Make connector (services/engine/src/vectasec/connect/make.py): the Make API token.
  -- zone, organization_id and base_url are public config.
  secret_map constant jsonb := '{
    "make": ["api_token"]
  }';
  rec      record;
  k        text;
  secrets  jsonb;
  pub      jsonb;
  ref      uuid;
  migrated int := 0;
begin
  -- Same guard as the base migration: no supabase_vault, nothing to migrate.
  if not exists (select 1 from pg_namespace where nspname = 'vault') then
    raise notice 'vault_creds_make backfill: supabase_vault absent — nothing to migrate';
    return;
  end if;

  for rec in
    select id, type, config, creds_ref
      from connections
     where config is not null and secret_map ? type
     for update
  loop
    secrets := '{}'::jsonb;
    pub     := rec.config;
    for k in select jsonb_array_elements_text(secret_map -> rec.type) loop
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

  raise notice 'vault_creds_make backfill: % connection row(s) had secret fields moved to Vault', migrated;
end $$;
