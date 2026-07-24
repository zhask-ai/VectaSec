"""Connection credentials live in Supabase Vault, not in `connections.config` (STATUS.md #11b).

The split is driven by the connector's OWN field declarations (registry.ConnectorField.secret):
whatever a connector marks `secret=True` is stripped out of the config before the row is written
and stored as ONE Vault secret — a JSON object of {field: value} — whose `vault.secrets.id` is
kept on `connections.creds_ref`. The stored config is metadata only; anyone reading the table
(a dump, a misissued read credential, PostgREST) sees hosts and usernames, never passwords.

At scan/test time the secrets are resolved from `vault.decrypted_secrets` and merged into the
in-memory config handed to the connector. They exist joined-together only inside the process
that is about to dial the target.

Contract notes:
  • The Vault value is authoritative for secret fields; an update that carries only SOME secret
    fields merges over what is stored, so re-saving a connection without retyping the password
    does not wipe it.
  • Everything here takes an open cursor and joins the CALLER's transaction — a creds_ref that
    commits without its Vault row (or vice versa) is a broken connection, so they land together.
  • No function here ever logs, returns, or persists a secret value anywhere but Vault and the
    in-memory merge. Audit rows record config KEYS only (api.main / cli enforce that).
"""
import json
from typing import Optional

from .registry import CONNECTOR_FIELDS

# One namespaced, unique-per-connection Vault name so the secret is attributable from the
# Vault side too (vault.secrets.name is unique).
_VAULT_NAME = "vectasec/connection/{connection_id}"


def secret_keys(type_: str) -> tuple[str, ...]:
    """The config keys the connector itself declares as credentials."""
    return tuple(f.key for f in CONNECTOR_FIELDS.get(type_, []) if f.secret)


def split_config(type_: str, config: dict) -> tuple[dict, dict]:
    """(public_config, secrets): the declared-secret fields, split out of a submitted config.

    Empty/None secret values are dropped rather than vaulted — an empty password field on a
    re-submitted form means "unchanged", not "the password is empty string".
    """
    keys = set(secret_keys(type_))
    public = {k: v for k, v in (config or {}).items() if k not in keys}
    secrets = {k: v for k, v in (config or {}).items() if k in keys and v not in (None, "")}
    return public, secrets


def resolve_secrets(cur, creds_ref: Optional[str]) -> dict:
    """The stored secret fields for a creds_ref, or {} when there is nothing to resolve.

    Defensive on shape: a missing Vault row or a non-object payload resolves to {} — the scan
    then proceeds with the public config alone and fails at the target with an honest auth
    error, rather than dying here on a bookkeeping inconsistency.
    """
    if not creds_ref:
        return {}
    cur.execute("select decrypted_secret from vault.decrypted_secrets where id = %s::uuid",
                (str(creds_ref),))
    row = cur.fetchone()
    if not row or row[0] is None:
        return {}
    try:
        value = json.loads(row[0])
    except (ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def store_secrets(cur, connection_id: str, secrets: dict,
                  existing_ref: Optional[str] = None) -> Optional[str]:
    """Create or update the connection's Vault secret. Returns the creds_ref to store.

    With an existing ref, the new fields are MERGED over the stored ones (see module doc).
    A ref that points at a vanished Vault row falls through to a fresh create rather than
    failing the save.
    """
    if not secrets:
        return existing_ref
    if existing_ref:
        current = resolve_secrets(cur, existing_ref)
        cur.execute("select 1 from vault.secrets where id = %s::uuid", (str(existing_ref),))
        if cur.fetchone():
            cur.execute("select vault.update_secret(%s::uuid, %s)",
                        (str(existing_ref), json.dumps({**current, **secrets})))
            return str(existing_ref)
    cur.execute(
        "select vault.create_secret(%s, %s, %s)",
        (json.dumps(secrets), _VAULT_NAME.format(connection_id=connection_id),
         "VectaSec connection credentials (engine-managed; JSON of declared secret fields)"),
    )
    return str(cur.fetchone()[0])


def delete_secret(cur, creds_ref: Optional[str]) -> None:
    """Remove the Vault row when its connection goes — a secret with no owner is pure risk."""
    if creds_ref:
        cur.execute("delete from vault.secrets where id = %s::uuid", (str(creds_ref),))


def runtime_config(public: dict, secrets: dict) -> dict:
    """The in-memory merge handed to a connector. Public keys win on collision — a caller who
    explicitly passed a value meant that value."""
    return {**secrets, **public}
