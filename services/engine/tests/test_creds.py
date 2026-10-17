"""Connection-credential vaulting (creds.py + scan.ensure_connection_with_creds — gap #11b).

What is pinned here:
  • The split is driven by the connector's OWN declared fields — a key is a secret because the
    registry says so, not because of a name heuristic.
  • Round trip: split → store → resolve → merge reproduces the original config in memory, while
    the stored (public) config carries no secret key at all.
  • Updates merge over stored secrets (re-saving without retyping a password keeps it).
  • Resolution fails SOFT ({}), never with an exception — a bookkeeping inconsistency must
    surface as an honest auth failure at the target, not a crash in the engine.

The fakes speak exactly the five SQL shapes creds.py emits. The live test at the bottom runs
the same round trip against the real Supabase Vault when DATABASE_URL is reachable, and cleans
up after itself.
"""
import json
import os
import uuid

import pytest

from vectasec import creds
from vectasec.creds import (delete_secret, resolve_secrets, runtime_config, secret_keys,
                            split_config, store_secrets)
import vectasec.connect  # noqa: F401 — auto-register connector field specs


# ── Fakes ──────────────────────────────────────────────────────────────────
class FakeVaultCursor:
    """A cursor that implements only Vault's surface, keyed on statement shape."""

    def __init__(self):
        self.secrets: dict[str, dict] = {}   # id -> {"name":…, "value":…}
        self._result = None

    def execute(self, sql, params=()):
        s = " ".join(sql.split()).lower()
        if s.startswith("select vault.create_secret"):
            value, name, _desc = params
            if any(v["name"] == name for v in self.secrets.values()):
                raise RuntimeError(f"duplicate vault secret name {name!r}")
            sid = str(uuid.uuid4())
            self.secrets[sid] = {"name": name, "value": value}
            self._result = (sid,)
        elif s.startswith("select vault.update_secret"):
            sid, value = str(params[0]), params[1]
            self.secrets[sid]["value"] = value
            self._result = (None,)
        elif s.startswith("select 1 from vault.secrets"):
            self._result = (1,) if str(params[0]) in self.secrets else None
        elif s.startswith("select decrypted_secret from vault.decrypted_secrets"):
            row = self.secrets.get(str(params[0]))
            self._result = (row["value"],) if row else None
        elif s.startswith("delete from vault.secrets"):
            self.secrets.pop(str(params[0]), None)
            self._result = None
        else:
            self._other(s, params)

    def _other(self, s, params):
        raise AssertionError(f"unexpected SQL for FakeVaultCursor: {s}")

    def fetchone(self):
        return self._result


class FakeConnCursor(FakeVaultCursor):
    """Adds the connections-table statements ensure_connection_with_creds touches."""

    def __init__(self):
        super().__init__()
        self.connections: dict[str, dict] = {}   # id -> {"config":…, "creds_ref":…}

    def _other(self, s, params):
        if s.startswith("select id from connections"):
            self._result = None   # always create-path in these tests
        elif s.startswith("insert into connections"):
            cid = str(uuid.uuid4())
            self.connections[cid] = {"config": json.loads(params[4]), "creds_ref": None}
            self._result = (cid,)
        elif s.startswith("select creds_ref from connections"):
            self._result = (self.connections[str(params[0])]["creds_ref"],)
        elif s.startswith("update connections set creds_ref"):
            self.connections[str(params[1])]["creds_ref"] = params[0]
            self._result = None
        elif s.startswith("update connections set config"):
            self.connections[str(params[1])]["config"] = json.loads(params[0])
            self._result = None
        else:
            raise AssertionError(f"unexpected SQL for FakeConnCursor: {s}")


# ── The split is registry-driven ───────────────────────────────────────────
def test_secret_keys_come_from_the_connector_declarations():
    assert "password" in secret_keys("rabbitmq")
    assert "admin_token" in secret_keys("kong")
    assert "token" in secret_keys("mcp")
    assert "password" in secret_keys("redis")
    assert secret_keys("kafka") == ()          # declares no secret fields
    assert secret_keys("no-such-type") == ()   # unknown type: nothing to split


def test_split_config_separates_only_declared_secrets():
    public, secrets = split_config(
        "rabbitmq", {"url": "http://mq:15672", "username": "svc", "password": "hunter2"})
    assert public == {"url": "http://mq:15672", "username": "svc"}
    assert secrets == {"password": "hunter2"}


def test_split_config_drops_empty_secret_values():
    """An empty password on a re-submitted form means "unchanged", not "vault empty string"."""
    public, secrets = split_config("rabbitmq", {"url": "u", "username": "s", "password": ""})
    assert secrets == {} and "password" not in public


def test_split_config_without_secrets_passes_through():
    cfg = {"bootstrap": "b:9092", "timeout": "30"}
    public, secrets = split_config("kafka", cfg)
    assert public == cfg and secrets == {}


# ── Round trip against the fake ────────────────────────────────────────────
def test_store_resolve_round_trip():
    cur = FakeVaultCursor()
    original = {"url": "http://mq:15672", "username": "svc", "password": "hunter2"}
    public, secrets = split_config("rabbitmq", original)

    ref = store_secrets(cur, "conn-1", secrets)
    assert ref and ref in cur.secrets
    # Nothing secret is visible outside Vault…
    assert "password" not in public
    # …and the in-memory merge reproduces the original exactly.
    assert runtime_config(public, resolve_secrets(cur, ref)) == original


def test_update_merges_over_stored_secrets():
    """Re-saving with a new token must not wipe the untouched password (and vice versa)."""
    cur = FakeVaultCursor()
    ref = store_secrets(cur, "conn-1", {"password": "old-pass", "token": "old-token"})
    ref2 = store_secrets(cur, "conn-1", {"token": "new-token"}, existing_ref=ref)
    assert ref2 == ref
    assert resolve_secrets(cur, ref) == {"password": "old-pass", "token": "new-token"}


def test_store_nothing_keeps_the_existing_ref():
    cur = FakeVaultCursor()
    assert store_secrets(cur, "conn-1", {}) is None
    assert store_secrets(cur, "conn-1", {}, existing_ref="abc") == "abc"


def test_stale_ref_falls_through_to_a_fresh_create():
    """A creds_ref whose Vault row vanished must not fail the save."""
    cur = FakeVaultCursor()
    ref = store_secrets(cur, "conn-1", {"password": "p"}, existing_ref=str(uuid.uuid4()))
    assert ref in cur.secrets
    assert resolve_secrets(cur, ref) == {"password": "p"}


def test_resolution_fails_soft():
    cur = FakeVaultCursor()
    assert resolve_secrets(cur, None) == {}
    assert resolve_secrets(cur, str(uuid.uuid4())) == {}          # no such row
    # A non-object payload resolves to {}, not a crash.
    sid = str(uuid.uuid4())
    cur.secrets[sid] = {"name": "x", "value": "not json {"}
    assert resolve_secrets(cur, sid) == {}
    cur.secrets[sid] = {"name": "x", "value": json.dumps(["a", "list"])}
    assert resolve_secrets(cur, sid) == {}


def test_delete_secret_removes_the_vault_row():
    cur = FakeVaultCursor()
    ref = store_secrets(cur, "conn-1", {"password": "p"})
    delete_secret(cur, ref)
    assert cur.secrets == {}
    delete_secret(cur, None)   # a no-ref delete is a no-op, not an error


def test_runtime_config_public_wins_on_collision():
    """A caller who explicitly passed a value meant that value."""
    assert runtime_config({"password": "explicit"}, {"password": "vaulted"}) == \
        {"password": "explicit"}


# ── ensure_connection_with_creds: the write path, end to end on fakes ──────
def test_ensure_connection_with_creds_stores_public_only():
    from vectasec.scan import ensure_connection_with_creds

    cur = FakeConnCursor()
    cid, public, ref = ensure_connection_with_creds(
        cur, "tenant-1", "rabbitmq", "mq",
        {"url": "http://mq:15672", "username": "svc", "password": "hunter2"})

    row = cur.connections[str(cid)]
    assert row["config"] == {"url": "http://mq:15672", "username": "svc"}   # no secret stored
    assert row["creds_ref"] == ref and ref in cur.secrets
    assert json.loads(cur.secrets[ref]["value"]) == {"password": "hunter2"}
    # And the scan-time merge gets the credentials back.
    assert runtime_config(public, resolve_secrets(cur, ref))["password"] == "hunter2"


def test_ensure_connection_without_secrets_sets_no_ref():
    from vectasec.scan import ensure_connection_with_creds

    cur = FakeConnCursor()
    cid, public, ref = ensure_connection_with_creds(
        cur, "tenant-1", "kafka", "dev", {"bootstrap": "b:9092"})
    assert ref is None
    assert cur.connections[str(cid)]["creds_ref"] is None
    assert cur.secrets == {}


# ── The migration's backfill map must match the registry ───────────────────
def test_migration_secret_map_matches_registry_declarations():
    """20260723000002_vault_creds.sql hardcodes a per-type secret-key snapshot for the backfill
    (SQL cannot read the Python registry). Applied migrations are never edited, so a connector
    added later gets its own `*_vault_creds_*.sql` extension carrying the same literal for just
    the new type(s). The UNION of every snapshot, in filename order, must equal what the
    connectors declare — otherwise a fresh apply on a pre-vault database would leave that
    connector's secrets in plain config."""
    import pathlib
    import re
    from vectasec.registry import CONNECTORS

    migrations = None
    for parent in pathlib.Path(__file__).resolve().parents:
        candidate = parent / "supabase" / "migrations"
        if (candidate / "20260723000002_vault_creds.sql").exists():
            migrations = candidate
            break
    if migrations is None:
        pytest.skip("migration file not reachable from the test tree")

    sql_map: dict = {}
    for path in sorted(migrations.glob("*_vault_creds*.sql")):
        m = re.search(r"secret_map constant jsonb := '(\{.*?\})'", path.read_text(), re.S)
        assert m, f"secret_map literal not found in {path.name}"
        for k, v in json.loads(m.group(1)).items():
            assert k not in sql_map, f"{k} re-declared in {path.name}; one snapshot per type"
            sql_map[k] = sorted(v)
    registry_map = {t: sorted(secret_keys(t)) for t in CONNECTORS if secret_keys(t)}
    assert sql_map == registry_map


# ── Live round trip against the real Supabase Vault ────────────────────────
def _live_database_url():
    if not os.environ.get("DATABASE_URL"):
        from vectasec.config import load_env
        load_env()   # walks up from cwd; finds the repo-root .env in dev
    return os.environ.get("DATABASE_URL", "")


def test_live_vault_round_trip():
    """The same store→resolve→delete cycle against the real vault.* API. Skips cleanly when no
    database is reachable; creates only its own uniquely-named secret and removes it."""
    url = _live_database_url()
    if not url:
        pytest.skip("DATABASE_URL not configured")
    import psycopg
    try:
        conn = psycopg.connect(url, connect_timeout=10)
    except psycopg.OperationalError as e:
        pytest.skip(f"database unreachable: {e}")

    marker = f"vectasec-test-{uuid.uuid4()}"
    ref = None
    try:
        with conn.cursor() as cur:
            cur.execute("select 1 from pg_extension where extname='supabase_vault'")
            if not cur.fetchone():
                pytest.skip("supabase_vault extension not installed")

            ref = store_secrets(cur, marker, {"password": "round-trip-value"})
            assert resolve_secrets(cur, ref) == {"password": "round-trip-value"}

            # Merge-update against the real update_secret.
            ref2 = store_secrets(cur, marker, {"token": "t2"}, existing_ref=ref)
            assert ref2 == ref
            assert resolve_secrets(cur, ref) == {"password": "round-trip-value", "token": "t2"}

            # The value at rest is NOT the plaintext.
            cur.execute("select secret from vault.secrets where id=%s::uuid", (ref,))
            assert "round-trip-value" not in (cur.fetchone()[0] or "")

            delete_secret(cur, ref)
            cur.execute("select 1 from vault.secrets where id=%s::uuid", (ref,))
            assert cur.fetchone() is None
            ref = None
        conn.commit()
    finally:
        if ref is not None:   # a failed assertion above must still not leave residue
            try:
                with conn.cursor() as cur:
                    delete_secret(cur, ref)
                conn.commit()
            except Exception:
                conn.rollback()
        conn.close()
