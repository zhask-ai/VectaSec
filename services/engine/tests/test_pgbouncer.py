"""PgBouncer connector + rulepack + NHI. Offline: no psycopg, no live pooler.

Golden SHOW rows feed the connector's OWN pure parse + _build_resources layer, so the detectors
run against exactly what the connector emits. Every rule gets FIRE / DOES-NOT-FIRE / (where
relevant) NOT-ASSESSABLE; the NHI extractor is exercised on the same resources.
"""
from vectasec.connect.pgbouncer import (_build_resources, _parse_config, _parse_databases,
                                        _parse_users)
from vectasec.contracts import Collected, ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import DETECTORS
import vectasec.detect.pgbouncer  # noqa: F401 — registers the rulepack

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("PGBOUNCER.")}

EXPECTED_RULES = {
    "PGBOUNCER.AUTH.TRUST", "PGBOUNCER.TLS.CLIENT_DISABLED", "PGBOUNCER.TLS.SERVER_DISABLED",
    "PGBOUNCER.AUTH.WEAK_TYPE", "PGBOUNCER.ADMIN.BROAD", "PGBOUNCER.POOL.NOT_ASSESSED",
}

_SECURE_CONFIG = {
    "auth_type": "scram-sha-256", "client_tls_sslmode": "require",
    "server_tls_sslmode": "verify-full", "admin_users": "pgb_admin", "stats_users": "",
    "auth_file": "/etc/pgbouncer/userlist.txt",
}


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def build(config=None, databases=None, users=None, config_readable=True, outcomes=None):
    cfg = dict(_SECURE_CONFIG)
    cfg.update(config or {})
    return _build_resources(cfg, databases or [], users or [],
                            config_readable=config_readable,
                            outcomes=outcomes or {"config": "ok", "databases": "ok", "users": "ok"})


def pool(**config):
    return next(r for r in build(config=config).resources if r.kind == "pgbouncer_pool")


def fire(rule_id, resource, ctx=None):
    d = RULES[rule_id]
    assert resource.kind in d.kinds
    return d.fn(resource, ctx or _ctx([resource])) or []


# ── pack shape + parsers ────────────────────────────────────────────────────--
def test_expected_rules_registered():
    assert set(RULES) == EXPECTED_RULES


def test_parse_layers():
    cfg = _parse_config([{"key": "auth_type", "value": "trust", "default": "md5",
                          "changeable": "yes"},
                         {"key": "admin_users", "value": "postgres,alice"}])
    assert cfg == {"auth_type": "trust", "admin_users": "postgres,alice"}
    dbs = _parse_databases([{"name": "orders", "host": "db1", "port": 5432,
                             "database": "orders", "force_user": "app_ro"}])
    assert dbs[0]["force_user"] == "app_ro" and dbs[0]["name"] == "orders"
    users = _parse_users([{"name": "app", "pool_mode": "transaction"}])
    assert users[0] == {"name": "app", "pool_mode": "transaction"}


# ── PGBOUNCER.AUTH.TRUST ────────────────────────────────────────────────────--
def test_auth_trust_fire_pass_and_unreadable():
    assert len(fire("PGBOUNCER.AUTH.TRUST", pool(auth_type="trust"))) == 1
    assert len(fire("PGBOUNCER.AUTH.TRUST", pool(auth_type="any"))) == 1
    assert fire("PGBOUNCER.AUTH.TRUST", pool()) == []                        # scram
    assert fire("PGBOUNCER.AUTH.TRUST", pool(auth_type=None)) == []          # gap owns it


# ── PGBOUNCER.TLS.CLIENT_DISABLED / SERVER_DISABLED ────────────────────────--
def test_client_tls_fire_and_pass():
    assert len(fire("PGBOUNCER.TLS.CLIENT_DISABLED", pool(client_tls_sslmode="disable"))) == 1
    assert fire("PGBOUNCER.TLS.CLIENT_DISABLED", pool()) == []               # require


def test_server_tls_fire_and_pass():
    assert len(fire("PGBOUNCER.TLS.SERVER_DISABLED", pool(server_tls_sslmode="disable"))) == 1
    assert fire("PGBOUNCER.TLS.SERVER_DISABLED", pool()) == []               # verify-full


# ── PGBOUNCER.AUTH.WEAK_TYPE ───────────────────────────────────────────────--
def test_auth_weak_type_fire_and_pass():
    assert "cleartext" in fire("PGBOUNCER.AUTH.WEAK_TYPE", pool(auth_type="plain"))[0].observation
    assert "MD5" in fire("PGBOUNCER.AUTH.WEAK_TYPE", pool(auth_type="md5"))[0].observation
    assert fire("PGBOUNCER.AUTH.WEAK_TYPE", pool()) == []                    # scram
    assert fire("PGBOUNCER.AUTH.WEAK_TYPE", pool(auth_type="trust")) == []   # TRUST rule owns it


# ── PGBOUNCER.ADMIN.BROAD ──────────────────────────────────────────────────--
def test_admin_broad_shared_superuser_and_count():
    assert len(fire("PGBOUNCER.ADMIN.BROAD", pool(admin_users="postgres,ops"))) == 1  # shared
    assert len(fire("PGBOUNCER.ADMIN.BROAD", pool(admin_users="a,b,c"))) == 1          # count>=3
    assert fire("PGBOUNCER.ADMIN.BROAD", pool(admin_users="pgb_admin")) == []          # dedicated


def test_admin_broad_quiet_when_config_unreadable():
    p = next(r for r in build(config={"admin_users": ""}, config_readable=False).resources
             if r.kind == "pgbouncer_pool")
    assert fire("PGBOUNCER.ADMIN.BROAD", p) == []


# ── PGBOUNCER.POOL.NOT_ASSESSED ────────────────────────────────────────────--
def test_pool_not_assessed_gap_and_quiet():
    p = next(r for r in build(config={"auth_type": None}, config_readable=False,
                              outcomes={"config": "error: denied"}).resources
             if r.kind == "pgbouncer_pool")
    hits = fire("PGBOUNCER.POOL.NOT_ASSESSED", p)
    assert len(hits) == 1 and hits[0].assessable is False
    assert fire("PGBOUNCER.POOL.NOT_ASSESSED", pool()) == []


# ── NHI ─────────────────────────────────────────────────────────────────────
def test_pgbouncer_extractor_registered():
    assert "pgbouncer" in IDENTITY_EXTRACTORS


def test_users_and_backends_become_nhi():
    users = [{"name": "app", "pool_mode": "transaction"},
             {"name": "pgb_admin", "pool_mode": None}]
    databases = [
        {"name": "orders", "host": "db1", "port": 5432, "database": "orders",
         "force_user": "orders_ro", "auth_user": None, "pool_mode": None, "pool_size": 20},
        {"name": "reports", "host": "db1", "port": 5432, "database": "reports",
         "force_user": None, "auth_user": None, "pool_mode": None, "pool_size": 5},
    ]
    col = build(config={"auth_type": "scram-sha-256", "admin_users": "pgb_admin"},
                databases=databases, users=users)
    nhi = derive_identities("pgbouncer", Collected(resources=col.resources))
    ids = [r for r in nhi.resources if r.kind == "identity"]
    creds = [r for r in nhi.resources if r.kind == "credential"]
    grants = [r for r in nhi.resources if r.kind == "grant"]
    # app + pgb_admin + one backend (orders_ro@orders); reports has no pinned backend user
    assert sorted(i.name for i in ids) == ["app", "orders_ro@orders", "pgb_admin"]
    assert len(creds) == 3                       # 2 user passwords + 1 backend password
    admin_id = next(i for i in ids if i.name == "pgb_admin")
    assert admin_id.raw["identity_type"] == "admin"
    assert len(grants) == 1 and grants[0].raw["action"] == "console-admin"


def test_trust_auth_stores_no_user_credential():
    users = [{"name": "app", "pool_mode": "transaction"}]
    col = build(config={"auth_type": "trust", "admin_users": ""}, users=users)
    nhi = derive_identities("pgbouncer", Collected(resources=col.resources))
    assert [r for r in nhi.resources if r.kind == "identity"]          # app is still an identity
    assert [r for r in nhi.resources if r.kind == "credential"] == []  # trust → no stored secret


def test_md5_backend_credential_flags_weak_hash_via_generic_pack():
    # md5 auth_type → the per-user credential is hashing=md5, which the generic NHI pack flags.
    from vectasec.detect import identity as nhi_pack
    users = [{"name": "app", "pool_mode": "transaction"}]
    col = build(config={"auth_type": "md5", "admin_users": ""}, users=users)
    derived = derive_identities("pgbouncer", Collected(resources=col.resources))
    cred = next(r for r in derived.resources if r.kind == "credential")
    assert cred.raw["hashing"] == "md5"
    assert nhi_pack.credential_weak_hash(cred, _ctx([cred]))
