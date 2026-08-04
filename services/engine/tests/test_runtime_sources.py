"""Agentless runtime evidence from the connectors that can report live clients.

The runtime rulepack (detect/runtime.py) is deliberately SOURCE-AGNOSTIC: it fires on the shared
`runtime_client` kind, so a connector earns all of its rules by emitting that kind with the
agreed raw keys. These tests pin that contract from both ends —

  * each connector's pure build layer produces `runtime_client` with the keys the rulepack reads
    (principal / principal_known / peer_host / connections / tls_all / observed_via), and
  * the rulepack fires the SAME rules on NATS and PgBouncer clients that it fires on the
    RabbitMQ and Redis clients it was originally written for.

which is the whole point: a fifth runtime source should need no new rules. Offline — no httpx,
no psycopg, no live server.
"""
import json
import pathlib

from vectasec.connect.nats import build_resources as nats_build
from vectasec.connect.pgbouncer import (_build_resources as pgb_build, _parse_clients)
from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.runtime  # noqa: F401 — registers the shared rulepack

FIX = json.loads((pathlib.Path(__file__).parent / "fixtures" / "nats_varz.json").read_text())

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("RUNTIME.")}

# The rules a runtime source gets for free by emitting `runtime_client`. Pinned so that deleting
# one silently (or renaming its id) fails here rather than quietly reducing coverage.
EXPECTED_RUNTIME_RULES = {
    "RUNTIME.CREDENTIAL.CLEARTEXT_ON_WIRE",
    "RUNTIME.IDENTITY.SHARED_DEFAULT_IN_USE",
    "RUNTIME.IDENTITY.UNATTRIBUTED_CLIENT",
    "RUNTIME.TRANSPORT.PLAINTEXT_IN_USE",
    "RUNTIME.ACCESS.UNEXPECTED_PEER",
}


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def _fire(rule_id, resource, resources=None):
    d = RULES[rule_id]
    assert "runtime_client" in d.kinds, f"{rule_id} must run on runtime_client"
    return d.fn(resource, _ctx(resources or [resource]))


def _nats_clients():
    col = nats_build(
        varz=FIX["varz"]["hardened"], jsz=FIX["jsz"], connz=FIX["connz"],
        base_url="http://localhost:8222", scheme="http", tls_verified=False,
        monitoring_unauthenticated=True, config=FIX["config"]["hardened"],
    )
    return [r for r in col.resources if r.kind == "runtime_client"], col


def _by_principal(clients, principal):
    return next(r for r in clients if (r.raw or {}).get("principal") == principal)


# ── the shared contract ───────────────────────────────────────────────────────
def test_all_expected_runtime_rules_are_registered():
    assert EXPECTED_RUNTIME_RULES <= set(RULES)


# ── NATS /connz ───────────────────────────────────────────────────────────────
def test_nats_emits_runtime_clients_aggregated_by_principal_and_peer():
    clients, _ = _nats_clients()
    # 4 connections, but cid 2 and 3 share (admin, APP, 93.184.216.34) -> 3 resources.
    assert len(clients) == 3
    admin = _by_principal(clients, "admin")
    assert admin.raw["connections"] == 2, "same principal+peer must fold into one resource"
    assert admin.raw["observed_via"] == "GET /connz?auth=1"
    assert admin.raw["vhost"] == "APP", "the account is the scope runtime_evidence folds on"


def test_nats_anonymous_client_is_marked_unknown_not_invented():
    clients, _ = _nats_clients()
    anon = _by_principal(clients, None)
    assert anon.raw["principal_known"] is False
    assert anon.raw["account"] == "$G"
    assert _fire("RUNTIME.IDENTITY.UNATTRIBUTED_CLIENT", anon), "anonymous client must be reported"


def test_nats_tls_is_read_from_tls_version_presence():
    clients, _ = _nats_clients()
    assert _by_principal(clients, "admin").raw["tls_all"] is True
    assert _by_principal(clients, None).raw["tls_all"] is False


def test_nats_plaintext_client_fires_transport_rule_and_tls_client_does_not():
    clients, _ = _nats_clients()
    assert _fire("RUNTIME.TRANSPORT.PLAINTEXT_IN_USE", _by_principal(clients, None))
    assert not _fire("RUNTIME.TRANSPORT.PLAINTEXT_IN_USE", _by_principal(clients, "admin"))


def test_nats_default_account_in_use_and_public_peer_fire():
    clients, _ = _nats_clients()
    admin = _by_principal(clients, "admin")
    assert _fire("RUNTIME.IDENTITY.SHARED_DEFAULT_IN_USE", admin)
    assert _fire("RUNTIME.ACCESS.UNEXPECTED_PEER", admin), "93.184.216.34 is public address space"


def test_nats_well_behaved_client_fires_nothing():
    clients, _ = _nats_clients()
    good = _by_principal(clients, "billing-svc")
    for rule_id in EXPECTED_RUNTIME_RULES:
        assert not _fire(rule_id, good), f"{rule_id} should be silent on a clean client"


def test_nats_runtime_edges_link_client_to_server():
    _, col = _nats_clients()
    uses = [e for e in col.edges if e.kind == "uses" and e.src_ext_id.startswith("runtime-")]
    assert len(uses) == 3 and all(e.dst_ext_id.startswith("nats-") for e in uses)


def test_nats_without_connections_list_emits_no_runtime_clients():
    """A server we could not read and a server nobody is talking to must look identical here.
    Reasoning about that silence belongs to runtime_evidence.py, which has a window."""
    col = nats_build(
        varz=FIX["varz"]["hardened"], jsz=FIX["jsz"], connz={"num_connections": 0},
        base_url="http://localhost:8222", scheme="http", tls_verified=False,
        monitoring_unauthenticated=True, config=FIX["config"]["hardened"],
    )
    assert not [r for r in col.resources if r.kind == "runtime_client"]
    col_none = nats_build(
        varz=FIX["varz"]["hardened"], jsz=FIX["jsz"], connz=None,
        base_url="http://localhost:8222", scheme="http", tls_verified=False,
        monitoring_unauthenticated=True, config=FIX["config"]["hardened"],
    )
    assert not [r for r in col_none.resources if r.kind == "runtime_client"]


# ── PgBouncer SHOW CLIENTS ────────────────────────────────────────────────────
_SHOW_CLIENTS = [
    # two sockets, one role, one host -> one aggregated resource, TLS reported present
    {"user": "app_rw", "database": "orders", "addr": "10.2.0.7", "port": 5432,
     "state": "active", "tls": "TLSv1.3", "connect_time": "2026-07-02 09:00:00"},
    {"user": "app_rw", "database": "orders", "addr": "10.2.0.7", "port": 5433,
     "state": "idle", "tls": "TLSv1.3", "connect_time": "2026-07-02 09:01:00"},
    # shared superuser, plaintext, from public address space
    {"user": "postgres", "database": "orders", "addr": "93.184.216.34", "port": 5555,
     "state": "active", "tls": "", "connect_time": "2026-07-02 08:00:00"},
]

_SECURE_CONFIG = {"auth_type": "scram-sha-256", "client_tls_sslmode": "require",
                  "server_tls_sslmode": "verify-full", "admin_users": "pgb_admin"}


def _pgb_clients(rows=None):
    col = pgb_build(dict(_SECURE_CONFIG), [], [], config_readable=True, outcomes={},
                    clients=_parse_clients(_SHOW_CLIENTS if rows is None else rows))
    return [r for r in col.resources if r.kind == "runtime_client"], col


def test_pgbouncer_emits_runtime_clients_aggregated_by_user_db_and_addr():
    clients, _ = _pgb_clients()
    assert len(clients) == 2
    app = _by_principal(clients, "app_rw")
    assert app.raw["connections"] == 2
    assert app.raw["observed_via"] == "SHOW CLIENTS"
    assert app.raw["vhost"] == "orders"
    assert app.raw["principal_known"] is True, "SHOW CLIENTS always names the authenticated role"


def test_pgbouncer_empty_tls_string_is_plaintext_not_unknown():
    clients, _ = _pgb_clients()
    assert _by_principal(clients, "app_rw").raw["tls_all"] is True
    pg = _by_principal(clients, "postgres")
    assert pg.raw["tls_all"] is False
    assert _fire("RUNTIME.TRANSPORT.PLAINTEXT_IN_USE", pg)


def test_pgbouncer_missing_tls_column_is_unknown_and_reports_a_coverage_gap():
    """An older PgBouncer omits the column entirely. That is NOT evidence of plaintext, and the
    rule must say so rather than assert an exposure it cannot see."""
    old = [{"user": "app_rw", "database": "orders", "addr": "10.2.0.7", "state": "active"}]
    clients, _ = _pgb_clients(old)
    assert clients[0].raw["tls_all"] is None
    hits = _fire("RUNTIME.TRANSPORT.PLAINTEXT_IN_USE", clients[0])
    assert hits and hits[0].assessable is False
    assert "does not report" in hits[0].assessment_reason


def test_pgbouncer_shared_superuser_from_public_peer_fires_both_rules():
    clients, _ = _pgb_clients()
    pg = _by_principal(clients, "postgres")
    assert _fire("RUNTIME.IDENTITY.SHARED_DEFAULT_IN_USE", pg)
    assert _fire("RUNTIME.ACCESS.UNEXPECTED_PEER", pg)


def test_pgbouncer_clean_client_fires_nothing():
    clients, _ = _pgb_clients()
    app = _by_principal(clients, "app_rw")
    for rule_id in EXPECTED_RUNTIME_RULES:
        assert not _fire(rule_id, app), f"{rule_id} should be silent on a clean client"


def test_pgbouncer_runtime_client_links_to_its_declared_user():
    """The acts_as edge is what lets the graph join live use to the declared identity — and what
    runtime_evidence's never-observed reasoning is ultimately measured against."""
    _, col = _pgb_clients()
    acts = [e for e in col.edges if e.kind == "acts_as"]
    assert {e.dst_ext_id for e in acts} == {"pgbouncer-user-app_rw", "pgbouncer-user-postgres"}


def test_pgbouncer_no_clients_is_not_an_error():
    clients, col = _pgb_clients([])
    assert clients == []
    pool = next(r for r in col.resources if r.kind == "pgbouncer_pool")
    assert pool.raw["live_client_count"] == 0


# ── the cross-source guarantee ────────────────────────────────────────────────
def test_both_sources_speak_the_same_raw_contract():
    """The keys detect/runtime.py reads must be present on EVERY source's runtime_client, or a
    rule silently no-ops on one connector while working on another."""
    required = {"principal", "principal_known", "peer_host", "connections", "tls_all",
                "observed_via"}
    nats_clients, _ = _nats_clients()
    pgb_clients, _ = _pgb_clients()
    for r in nats_clients + pgb_clients:
        assert required <= set(r.raw), f"{r.ext_id} is missing {required - set(r.raw)}"
        assert r.labels.get("source"), "every runtime resource must name the source that saw it"
