"""Redpanda connector + rulepack — offline. No httpx, no live Admin API. Detectors run on
parse_cluster() output from golden Admin API response dicts.
"""
from vectasec.contracts import ScanContext
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
from vectasec.connect.redpanda import parse_cluster
import vectasec.detect.redpanda as rp


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=list(resources))


def cluster(cluster_config=None, node_config=None, *, config_readable=True,
            anonymous_readable=False, version="24.2.1", tls_url=False, brokers=None):
    cc = {"enable_sasl": True, "kafka_enable_authorization": True,
          "admin_api_require_auth": True, "superusers": ["admin"]}
    cc.update(cluster_config or {})
    nc = node_config if node_config is not None else {"redpanda": {
        "kafka_api_tls": [{"enabled": True, "name": "external"}]}}
    return parse_cluster("http://redpanda:9644", cc, nc, brokers or [{"node_id": 0}],
                         config_readable=config_readable, anonymous_readable=anonymous_readable,
                         version=version, tls_url=tls_url)


def test_connector_registered_and_secret_marked():
    assert "redpanda" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["redpanda"]}
    assert fields["password"].secret and fields["url"].required


# ── REDPANDA.AUTH.SASL_DISABLED ────────────────────────────────────────────────
def test_sasl_disabled_fires_critical():
    r = cluster({"enable_sasl": False})
    hits = rp.sasl_disabled(r, _ctx([r]))
    assert len(hits) == 1 and hits[0].severity is None   # decorator critical


def test_sasl_enabled_does_not_fire():
    assert rp.sasl_disabled(cluster({"enable_sasl": True}), _ctx([])) == []


def test_sasl_not_assessable_when_config_unreadable():
    r = cluster(config_readable=False)
    hits = rp.sasl_disabled(r, _ctx([r]))
    assert len(hits) == 1 and hits[0].assessable is False


# ── REDPANDA.AUTHZ.DISABLED ────────────────────────────────────────────────────
def test_authz_disabled_fires_when_false():
    r = cluster({"kafka_enable_authorization": False})
    assert len(rp.authz_disabled(r, _ctx([r]))) == 1


def test_authz_null_with_sasl_on_is_enforced():
    r = cluster({"kafka_enable_authorization": None, "enable_sasl": True})
    assert rp.authz_disabled(r, _ctx([r])) == []


def test_authz_null_with_sasl_off_is_not_enforced():
    r = cluster({"kafka_enable_authorization": None, "enable_sasl": False})
    hits = rp.authz_disabled(r, _ctx([r]))
    assert len(hits) == 1 and "unset (null)" in hits[0].observation


def test_authz_true_does_not_fire():
    assert rp.authz_disabled(cluster({"kafka_enable_authorization": True}), _ctx([])) == []


# ── REDPANDA.ADMIN_API.NO_AUTH ─────────────────────────────────────────────────
def test_admin_api_critical_when_anonymous():
    r = cluster({"admin_api_require_auth": True}, anonymous_readable=True)
    hits = rp.admin_api_no_auth(r, _ctx([r]))
    assert len(hits) == 1 and hits[0].severity == "critical"
    assert "NO credentials" in hits[0].observation


def test_admin_api_high_when_flag_false_but_authenticated():
    r = cluster({"admin_api_require_auth": False}, anonymous_readable=False)
    hits = rp.admin_api_no_auth(r, _ctx([r]))
    assert len(hits) == 1 and hits[0].severity == "high"


def test_admin_api_does_not_fire_when_required_and_no_anon():
    r = cluster({"admin_api_require_auth": True}, anonymous_readable=False)
    assert rp.admin_api_no_auth(r, _ctx([r])) == []


def test_admin_api_not_assessable_when_config_unreadable():
    r = cluster(config_readable=False, anonymous_readable=False)
    # config_readable False means admin_api_require_auth reads None -> not proven false
    r.raw["admin_api_require_auth"] = None
    hits = rp.admin_api_no_auth(r, _ctx([r]))
    assert len(hits) == 1 and hits[0].assessable is False


# ── REDPANDA.TLS.KAFKA_API_DISABLED ────────────────────────────────────────────
def test_tls_fires_when_kafka_api_has_no_tls():
    r = cluster(node_config={"redpanda": {"kafka_api_tls": [{"enabled": False}]}})
    assert len(rp.kafka_api_tls_disabled(r, _ctx([r]))) == 1


def test_tls_does_not_fire_when_enabled():
    r = cluster(node_config={"redpanda": {"kafka_api_tls": [{"enabled": True}]}})
    assert rp.kafka_api_tls_disabled(r, _ctx([r])) == []


def test_tls_not_assessable_when_node_config_missing_the_block():
    r = cluster(node_config={"redpanda": {}})
    hits = rp.kafka_api_tls_disabled(r, _ctx([r]))
    assert len(hits) == 1 and hits[0].assessable is False
