"""The new cross-cutting detector packs: NHI hygiene, DSPM data rules, and Redis."""
from vectasec.contracts import ScanContext, Resource
from vectasec.detect import identity as nhi
from vectasec.detect import data as dspm
from vectasec.detect import redis as rd


def _ctx(resources, config=None):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources, config=config or {})


# ── NHI ───────────────────────────────────────────────────────────────────────
def test_nhi_wildcard_grant_fires_on_allow_only():
    allow = Resource(kind="grant", name="g", ext_id="grant:x:1", raw={
        "system": "kafka", "action": "all", "target": "topic:*", "wildcard": True,
        "permission": "allow", "identity_ext_id": "identity:x"})
    deny = Resource(kind="grant", name="g", ext_id="grant:x:2", raw={
        "system": "kafka", "action": "all", "target": "topic:*", "wildcard": True,
        "permission": "deny", "identity_ext_id": "identity:x"})
    assert nhi.grant_wildcard(allow, _ctx([allow]))
    assert nhi.grant_wildcard(deny, _ctx([deny])) == []   # a deny wildcard is not over-privilege


def test_nhi_shared_default_matches_leaf_name():
    guest = Resource(kind="identity", name="guest", ext_id="identity:rabbitmq:guest",
                     labels={"system": "rabbitmq"}, raw={"identity_type": "service_account"})
    named = Resource(kind="identity", name="User:alice", ext_id="identity:kafka:alice",
                     labels={"system": "kafka"}, raw={"identity_type": "service_account"})
    assert nhi.identity_shared_default(guest, _ctx([guest]))
    assert nhi.identity_shared_default(named, _ctx([named])) == []


def test_nhi_weak_hash_only_md5_sha1():
    md5 = Resource(kind="credential", name="c", ext_id="cred:1", raw={"hashing": "md5", "system": "r"})
    bcrypt = Resource(kind="credential", name="c", ext_id="cred:2", raw={"hashing": "bcrypt", "system": "r"})
    assert nhi.credential_weak_hash(md5, _ctx([md5]))
    assert nhi.credential_weak_hash(bcrypt, _ctx([bcrypt])) == []


def test_nhi_kong_api_key_storage_is_not_assessable():
    cred = Resource(kind="credential", name="c", ext_id="cred:3",
                    raw={"credential_type": "api_key", "system": "kong", "count": 3})
    hits = nhi.credential_storage_unverified(cred, _ctx([cred]))
    assert hits and hits[0].assessable is False and hits[0].assessment_reason


# ── DSPM ──────────────────────────────────────────────────────────────────────
def test_data_inventory_high_sensitivity_only():
    pci = Resource(kind="topic", name="payments", ext_id="t1",
                   labels={"data_classes": "pci", "data_sensitivity": "high", "data_signals": "pci:payments"})
    pii = Resource(kind="topic", name="customer", ext_id="t2",
                   labels={"data_classes": "pii", "data_sensitivity": "medium", "data_signals": "pii:customer"})
    assert dspm.sensitive_inventory(pci, _ctx([pci]))
    assert dspm.sensitive_inventory(pii, _ctx([pii])) == []   # medium is not in the inventory rule


def test_data_toxic_combination_pci_plus_plaintext_no_authz_is_critical():
    broker = Resource(kind="broker", name="broker-1", ext_id="broker-1", raw={"config": {
        "listener.security.protocol.map": {"value": "CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT"},
        "controller.listener.names": {"value": "CONTROLLER"},
        "authorizer.class.name": {"value": ""}}})
    topic = Resource(kind="topic", name="payments", ext_id="topic-payments",
                     labels={"data_classes": "pci", "data_sensitivity": "high", "data_signals": "pci:payments"})
    hits = dspm.sensitive_plaintext_exposure(topic, _ctx([broker, topic]))
    assert hits and hits[0].severity == "critical"
    assert "payments" in hits[0].observation and "PLAINTEXT" in hits[0].observation


def test_data_exposure_needs_both_classification_and_exposure():
    secure_broker = Resource(kind="broker", name="b", ext_id="b1", raw={"config": {
        "listener.security.protocol.map": {"value": "EXTERNAL:SASL_SSL"},
        "authorizer.class.name": {"value": "kafka.security.authorizer.AclAuthorizer"}}})
    topic = Resource(kind="topic", name="payments", ext_id="topic-payments",
                     labels={"data_classes": "pci", "data_sensitivity": "high", "data_signals": "pci:payments"})
    assert dspm.sensitive_plaintext_exposure(topic, _ctx([secure_broker, topic])) == []
    unclassified = Resource(kind="topic", name="heartbeat", ext_id="topic-hb", labels={})
    broker = Resource(kind="broker", name="b", ext_id="b1", raw={"config": {
        "authorizer.class.name": {"value": ""}}})
    assert dspm.sensitive_plaintext_exposure(unclassified, _ctx([broker, unclassified])) == []


# ── Redis ─────────────────────────────────────────────────────────────────────
def _server(**raw):
    base = {"redis_version": "7.2.4", "has_requirepass": False, "protected_mode": "yes",
            "bind": "127.0.0.1", "tls_port": "6380"}
    base.update(raw)
    return Resource(kind="redis_server", name="r", ext_id="redis-r", raw=base)


def test_redis_no_password_needs_default_nopass():
    default = Resource(kind="redis_user", name="default", ext_id="u1", raw={"username": "default", "nopass": True})
    assert rd.no_password(_server(has_requirepass=False), _ctx([default]))
    assert rd.no_password(_server(has_requirepass=True), _ctx([default])) == []


def test_redis_protected_mode_bind_tls():
    assert rd.protected_mode_off(_server(protected_mode="no"), _ctx([]))
    assert rd.protected_mode_off(_server(protected_mode="yes"), _ctx([])) == []
    assert rd.bind_all(_server(bind="0.0.0.0"), _ctx([]))
    assert rd.bind_all(_server(bind=""), _ctx([]))                      # unset == all interfaces
    assert rd.bind_all(_server(bind="127.0.0.1"), _ctx([])) == []
    assert rd.tls_disabled(_server(tls_port="0"), _ctx([]))
    assert rd.tls_disabled(_server(tls_port="6380"), _ctx([])) == []


def test_redis_redishell_version_boundaries():
    assert rd.rce_cve(_server(redis_version="7.2.4"), _ctx([]))          # < 7.2.11 → vulnerable
    assert rd.rce_cve(_server(redis_version="7.2.11"), _ctx([])) == []   # patched
    assert rd.rce_cve(_server(redis_version="8.2.2"), _ctx([])) == []
    # unparseable / unmapped series → not assessable, never a silent pass
    hits = rd.rce_cve(_server(redis_version="unknown"), _ctx([]))
    assert hits and hits[0].assessable is False


def test_redis_user_nopass():
    u = Resource(kind="redis_user", name="svc", ext_id="u2",
                 raw={"username": "svc", "enabled": True, "nopass": True})
    off = Resource(kind="redis_user", name="svc", ext_id="u3",
                   raw={"username": "svc", "enabled": False, "nopass": True})
    assert rd.user_nopass(u, _ctx([u]))
    assert rd.user_nopass(off, _ctx([off])) == []      # a disabled user is not an open door
