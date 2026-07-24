"""NHI derivation — the per-connector extractors that normalize identity/credential/grant."""
from vectasec.contracts import Collected, Resource
from vectasec.identity import derive_identities, IDENTITY_EXTRACTORS


def _kinds(resources):
    out: dict[str, int] = {}
    for r in resources:
        out[r.kind] = out.get(r.kind, 0) + 1
    return out


def test_all_connectors_have_an_extractor():
    assert set(IDENTITY_EXTRACTORS) >= {"kafka", "rabbitmq", "kong", "mcp", "redis"}


def test_kafka_acls_become_identity_and_grants():
    broker = Resource(kind="broker", name="broker-1", ext_id="broker-1", raw={"acls": {
        "outcome": "ok", "bindings": [
            {"restype": "TOPIC", "name": "payments", "pattern": "LITERAL",
             "principal": "User:alice", "host": "*", "operation": "READ", "permission_type": "ALLOW"},
            {"restype": "TOPIC", "name": "*", "pattern": "LITERAL",
             "principal": "User:svc", "host": "*", "operation": "ALL", "permission_type": "ALLOW"},
        ]}})
    col = derive_identities("kafka", Collected(resources=[broker]))
    k = _kinds(col.resources)
    assert k.get("identity") == 2          # alice + svc, deduped
    assert k.get("grant") == 2
    # the wildcard ALL grant is flagged wildcard; the literal READ is not
    grants = [r for r in col.resources if r.kind == "grant"]
    assert any(g.raw["wildcard"] for g in grants) and any(not g.raw["wildcard"] for g in grants)
    # literal topic grant resolves an edge to the collected topic
    assert any(e.dst_ext_id == "topic-payments" and e.kind == "grants_access" for e in col.edges)


def test_kafka_exposes_no_credentials():
    broker = Resource(kind="broker", name="broker-1", ext_id="broker-1",
                      raw={"acls": {"bindings": [
                          {"restype": "TOPIC", "name": "t", "pattern": "LITERAL",
                           "principal": "User:a", "operation": "READ", "permission_type": "ALLOW"}]}})
    col = derive_identities("kafka", Collected(resources=[broker]))
    assert _kinds(col.resources).get("credential") is None   # AdminClient can't read SASL creds


def test_rabbitmq_user_perms_and_weak_hash():
    user = Resource(kind="user", name="app", ext_id="user-app", raw={
        "name": "app", "tags": ["administrator"], "hashing_algorithm": "rabbit_password_hashing_md5",
        "has_internal_password": True, "default_password_confirmed": False})
    # connector stores the short form; the extractor reads hashing_algorithm verbatim
    user.raw["hashing_algorithm"] = "md5"
    perm = Resource(kind="permission", name="app@/", ext_id="permission-/-app", raw={
        "user": "app", "vhost": "/", "configure": ".*", "write": "amq\\.", "read": ""})
    col = derive_identities("rabbitmq", Collected(resources=[user, perm]))
    k = _kinds(col.resources)
    assert k.get("identity") == 1 and k.get("credential") == 1
    cred = next(r for r in col.resources if r.kind == "credential")
    assert cred.raw["hashing"] == "md5"
    # configure=.* is wildcard; write=amq\. is not; read="" produces no grant
    grants = [r for r in col.resources if r.kind == "grant"]
    assert len(grants) == 2
    assert any(g.raw["action"] == "configure" and g.raw["wildcard"] for g in grants)
    assert all(g.raw["action"] != "read" for g in grants)


def test_kong_consumer_credentials_counted_not_valued():
    consumer = Resource(kind="consumer", name="svc", ext_id="kong-consumer-1", raw={
        "username": "svc", "credentials": {
            "key-auth": {"count": 2}, "jwt": {"count": 0},
            "acls": {"groups": ["admins"]}}})
    col = derive_identities("kong", Collected(resources=[consumer]))
    k = _kinds(col.resources)
    assert k.get("identity") == 1
    creds = [r for r in col.resources if r.kind == "credential"]
    assert len(creds) == 1 and creds[0].raw["credential_type"] == "api_key"   # jwt count 0 skipped
    assert creds[0].raw["count"] == 2
    grants = [r for r in col.resources if r.kind == "grant"]
    assert any("admins" in g.raw["target"] for g in grants)


def test_redis_user_nopass_has_no_credential_but_god_mode_grant():
    default = Resource(kind="redis_user", name="default", ext_id="redis-user-x-default", raw={
        "username": "default", "enabled": True, "nopass": True,
        "keys": "~*", "commands": "+@all"})
    col = derive_identities("redis", Collected(resources=[default]))
    k = _kinds(col.resources)
    assert k.get("identity") == 1 and k.get("credential") is None   # nopass → no credential
    grant = next(r for r in col.resources if r.kind == "grant")
    assert grant.raw["wildcard"] is True


def test_unknown_type_is_a_noop():
    col = derive_identities("nats", Collected(resources=[Resource(kind="x", name="y", ext_id="z")]))
    assert len(col.resources) == 1   # no extractor → unchanged
