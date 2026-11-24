"""Effective access (effective.py, detect/effective_access.py), pinned against the documented
semantics in research_notes/.../engine_depth_techniques.md §B1-B3."""
from vectasec.contracts import Resource
from vectasec.effective import (kafka_broker_view, kafka_topic_access, parse_redis_acl_line,
                                rabbitmq_vhost_access, redis_user_access, who_can,
                                who_can_consume)
from vectasec import detect as _detect  # noqa: F401
from vectasec.registry import DETECTORS


def acl(name, principal, op="READ", perm="ALLOW", pattern="LITERAL", host="*"):
    return {"restype": "TOPIC", "name": name, "pattern": pattern, "principal": principal,
            "host": host, "operation": op, "permission_type": perm}


def broker(bindings, everyone="false", supers="User:admin", authorizer="org.apache.kafka.metadata.authorizer.StandardAuthorizer", outcome="ok"):
    return {"kind": "broker", "raw": {"acls": {"outcome": outcome, "bindings": bindings},
            "config": {"super.users": {"value": supers}, "allow.everyone.if.no.acl.found": {"value": everyone},
                       "authorizer.class.name": {"value": authorizer}}}}


# ── Kafka ─────────────────────────────────────────────────────────────────
def test_unreadable_acls_are_unknown_not_open():
    a = kafka_topic_access("t", kafka_broker_view([broker([], outcome="error")]))
    assert a["assessable"] is False and a["everyone_read"] is None


def test_no_authorizer_means_everyone():
    a = kafka_topic_access("t", kafka_broker_view([broker([], authorizer="")]))
    assert a["everyone_read"] and a["everyone_write"]


def test_allow_everyone_opens_only_unmatched_topics():
    view = kafka_broker_view([broker([acl("orders", "User:svc")], everyone="true")])
    assert kafka_topic_access("payments", view)["everyone_read"] is True
    o = kafka_topic_access("orders", view)
    assert o["everyone_read"] is False and [r["principal"] for r in o["readers"]] == ["User:admin", "User:svc"]


def test_one_wildcard_acl_closes_every_topic():
    view = kafka_broker_view([broker([acl("*", "User:metrics", op="DESCRIBE")], everyone="true")])
    a = kafka_topic_access("payments", view)
    assert a["everyone_read"] is False and [r["principal"] for r in a["readers"]] == ["User:admin"]


def test_prefixed_deny_beats_allow_and_implied_describe():
    view = kafka_broker_view([broker([
        acl("pay", "User:*", op="READ", pattern="PREFIXED"),
        acl("payments", "User:intern", op="READ", perm="DENY"),
        acl("payments", "User:etl", op="ALL"),
        acl("payments", "User:writer", op="WRITE"),
    ])])
    a = kafka_topic_access("payments", view)
    readers = {r["principal"] for r in a["readers"]}
    assert a["everyone_read"] is True and "User:intern" not in readers and "User:etl" in readers
    assert {r["principal"] for r in a["writers"]} == {"User:admin", "User:etl", "User:writer"}
    assert kafka_topic_access("other", view)["everyone_read"] is False


def test_everyone_deny_removes_everyone_allow():
    view = kafka_broker_view([broker([acl("t", "User:*"), acl("t", "User:*", perm="DENY")])])
    assert kafka_topic_access("t", view)["everyone_read"] is False


# ── RabbitMQ ──────────────────────────────────────────────────────────────
def test_rabbitmq_vhost_access_and_consumers():
    perms = [{"user": "guest", "vhost": "/", "configure": ".*", "write": ".*", "read": ".*"},
             {"user": "billing", "vhost": "/", "configure": "^$", "write": "^billing\\.", "read": "orders"},
             {"user": "other", "vhost": "/x", "configure": ".*", "write": ".*", "read": ".*"}]
    v = rabbitmq_vhost_access("/", perms, [{"name": "guest", "tags": ["administrator"]}, {"name": "billing", "tags": []}])
    assert v["read_everything"] == ["guest"] and v["administrators"] == ["guest"]
    billing = next(u for u in v["users"] if u["user"] == "billing")
    assert billing["configure"]["scope"] == "none" and billing["read"]["unanchored"] is True
    assert [c["user"] for c in who_can_consume("preorders-dlq", "/", perms)] == ["guest", "billing"]


# ── Redis ─────────────────────────────────────────────────────────────────
def test_parse_acl_line_with_selector():
    p = parse_redis_acl_line("user app on sanitize-payload ~app1:* &* -@all +get +set (~app2:* %R~app3:* +@read)")
    assert p["name"] == "app" and p["keys"] == ["~app1:*"] and p["commands"] == ["-@all", "+get", "+set"]
    assert p["selectors"][0]["keys"] == ["~app2:*", "%R~app3:*"] and p["selectors"][0]["commands"] == ["+@read"]


def test_default_user_is_anonymous_and_all_powerful():
    a = redis_user_access({"name": "default", "enabled": True, "nopass": True, "keys": "~*", "commands": "+@all"})
    assert a["anonymous"] and a["all_keys"] and len(a["risky"]) == 10 and not a["keyless_bypass"]


def test_key_fence_bypass_and_self_escalation():
    a = redis_user_access({"name": "tenant1", "enabled": True, "keys": "~tenant1:*", "commands": "+@all"})
    assert a["key_restricted"] and a["keyless_bypass"] and a["self_escalation"]
    safe = redis_user_access({"name": "t", "enabled": True, "keys": "~t:*", "commands": "+@all -@dangerous"})
    assert not safe["keyless_bypass"] and not safe["self_escalation"]
    sub = redis_user_access({"name": "s", "enabled": True, "keys": "~s:*", "commands": "-@all +get +config|get"})
    assert not sub["self_escalation"], "+config|get does not grant CONFIG SET"
    later = redis_user_access({"name": "l", "enabled": True, "keys": "~l:*", "commands": "-@all +get +flushdb -flushdb"})
    assert not later["keyless_bypass"], "rules apply left to right"
    sel = redis_user_access({"name": "x", "enabled": True, "keys": "~x:*", "commands": "-@all +get",
                             "selectors": [{"keys": "~y:*", "commands": "+@keyspace"}]})
    assert sel["keyless_bypass"], "any selector may authorise a command"


def test_detectors_fire_only_on_stored_rule_lines():
    by = {d.rule_id: d for d in DETECTORS}
    class Ctx:
        resources = []
    u = Resource(kind="redis_user", name="tenant1", ext_id="u", raw={
        "username": "tenant1", "enabled": True, "nopass": False,
        "acl_line": "user tenant1 on ~tenant1:* &* +@all"})
    assert by["REDIS.ACL.KEYPATTERN_BYPASS"].fn(u, Ctx) and by["REDIS.ACL.SELF_ESCALATION"].fn(u, Ctx)
    old = Resource(kind="redis_user", name="tenant1", ext_id="u", raw={"username": "tenant1", "enabled": True, "commands": "[]", "keys": "~tenant1:*"})
    assert by["REDIS.ACL.KEYPATTERN_BYPASS"].fn(old, Ctx) == [], "no ordered rules stored: no claim"
    root = Resource(kind="redis_user", name="default", ext_id="d", raw={"username": "default", "enabled": True, "acl_line": "user default on nopass ~* &* +@all"})
    assert by["REDIS.ACL.SELF_ESCALATION"].fn(root, Ctx) == [], "all-powerful by design is a different finding"


def test_kafka_detectors_use_scan_context_and_raise_severity_for_sensitive_data():
    by = {d.rule_id: d for d in DETECTORS}
    class Ctx:
        resources = [Resource(kind="broker", name="b", ext_id="b", raw=broker([acl("orders", "User:svc")], everyone="true")["raw"])]
    pay = Resource(kind="topic", name="payments", ext_id="t", labels={"data_sensitivity": "high"})
    hits = by["KAFKA.EFFECTIVE.TOPIC_OPEN_NO_ACL"].fn(pay, Ctx)
    assert hits and hits[0].severity == "critical"
    orders = Resource(kind="topic", name="orders", ext_id="o")
    assert by["KAFKA.EFFECTIVE.TOPIC_OPEN_NO_ACL"].fn(orders, Ctx) == []
    class Ctx2:
        resources = [Resource(kind="broker", name="b", ext_id="b", raw=broker([acl("pay", "User:*", pattern="PREFIXED")])["raw"])]
    assert by["KAFKA.EFFECTIVE.TOPIC_WORLD_READABLE"].fn(pay, Ctx2)


def test_who_can_dispatch():
    out = who_can({"kind": "topic", "name": "orders"}, [broker([acl("orders", "User:svc")])])
    assert out["system"] == "kafka" and out["everyone_read"] is False
    assert who_can({"kind": "rest_route", "name": "x"}, []) is None
    r = who_can({"kind": "redis_server", "raw": {"bind": "0.0.0.0", "protected_mode": "no"}},
                [{"kind": "redis_user", "raw": {"username": "default", "enabled": True, "nopass": True,
                                                 "acl_line": "user default on nopass ~* &* +@all"}}])
    assert r["anonymous_access"] and r["exposed_bind"] and "protected mode off" in r["reason"]
