"""Unit tests for the KAFKA rulepack. Offline: no broker, no DB, no network.

Every rule gets a FIRE case and a DOES-NOT-FIRE case. The negative is the load-bearing one —
a detector that always fires carries no information.

The baseline for both is the REAL captured broker snapshot in
fixtures/kafka_broker_config.json (apache/kafka:3.9.0, KRaft, deliberately misconfigured), so a
rule that only passes against a hand-written dict cannot pass here. Note the fixture's entries
carry `source` as a raw int and no `source_name`, which exercises the detector's `_SOURCE`
fallback rather than the connector's resolved name.
"""
import copy
import json
import pathlib

import pytest

from vectasec.contracts import Resource, ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.kafka  # noqa: F401  — import registers the rulepack

_FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "kafka_broker_config.json").read_text()
)

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("KAFKA.")}

# Every rule_id the pack is expected to ship. Kept explicit so silently dropping a detector
# fails a test rather than quietly shrinking coverage.
EXPECTED_RULES = {
    "KAFKA.LISTENER.PLAINTEXT",
    "KAFKA.LISTENER.SASL_PLAINTEXT",
    "KAFKA.INTERBROKER.PLAINTEXT",
    "KAFKA.AUTHZ.NO_AUTHORIZER",
    "KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL",
    "KAFKA.ACL.WILDCARD_PRINCIPAL",
    "KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS",
    "KAFKA.ACL.ANONYMOUS_PRINCIPAL",
    "KAFKA.ACL.PREFIXED_OVERBROAD",
    "KAFKA.SASL.PLAIN_WITHOUT_TLS",
    "KAFKA.SASL.SCRAM_WITHOUT_TLS",
    "KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT",
    "KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED",
    "KAFKA.SSL.HOSTNAME_VERIFICATION_DISABLED",
    "KAFKA.TOPIC.AUTO_CREATE_ENABLED",
    "KAFKA.TOPIC.RETENTION_UNBOUNDED",
    "KAFKA.DURABILITY.MIN_INSYNC_REPLICAS_ONE",
    "KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION",
    "KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES",
    "KAFKA.ZK.LEGACY_MODE_PLAINTEXT_ZK",
    "KAFKA.AUTHZ.SUPER_USERS_BREADTH",
    "KAFKA.DELEGATION_TOKEN.INSECURE_TRANSPORT",
    "KAFKA.ZK.KRAFT_MIGRATION_ACL_GAP",
}


# ── builders ──────────────────────────────────────────────────────────────
DELETE = object()   # sentinel: remove a key entirely (a real response omits keys)


def entry(value, *, source=4, is_default=False, is_sensitive=False):
    """A describe_configs entry in the shape the real broker returns. source=4 is
    STATIC_BROKER_CONFIG — i.e. an operator explicitly set this."""
    return {"value": value, "source": source, "is_default": is_default,
            "is_sensitive": is_sensitive}


def config(overrides=None) -> dict:
    """The real fixture config with overrides applied. A bare string/None value is wrapped as an
    explicitly-set static entry; pass a dict for full control, or DELETE to drop the key."""
    cfg = copy.deepcopy(_FIXTURE["config"])
    for key, val in (overrides or {}).items():
        if val is DELETE:
            cfg.pop(key, None)
        elif isinstance(val, dict):
            cfg[key] = val
        else:
            cfg[key] = entry(val)
    return cfg


def acl(principal="User:svc", operation="READ", restype="TOPIC", pattern="LITERAL",
        name="orders", host="*", permission_type="ALLOW") -> dict:
    return {"restype": restype, "name": name, "pattern": pattern, "principal": principal,
            "host": host, "operation": operation, "permission_type": permission_type}


def broker(cfg=None, *, bid=1, outcome="ok", bindings=(), cluster_scope=True,
           cluster_dynamic=None) -> Resource:
    return Resource(
        kind="broker", name=f"broker-{bid}", ext_id=f"broker-{bid}",
        labels={"host": "localhost", "port": "9092"},
        raw={"id": bid, "host": "localhost", "port": 9092,
             "config": config() if cfg is None else cfg,
             "cluster_id": _FIXTURE["cluster_id"],
             "cluster_dynamic_config": cluster_dynamic,
             "acls": {"outcome": outcome, "bindings": list(bindings), "error": None},
             "cluster_scope": cluster_scope},
    )


def topic(name="orders", *, cfg=None, rf=3, internal=False, partitions=3) -> Resource:
    return Resource(
        kind="topic", name=name, ext_id=f"topic-{name}", labels={"partitions": str(partitions)},
        raw={"partitions": partitions, "replication_factor": rf,
             "internal": internal, "config": cfg or {}},
    )


def scan(*resources) -> ScanContext:
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1", resources=list(resources))


def fire(rule_id, resource, ctx=None) -> list:
    """Run one rule against one resource. Defaults to a context holding just that resource."""
    d = RULES[rule_id]
    assert resource.kind in d.kinds, f"{rule_id} does not apply to kind={resource.kind}"
    return d.fn(resource, ctx or scan(resource)) or []


def sev(hits, rule_id) -> list:
    """Effective severities — a Hit that leaves severity None defers to the decorator."""
    base = RULES[rule_id].severity
    return [h.severity or base for h in hits]


def sweep(ctx) -> list:
    """Every KAFKA rule against every resource, as the scan loop would. -> [(rule_id, severity)]"""
    out = []
    for d in DETECTORS:
        if not d.rule_id.startswith("KAFKA."):
            continue
        for r in ctx.resources:
            if r.kind not in d.kinds:
                continue
            for h in d.fn(r, ctx) or []:
                out.append((d.rule_id, h.severity or d.severity))
    return out


# The fixture records topic NAMES only — no partition/replica data — so replication_factor is
# genuinely unknown here, which is what the connector emits when partitions aren't collected.
def fixture_scan(cfg=None, **kw):
    b = broker(cfg, **kw)
    ctx = scan(b, *[topic(n, rf=None) for n in _FIXTURE["topics"]])
    return b, ctx


# Hardened counterpart of the fixture: SSL/SASL_SSL listeners, authorizer set, mTLS required on
# the SSL listener, nothing auto-created, no unclean elections. NOTHING may fire on this.
def hardened_config(overrides=None) -> dict:
    base = {
        "listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SASL_SSL",
        "authorizer.class.name": entry("org.apache.kafka.metadata.authorizer.StandardAuthorizer"),
        "listener.name.internal.ssl.client.auth": entry("required"),
        "sasl.enabled.mechanisms": entry("SCRAM-SHA-512"),
        "auto.create.topics.enable": "false",
        "unclean.leader.election.enable": "false",
        # Left as the real broker returns it: redacted, but is_default=true proves it is untouched.
        "allow.everyone.if.no.acl.found": entry(None, source=5, is_default=True,
                                                is_sensitive=True),
    }
    base.update(overrides or {})
    return config(base)


def hardened_topic_config() -> dict:
    return {
        "cleanup.policy": entry("delete", source=5, is_default=True),
        "retention.ms": entry("604800000"),
        "retention.bytes": entry("-1", source=5, is_default=True),
        "min.insync.replicas": entry("2"),
        "unclean.leader.election.enable": entry("false", source=5, is_default=True),
    }


# ═══ registry sanity ══════════════════════════════════════════════════════
def test_all_expected_rules_are_registered():
    assert set(RULES) == EXPECTED_RULES


def test_rule_ids_are_unique():
    ids = [d.rule_id for d in DETECTORS if d.rule_id.startswith("KAFKA.")]
    assert len(ids) == len(set(ids)) == 23


def test_every_rule_declares_severity_and_title():
    for rid, d in RULES.items():
        assert d.severity in ("info", "low", "medium", "high", "critical"), rid
        assert d.title and d.kinds, rid


# ═══ the real fixture ═════════════════════════════════════════════════════
def test_fixture_produces_exactly_the_expected_findings():
    """The captured broker is misconfigured in five distinct ways; assert the whole result set,
    not just that something fired — an extra finding is as much a bug as a missing one."""
    _, ctx = fixture_scan()
    assert sorted(sweep(ctx)) == sorted([
        ("KAFKA.LISTENER.PLAINTEXT", "critical"),        # INTERNAL://:29092
        ("KAFKA.LISTENER.PLAINTEXT", "critical"),        # EXTERNAL://:9092
        ("KAFKA.INTERBROKER.PLAINTEXT", "high"),
        ("KAFKA.AUTHZ.NO_AUTHORIZER", "critical"),
        ("KAFKA.TOPIC.AUTO_CREATE_ENABLED", "high"),     # escalated: no authorizer
        ("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", "medium"),
    ])


def test_fixture_controller_listener_is_not_reported_as_a_client_listener():
    """CONTROLLER is mapped to PLAINTEXT in the fixture too, but carries no client traffic.
    It may still appear inside the echoed protocol map — just never as a reported listener."""
    b, ctx = fixture_scan()
    hits = fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)
    assert {h.source_ref["listener"] for h in hits} == {"INTERNAL", "EXTERNAL"}
    assert not any("CONTROLLER://:9093" in h.observation for h in hits)


def test_fixture_allow_everyone_is_silent_because_there_is_no_authorizer():
    """The fixture sets allow.everyone.if.no.acl.found explicitly (is_default=false) but has no
    authorizer, which makes the setting inert — reporting it would be a false claim."""
    e = _FIXTURE["config"]["allow.everyone.if.no.acl.found"]
    assert e["is_sensitive"] is True and e["value"] is None and e["is_default"] is False
    b, ctx = fixture_scan()
    assert fire("KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", b, ctx) == []


def test_fixture_super_users_is_absent_and_does_not_raise():
    """super.users is missing from a real describe_configs response; a subscript would KeyError."""
    assert _FIXTURE["config"].get("super.users") is None
    b, ctx = fixture_scan(bindings=[acl(operation="ALL", name="*")])
    assert len(fire("KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS", b, ctx)) == 1


def test_hardened_config_fires_nothing_at_all():
    """The global negative: a well-configured cluster must produce an empty report."""
    b = broker(hardened_config(), bindings=[acl()])
    ctx = scan(b, topic("orders", cfg=hardened_topic_config(), rf=3))
    assert sweep(ctx) == []


def test_every_hit_carries_observation_remediation_and_source_ref():
    _, ctx = fixture_scan()
    for d in DETECTORS:
        if not d.rule_id.startswith("KAFKA."):
            continue
        for r in ctx.resources:
            if r.kind not in d.kinds:
                continue
            for h in d.fn(r, ctx) or []:
                assert h.observation.strip(), d.rule_id
                assert h.remediation.strip(), d.rule_id
                assert h.source_ref, d.rule_id
                # Evidence must be a fact read from the target, not a verdict.
                assert "insecure" not in h.observation.lower(), d.rule_id


# ═══ KAFKA.LISTENER.PLAINTEXT ═════════════════════════════════════════════
def test_listener_plaintext_fires_on_fixture_with_observed_values():
    b, ctx = fixture_scan()
    hits = fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)
    assert len(hits) == 2
    assert sev(hits, "KAFKA.LISTENER.PLAINTEXT") == ["critical", "critical"]
    obs = " ".join(h.observation for h in hits)
    assert "EXTERNAL://:9092" in obs and "INTERNAL://:29092" in obs
    assert "CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT" in obs
    assert "'localhost'" in obs   # the advertised host actually read


def test_listener_plaintext_does_not_fire_when_all_listeners_are_ssl():
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SSL"}))
    assert fire("KAFKA.LISTENER.PLAINTEXT", b, ctx) == []


def test_listener_plaintext_resolves_through_the_map_not_the_listener_name():
    """A listener NAMED SSL but MAPPED to PLAINTEXT is still PLAINTEXT."""
    b, ctx = fixture_scan(config({
        "listeners": "SSL://:9092,CONTROLLER://:9093",
        "advertised.listeners": "SSL://kafka:9092",
        "inter.broker.listener.name": "SSL",
        "listener.security.protocol.map": "CONTROLLER:PLAINTEXT,SSL:PLAINTEXT"}))
    hits = fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)
    assert len(hits) == 1 and "SSL://:9092" in hits[0].observation


def test_listener_plaintext_is_low_on_a_loopback_bound_listener():
    b, ctx = fixture_scan(config({
        "listeners": "EXTERNAL://127.0.0.1:9092,CONTROLLER://:9093",
        "advertised.listeners": "EXTERNAL://127.0.0.1:9092"}))
    hits = fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)
    assert sev(hits, "KAFKA.LISTENER.PLAINTEXT") == ["low"]


def test_listener_plaintext_is_critical_when_advertised_on_a_routable_ip():
    """8.8.8.8, not a 203.0.113.x documentation address — Python's ipaddress classifies the
    TEST-NET ranges as private, so they are correctly NOT treated as routable."""
    b, ctx = fixture_scan(config({
        "listeners": "EXTERNAL://:9092,CONTROLLER://:9093",
        "advertised.listeners": "EXTERNAL://8.8.8.8:9092",
        "authorizer.class.name": entry("kafka.security.authorizer.AclAuthorizer")}))
    hits = fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)
    assert sev(hits, "KAFKA.LISTENER.PLAINTEXT") == ["critical"]
    assert "8.8.8.8" in hits[0].observation


def test_listener_plaintext_does_not_assume_a_dns_name_or_private_ip_is_public():
    """A DNS name resolves nowhere a config scan can see, so it stays unknown rather than being
    assumed public; an RFC1918 address is not public either. Both fall back to the authz tier."""
    for host in ("kafka.internal.acme.com", "10.0.0.7"):
        b, ctx = fixture_scan(config({
            "listeners": "EXTERNAL://:9092,CONTROLLER://:9093",
            "advertised.listeners": f"EXTERNAL://{host}:9092",
            "authorizer.class.name": entry("kafka.security.authorizer.AclAuthorizer")}))
        hits = fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)
        assert sev(hits, "KAFKA.LISTENER.PLAINTEXT") == ["high"], host


# ═══ KAFKA.LISTENER.SASL_PLAINTEXT ════════════════════════════════════════
def test_listener_sasl_plaintext_fires_and_names_the_mechanism():
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,"
                                          "EXTERNAL:SASL_PLAINTEXT",
        "sasl.enabled.mechanisms": "PLAIN"}))
    hits = fire("KAFKA.LISTENER.SASL_PLAINTEXT", b, ctx)
    assert len(hits) == 1
    assert sev(hits, "KAFKA.LISTENER.SASL_PLAINTEXT") == ["high"]
    assert "EXTERNAL://:9092" in hits[0].observation and "PLAIN" in hits[0].observation


def test_listener_sasl_plaintext_does_not_fire_on_sasl_ssl():
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SASL_SSL",
        "sasl.enabled.mechanisms": "PLAIN"}))
    assert fire("KAFKA.LISTENER.SASL_PLAINTEXT", b, ctx) == []


def test_listener_sasl_plaintext_is_medium_for_gssapi():
    """Kerberos supplies its own authentication; no password crosses the wire."""
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,"
                                          "EXTERNAL:SASL_PLAINTEXT",
        "sasl.enabled.mechanisms": entry("GSSAPI", source=5, is_default=True)}))
    hits = fire("KAFKA.LISTENER.SASL_PLAINTEXT", b, ctx)
    assert sev(hits, "KAFKA.LISTENER.SASL_PLAINTEXT") == ["medium"]


def test_listener_override_replaces_rather_than_unions_the_global_mechanisms():
    """global=SCRAM-SHA-512,PLAIN + listener override=SCRAM-SHA-512 must NOT report PLAIN."""
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,"
                                          "EXTERNAL:SASL_PLAINTEXT",
        "sasl.enabled.mechanisms": "SCRAM-SHA-512,PLAIN",
        "listener.name.external.sasl.enabled.mechanisms": "SCRAM-SHA-512"}))
    assert fire("KAFKA.SASL.PLAIN_WITHOUT_TLS", b, ctx) == []
    hits = fire("KAFKA.LISTENER.SASL_PLAINTEXT", b, ctx)
    assert len(hits) == 1 and "PLAIN," not in hits[0].observation


# ═══ KAFKA.INTERBROKER.PLAINTEXT ══════════════════════════════════════════
def test_interbroker_plaintext_fires_on_fixture():
    b, ctx = fixture_scan()
    hits = fire("KAFKA.INTERBROKER.PLAINTEXT", b, ctx)
    assert len(hits) == 1
    assert "inter.broker.listener.name=INTERNAL mapped to PLAINTEXT" in hits[0].observation


def test_interbroker_plaintext_does_not_fire_when_named_listener_is_ssl():
    """REGRESSION: security.inter.broker.protocol ALWAYS returns its PLAINTEXT default, even
    when inter.broker.listener.name is set and wins. Reading it first false-positives on a
    correctly-secured cluster."""
    cfg = config({"inter.broker.listener.name": "INTERNAL",
                  "listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SSL"})
    assert cfg["security.inter.broker.protocol"]["value"] == "PLAINTEXT"   # still there, still lying
    b, ctx = fixture_scan(cfg)
    assert fire("KAFKA.INTERBROKER.PLAINTEXT", b, ctx) == []


def test_interbroker_falls_back_to_security_inter_broker_protocol_when_no_listener_name():
    b, ctx = fixture_scan(config({"inter.broker.listener.name": DELETE,
                                  "security.inter.broker.protocol": "SSL"}))
    assert fire("KAFKA.INTERBROKER.PLAINTEXT", b, ctx) == []

    b, ctx = fixture_scan(config({"inter.broker.listener.name": DELETE}))
    hits = fire("KAFKA.INTERBROKER.PLAINTEXT", b, ctx)
    assert len(hits) == 1
    assert "security.inter.broker.protocol=PLAINTEXT" in hits[0].observation


# ═══ KAFKA.AUTHZ.NO_AUTHORIZER ════════════════════════════════════════════
def test_no_authorizer_fires_critical_on_fixture():
    b, ctx = fixture_scan()
    hits = fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "critical"
    assert "authorizer.class.name is the empty string" in hits[0].observation
    assert "is_default=True" in hits[0].observation
    assert "source=DEFAULT_CONFIG" in hits[0].observation     # int 5 resolved via the fallback map
    assert "INTERNAL (PLAINTEXT)" in hits[0].observation


def test_no_authorizer_does_not_fire_when_an_authorizer_is_set():
    b, ctx = fixture_scan(config({
        "authorizer.class.name": entry("org.apache.kafka.metadata.authorizer.StandardAuthorizer")}))
    assert fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx) == []


def test_no_authorizer_does_not_fire_for_any_non_apache_authorizer_class():
    for klass in ("org.apache.ranger.authorization.kafka.authorizer.RangerKafkaAuthorizer",
                  "io.confluent.kafka.security.authorizer.ConfluentServerAuthorizer"):
        b, ctx = fixture_scan(config({"authorizer.class.name": entry(klass)}))
        assert fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx) == [], klass


def test_no_authorizer_is_suppressed_by_contradicting_acl_evidence():
    """A managed platform enforcing authz outside the Kafka config returns REAL ACLs. That
    contradiction — not a missing SecurityDisabledException — is the false-positive gate."""
    b, ctx = fixture_scan(bindings=[acl(principal="User:app", operation="READ")])
    assert fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx) == []


def test_no_authorizer_is_indeterminate_when_acls_could_not_be_read():
    b, ctx = fixture_scan(outcome="error")
    assert fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx) == []


def test_no_authorizer_states_that_an_empty_acl_list_proves_nothing():
    """The real broker returns [] with no authorizer, so the evidence must not overclaim."""
    b, ctx = fixture_scan()
    assert "distinguishes nothing" in fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx)[0].observation


def test_no_authorizer_cites_the_exception_when_the_broker_does_raise():
    b, ctx = fixture_scan(outcome="security_disabled")
    hits = fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx)
    assert "SecurityDisabledException" in hits[0].observation


def test_no_authorizer_is_high_not_critical_without_an_anonymous_listener():
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SSL",
        "ssl.client.auth": entry("required")}))
    assert fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx)[0].severity == "high"


# ═══ KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL ═════════════════════════════════
AUTHZ_SET = {"authorizer.class.name":
             entry("org.apache.kafka.metadata.authorizer.StandardAuthorizer")}


def test_allow_everyone_fires_when_the_value_is_readable_and_true():
    b, ctx = fixture_scan(config({**AUTHZ_SET,
                                  "allow.everyone.if.no.acl.found": entry("true")}))
    hits = fire("KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "critical"   # PLAINTEXT listeners -> ANONYMOUS
    assert "allow.everyone.if.no.acl.found='true'" in hits[0].observation


def test_allow_everyone_parses_boolean_the_way_the_broker_does():
    """The broker uses Boolean.parseBoolean(value.trim()); a literal == "true" is a false negative."""
    for raw in ("TRUE", " true ", "True"):
        b, ctx = fixture_scan(config({**AUTHZ_SET,
                                      "allow.everyone.if.no.acl.found": entry(raw)}))
        assert len(fire("KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", b, ctx)) == 1, raw


def test_allow_everyone_does_not_fire_when_readable_and_false():
    b, ctx = fixture_scan(config({**AUTHZ_SET,
                                  "allow.everyone.if.no.acl.found": entry("false")}))
    assert fire("KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", b, ctx) == []


def test_allow_everyone_reports_redacted_explicit_override_without_claiming_the_value():
    """is_sensitive=true redacts the value, so is_default=false proves only that it was SET."""
    b, ctx = fixture_scan(config({**AUTHZ_SET}))   # fixture entry: sensitive, null, is_default=false
    hits = fire("KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "medium"
    obs = hits[0].observation
    assert "is_sensitive=true" in obs and "redacts its value to null" in obs
    assert "is_default=false" in obs
    assert "cannot tell which" in obs        # never asserts the value is true


def test_allow_everyone_does_not_fire_when_redacted_but_left_at_default():
    b, ctx = fixture_scan(config({
        **AUTHZ_SET,
        "allow.everyone.if.no.acl.found": entry(None, source=5, is_default=True,
                                                is_sensitive=True)}))
    assert fire("KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", b, ctx) == []


def test_allow_everyone_does_not_fire_when_the_key_is_absent():
    b, ctx = fixture_scan(config({**AUTHZ_SET, "allow.everyone.if.no.acl.found": DELETE}))
    assert fire("KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", b, ctx) == []


def test_allow_everyone_counts_uncovered_topics_as_blast_radius():
    b = broker(config({**AUTHZ_SET, "allow.everyone.if.no.acl.found": entry("true")}),
               bindings=[acl(name="orders")])
    ctx = scan(b, topic("orders"), topic("payments"), topic("__consumer_offsets", internal=True))
    hits = fire("KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", b, ctx)
    assert "1 of 2 non-internal topics" in hits[0].detail


# ═══ KAFKA.ACL.WILDCARD_PRINCIPAL ═════════════════════════════════════════
def test_acl_wildcard_principal_fires_and_quotes_the_binding():
    b, ctx = fixture_scan(bindings=[acl(principal="User:*", operation="WRITE", name="payments")])
    hits = fire("KAFKA.ACL.WILDCARD_PRINCIPAL", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "high"
    assert "User:*" in hits[0].observation and "'payments'" in hits[0].observation


def test_acl_wildcard_principal_is_critical_for_cluster_wide_all():
    b, ctx = fixture_scan(bindings=[acl(principal="User:*", operation="ALL", restype="BROKER",
                                        name="kafka-cluster")])
    assert fire("KAFKA.ACL.WILDCARD_PRINCIPAL", b, ctx)[0].severity == "critical"


def test_acl_wildcard_principal_is_low_for_describe_only():
    b, ctx = fixture_scan(bindings=[acl(principal="User:*", operation="DESCRIBE")])
    assert fire("KAFKA.ACL.WILDCARD_PRINCIPAL", b, ctx)[0].severity == "low"


def test_acl_wildcard_principal_does_not_fire_for_named_principals():
    b, ctx = fixture_scan(bindings=[acl(principal="User:svc-a", operation="ALL", name="*")])
    assert fire("KAFKA.ACL.WILDCARD_PRINCIPAL", b, ctx) == []


def test_acl_wildcard_principal_is_case_sensitive():
    """PrincipalType is case-sensitive: `user:*` is a different principal, not a match."""
    b, ctx = fixture_scan(bindings=[acl(principal="user:*", operation="ALL")])
    assert fire("KAFKA.ACL.WILDCARD_PRINCIPAL", b, ctx) == []


def test_acl_wildcard_principal_ignores_deny_bindings_as_the_trigger():
    b, ctx = fixture_scan(bindings=[acl(principal="User:*", operation="ALL",
                                        permission_type="DENY")])
    assert fire("KAFKA.ACL.WILDCARD_PRINCIPAL", b, ctx) == []


def test_acl_wildcard_principal_downgraded_by_an_overriding_deny():
    b, ctx = fixture_scan(bindings=[
        acl(principal="User:*", operation="WRITE", name="payments"),
        acl(principal="User:*", operation="WRITE", name="payments", permission_type="DENY")])
    hits = fire("KAFKA.ACL.WILDCARD_PRINCIPAL", b, ctx)
    assert hits[0].severity == "medium"   # high, downgraded one tier
    assert "An overriding DENY exists" in hits[0].observation


def test_acl_rules_only_fire_on_the_cluster_scoped_broker():
    """ACLs are one cluster-wide fact; without a single owner an N-broker cluster raises N
    identical findings."""
    b, ctx = fixture_scan(bindings=[acl(principal="User:*", operation="ALL")],
                          cluster_scope=False)
    for rid in ("KAFKA.ACL.WILDCARD_PRINCIPAL", "KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS",
                "KAFKA.ACL.ANONYMOUS_PRINCIPAL", "KAFKA.ACL.PREFIXED_OVERBROAD"):
        assert fire(rid, b, ctx) == [], rid


def test_acl_rules_do_not_fire_when_acls_were_unreadable():
    b, ctx = fixture_scan(outcome="error")
    for rid in ("KAFKA.ACL.WILDCARD_PRINCIPAL", "KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS",
                "KAFKA.ACL.ANONYMOUS_PRINCIPAL", "KAFKA.ACL.PREFIXED_OVERBROAD"):
        assert fire(rid, b, ctx) == [], rid


# ═══ KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS ═══════════════════════════
def test_acl_wildcard_resource_all_fires_on_literal_star():
    b, ctx = fixture_scan(bindings=[acl(principal="User:app", operation="ALL", name="*")])
    hits = fire("KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "critical"
    assert "TOPIC:LITERAL:'*'" in hits[0].observation and "User:app" in hits[0].observation


def test_acl_wildcard_resource_all_fires_on_the_cluster_resource_by_name():
    """The cluster ACL is written LITERAL 'kafka-cluster', not '*' — a name=='*' test misses it.
    confluent's ResourceType has no CLUSTER member, so it arrives as restype BROKER."""
    b, ctx = fixture_scan(bindings=[acl(principal="User:app", operation="ALL", restype="BROKER",
                                        name="kafka-cluster")])
    hits = fire("KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "critical"
    assert "kafka-cluster" in hits[0].observation


def test_acl_wildcard_resource_all_does_not_fire_on_a_scoped_binding():
    b, ctx = fixture_scan(bindings=[acl(principal="User:app", operation="READ", name="orders")])
    assert fire("KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS", b, ctx) == []


def test_acl_wildcard_resource_all_is_info_for_a_super_user():
    """A super user bypasses ACL evaluation, so the binding grants nothing — cleanup, not risk."""
    b, ctx = fixture_scan(config({"super.users": "User:admin;User:CN=broker,OU=eng,O=acme"}),
                          bindings=[acl(principal="User:admin", operation="ALL", name="*")])
    hits = fire("KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS", b, ctx)
    assert hits[0].severity == "info"
    assert "also listed in super.users" in hits[0].observation


def test_super_users_splits_on_semicolon_not_comma():
    """A TLS distinguished name contains commas; splitting on comma shreds it."""
    b, ctx = fixture_scan(config({"super.users": "User:admin;User:CN=broker,OU=eng,O=acme"}),
                          bindings=[acl(principal="User:CN=broker,OU=eng,O=acme",
                                        operation="ALL", name="*")])
    assert fire("KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS", b, ctx)[0].severity == "info"


# ═══ KAFKA.ACL.ANONYMOUS_PRINCIPAL ════════════════════════════════════════
def test_acl_anonymous_principal_fires_critical_with_a_plaintext_listener():
    b, ctx = fixture_scan(bindings=[acl(principal="User:ANONYMOUS", operation="READ")])
    hits = fire("KAFKA.ACL.ANONYMOUS_PRINCIPAL", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "critical"
    assert "User:ANONYMOUS" in hits[0].observation
    assert "broker 1 listener EXTERNAL (PLAINTEXT)" in hits[0].observation


def test_acl_anonymous_principal_is_latent_medium_without_an_anonymous_listener():
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SSL",
        "ssl.client.auth": entry("required")}),
        bindings=[acl(principal="User:ANONYMOUS", operation="READ")])
    hits = fire("KAFKA.ACL.ANONYMOUS_PRINCIPAL", b, ctx)
    assert hits[0].severity == "medium" and "latent" in hits[0].observation


def test_acl_anonymous_principal_is_low_when_host_scoped():
    """The documented PLAINTEXT inter-broker migration pattern — not reachable by arbitrary clients."""
    b, ctx = fixture_scan(bindings=[acl(principal="User:ANONYMOUS", operation="ALL",
                                        host="10.0.0.7")])
    hits = fire("KAFKA.ACL.ANONYMOUS_PRINCIPAL", b, ctx)
    assert hits[0].severity == "low" and "10.0.0.7" in hits[0].observation


def test_acl_anonymous_principal_does_not_fire_without_an_anonymous_binding():
    b, ctx = fixture_scan(bindings=[acl(principal="User:svc", operation="ALL", name="*")])
    assert fire("KAFKA.ACL.ANONYMOUS_PRINCIPAL", b, ctx) == []


# ═══ KAFKA.ACL.PREFIXED_OVERBROAD ═════════════════════════════════════════
def test_acl_prefixed_overbroad_fires_on_a_one_character_prefix():
    b, ctx = fixture_scan(bindings=[acl(principal="User:app", operation="ALL",
                                        pattern="PREFIXED", name="a")])
    hits = fire("KAFKA.ACL.PREFIXED_OVERBROAD", b, ctx)
    assert len(hits) == 1
    assert "TOPIC:PREFIXED:'a'" in hits[0].observation
    assert "1 character(s) long" in hits[0].observation


def test_acl_prefixed_overbroad_does_not_fire_on_a_scoped_namespace_prefix():
    """PREFIXED is the documented namespace-grant mechanism, not a misconfiguration."""
    b, ctx = fixture_scan(bindings=[acl(principal="User:app", operation="READ",
                                        pattern="PREFIXED", name="payments.")])
    assert fire("KAFKA.ACL.PREFIXED_OVERBROAD", b, ctx) == []


def test_acl_prefixed_overbroad_ratio_needs_a_floor_not_just_a_percentage():
    """On a small cluster a legitimate prefix trivially exceeds 50%; the m>=20/n>=5 floors exist
    to stop that. Same prefix, two cluster sizes."""
    small = broker(bindings=[acl(principal="User:app", operation="READ",
                                 pattern="PREFIXED", name="ns-")])
    ctx = scan(small, *[topic(f"ns-{i}") for i in range(3)], topic("other"))
    assert fire("KAFKA.ACL.PREFIXED_OVERBROAD", small, ctx) == []

    big = broker(bindings=[acl(principal="User:app", operation="READ",
                               pattern="PREFIXED", name="ns-")])
    ctx = scan(big, *[topic(f"ns-{i}") for i in range(15)],
               *[topic(f"other-{i}") for i in range(10)])
    hits = fire("KAFKA.ACL.PREFIXED_OVERBROAD", big, ctx)
    assert len(hits) == 1 and "15 of 25 existing topics (60%)" in hits[0].observation


def test_acl_prefixed_overbroad_suppressed_by_an_overriding_deny():
    b, ctx = fixture_scan(bindings=[
        acl(principal="User:app", operation="READ", pattern="PREFIXED", name="a"),
        acl(principal="User:app", operation="READ", pattern="PREFIXED", name="a",
            permission_type="DENY")])
    assert fire("KAFKA.ACL.PREFIXED_OVERBROAD", b, ctx) == []


# ═══ KAFKA.SASL.PLAIN_WITHOUT_TLS ═════════════════════════════════════════
SASL_PLAIN = {"listener.security.protocol.map":
              "CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,EXTERNAL:SASL_PLAINTEXT"}


def test_sasl_plain_without_tls_fires_critical():
    b, ctx = fixture_scan(config({**SASL_PLAIN, "sasl.enabled.mechanisms": "PLAIN"}))
    hits = fire("KAFKA.SASL.PLAIN_WITHOUT_TLS", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "critical"
    assert "EXTERNAL://:9092" in hits[0].observation
    assert "which includes PLAIN" in hits[0].observation


def test_sasl_plain_without_tls_does_not_fire_over_sasl_ssl():
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SASL_SSL",
        "sasl.enabled.mechanisms": "PLAIN"}))
    assert fire("KAFKA.SASL.PLAIN_WITHOUT_TLS", b, ctx) == []


def test_sasl_plain_without_tls_does_not_fire_for_scram_only():
    b, ctx = fixture_scan(config({**SASL_PLAIN, "sasl.enabled.mechanisms": "SCRAM-SHA-512"}))
    assert fire("KAFKA.SASL.PLAIN_WITHOUT_TLS", b, ctx) == []


def test_sasl_rules_enumerate_listeners_not_the_protocol_map():
    """The DEFAULT protocol map contains a SASL_PLAINTEXT entry on every broker. Iterating the
    map instead of `listeners` fires a critical against a listener that does not exist."""
    b, ctx = fixture_scan(config({
        "listeners": "PLAINTEXT://:9092",
        "advertised.listeners": "PLAINTEXT://kafka:9092",
        "listener.security.protocol.map": DELETE,      # -> identity default map
        "inter.broker.listener.name": DELETE,
        "controller.listener.names": DELETE,
        "sasl.enabled.mechanisms": "PLAIN"}))
    assert fire("KAFKA.SASL.PLAIN_WITHOUT_TLS", b, ctx) == []
    assert fire("KAFKA.SASL.SCRAM_WITHOUT_TLS", b, ctx) == []
    assert len(fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)) == 1   # the listener that DOES exist


def test_sasl_plain_without_tls_is_low_on_loopback():
    b, ctx = fixture_scan(config({**SASL_PLAIN,
                                  "listeners": "EXTERNAL://127.0.0.1:9092,CONTROLLER://:9093",
                                  "sasl.enabled.mechanisms": "PLAIN"}))
    assert fire("KAFKA.SASL.PLAIN_WITHOUT_TLS", b, ctx)[0].severity == "low"


# ═══ KAFKA.SASL.SCRAM_WITHOUT_TLS ═════════════════════════════════════════
def test_sasl_scram_without_tls_fires_and_names_the_mechanism():
    b, ctx = fixture_scan(config({**SASL_PLAIN,
                                  "sasl.enabled.mechanisms": "SCRAM-SHA-512,PLAIN"}))
    hits = fire("KAFKA.SASL.SCRAM_WITHOUT_TLS", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "high"
    assert "SCRAM-SHA-512" in hits[0].observation
    assert "CVE-2024-56128" in hits[0].remediation   # advisory only, never asserted as observed


def test_sasl_scram_without_tls_does_not_fire_over_sasl_ssl():
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SASL_SSL",
        "sasl.enabled.mechanisms": "SCRAM-SHA-512"}))
    assert fire("KAFKA.SASL.SCRAM_WITHOUT_TLS", b, ctx) == []


def test_sasl_scram_without_tls_does_not_fire_for_gssapi_only():
    b, ctx = fixture_scan(config({**SASL_PLAIN, "sasl.enabled.mechanisms": "GSSAPI"}))
    assert fire("KAFKA.SASL.SCRAM_WITHOUT_TLS", b, ctx) == []


# ═══ KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT ═════════════════════════════════
OAUTH = {"listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SASL_SSL",
         "sasl.enabled.mechanisms": "OAUTHBEARER"}
OAUTH_KEY = "listener.name.external.oauthbearer.sasl.server.callback.handler.class"


def test_oauthbearer_unsecured_fires_when_no_handler_is_configured():
    b, ctx = fixture_scan(config(OAUTH))
    hits = fire("KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT", b, ctx)
    assert len(hits) == 1
    assert OAUTH_KEY in hits[0].observation and "is absent" in hits[0].observation
    assert "OAuthBearerUnsecuredValidatorCallbackHandler" in hits[0].observation


def test_oauthbearer_unsecured_defers_severity_to_the_decorator():
    """REGRESSION: a Hit that leaves severity None must survive the severity-normalising helper.
    The scan loop swallows detector exceptions, so a crash here silently disables the rule."""
    b, ctx = fixture_scan(config(OAUTH))
    hits = fire("KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT", b, ctx)
    assert hits[0].severity is None
    assert RULES["KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT"].severity == "high"


def test_oauthbearer_unsecured_does_not_fire_with_a_production_handler():
    b, ctx = fixture_scan(config({**OAUTH, OAUTH_KEY: entry("com.acme.OAuthValidator")}))
    assert fire("KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT", b, ctx) == []


def test_oauthbearer_unsecured_does_not_fire_when_oauthbearer_is_not_enabled():
    b, ctx = fixture_scan(config({**OAUTH, "sasl.enabled.mechanisms": "SCRAM-SHA-512"}))
    assert fire("KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT", b, ctx) == []


def test_oauthbearer_unsecured_still_fires_when_only_the_unprefixed_key_is_set():
    """SaslChannelBuilder consults ONLY the mechanism-prefixed key. Treating the bare key as a
    pass is a false negative on a genuinely broken broker — and setting the bare key is exactly
    the mistake an operator makes."""
    b, ctx = fixture_scan(config({
        **OAUTH, "sasl.server.callback.handler.class": entry("com.acme.OAuthValidator")}))
    hits = fire("KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT", b, ctx)
    assert len(hits) == 1
    assert "which the broker does not consult for this mechanism" in hits[0].observation


# ═══ KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED ═══════════════════════════════════
SSL_MAP = {"listener.security.protocol.map":
           "CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,EXTERNAL:SSL"}


def test_ssl_client_auth_not_required_fires_high_when_none():
    b, ctx = fixture_scan(config(SSL_MAP))
    hits = fire("KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "high"
    assert "ssl.client.auth=none" in hits[0].observation
    assert "User:ANONYMOUS" in hits[0].observation


def test_ssl_client_auth_not_required_does_not_fire_when_required():
    b, ctx = fixture_scan(config({**SSL_MAP, "ssl.client.auth": entry("required")}))
    assert fire("KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", b, ctx) == []


def test_ssl_client_auth_reads_the_lowercased_listener_prefix():
    """`listeners` uses UPPERCASE names but the per-listener key prefix must be lowercased. A
    case-sensitive lookup misses the override and misreports a hardened listener."""
    b, ctx = fixture_scan(config({**SSL_MAP,
                                  "listener.name.external.ssl.client.auth": entry("required")}))
    assert fire("KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", b, ctx) == []


def test_ssl_client_auth_listener_override_outranks_the_global_key():
    b, ctx = fixture_scan(config({**SSL_MAP,
                                  "ssl.client.auth": entry("required"),
                                  "listener.name.external.ssl.client.auth": entry("none")}))
    hits = fire("KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", b, ctx)
    assert len(hits) == 1
    assert "listener.name.external.ssl.client.auth" in hits[0].observation


def test_ssl_client_auth_requested_is_medium_not_high():
    b, ctx = fixture_scan(config({**SSL_MAP, "ssl.client.auth": entry("requested")}))
    hits = fire("KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", b, ctx)
    assert hits[0].severity == "medium"
    assert "ssl.client.auth=requested" in hits[0].observation


def test_ssl_client_auth_does_not_fire_on_sasl_ssl_where_sasl_authenticates():
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,"
                                          "EXTERNAL:SASL_SSL"}))
    assert fire("KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", b, ctx) == []


def test_ssl_client_auth_downgraded_when_anonymous_is_provably_denied():
    b, ctx = fixture_scan(config({
        **SSL_MAP, **AUTHZ_SET,
        "allow.everyone.if.no.acl.found": entry("false", is_sensitive=False)}),
        bindings=[acl(principal="User:app")])
    hits = fire("KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", b, ctx)
    assert hits[0].severity == "medium"   # high, downgraded one tier
    assert "provably denied" in hits[0].detail


def test_ssl_client_auth_not_downgraded_when_allow_everyone_is_redacted():
    """A redacted value cannot be assumed false, so the downgrade must not apply."""
    b, ctx = fixture_scan(config({**SSL_MAP, **AUTHZ_SET}), bindings=[acl(principal="User:app")])
    hits = fire("KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", b, ctx)
    assert hits[0].severity == "high"
    assert "not provably denied" in hits[0].detail


# ═══ KAFKA.SSL.HOSTNAME_VERIFICATION_DISABLED ═════════════════════════════
def test_ssl_hostname_verification_fires_on_explicit_empty_string():
    b, ctx = fixture_scan(config({
        "listener.security.protocol.map": "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SSL",
        "ssl.endpoint.identification.algorithm": entry("")}))
    hits = fire("KAFKA.SSL.HOSTNAME_VERIFICATION_DISABLED", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "medium"
    assert "set to the empty string" in hits[0].observation
    assert "effective inter-broker protocol is SSL" in hits[0].observation


def test_ssl_hostname_verification_does_not_fire_on_the_fixture_default():
    """Absent or 'https' means verification is on. Only an explicit empty string disables it."""
    assert _FIXTURE["config"]["ssl.endpoint.identification.algorithm"]["value"] == "https"
    b, ctx = fixture_scan()
    assert fire("KAFKA.SSL.HOSTNAME_VERIFICATION_DISABLED", b, ctx) == []


def test_ssl_hostname_verification_does_not_fire_when_the_key_is_absent():
    b, ctx = fixture_scan(config({"ssl.endpoint.identification.algorithm": DELETE}))
    assert fire("KAFKA.SSL.HOSTNAME_VERIFICATION_DISABLED", b, ctx) == []


def test_ssl_hostname_verification_is_low_when_no_outbound_tls_exists():
    """The setting applies to client-mode SSL engines only. With PLAINTEXT inter-broker it is an
    inert leftover, not a live MITM exposure."""
    b, ctx = fixture_scan(config({"ssl.endpoint.identification.algorithm": entry("")}))
    hits = fire("KAFKA.SSL.HOSTNAME_VERIFICATION_DISABLED", b, ctx)
    assert hits[0].severity == "low" and "inert leftover" in hits[0].detail


# ═══ KAFKA.TOPIC.AUTO_CREATE_ENABLED ══════════════════════════════════════
def test_auto_create_fires_high_on_fixture_because_authz_is_absent():
    b, ctx = fixture_scan()
    hits = fire("KAFKA.TOPIC.AUTO_CREATE_ENABLED", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "high"
    assert "auto.create.topics.enable='true'" in hits[0].observation
    assert "num.partitions='1'" in hits[0].observation
    assert "default.replication.factor='1'" in hits[0].observation


def test_auto_create_does_not_fire_when_false():
    b, ctx = fixture_scan(config({"auto.create.topics.enable": "false"}))
    assert fire("KAFKA.TOPIC.AUTO_CREATE_ENABLED", b, ctx) == []


def test_auto_create_does_not_fire_when_the_key_is_absent():
    """A managed platform that restricts DescribeConfigs on BROKER leaves this unknown, not failed."""
    b, ctx = fixture_scan(config({"auto.create.topics.enable": DELETE}))
    assert fire("KAFKA.TOPIC.AUTO_CREATE_ENABLED", b, ctx) == []


def test_auto_create_is_only_low_when_an_authorizer_enforces_create():
    """Standalone this crosses no security boundary — the auto-create path is authz-checked.

    The fixture's allow.everyone.if.no.acl.found is the shape the REAL broker returns: typed
    PASSWORD, so `value` is redacted to None with is_default=false. The escalation gate must not
    read that None as `false` and then TELL THE CUSTOMER no boundary is crossed — that is a pass
    claim resting on a value the broker demonstrably does not return. Not escalating is right
    (escalating on an unknown would be a false positive); claiming the all-clear is not.
    """
    b, ctx = fixture_scan(config(AUTHZ_SET))
    hits = fire("KAFKA.TOPIC.AUTO_CREATE_ENABLED", b, ctx)
    assert hits[0].severity == "low" and "Not escalated" in hits[0].detail
    assert "NOT established by this scan" in hits[0].detail
    assert "no security boundary is crossed" not in hits[0].detail


def test_auto_create_claims_no_boundary_crossed_only_when_allow_everyone_is_READABLE():
    """The clean bill of health is legitimate here and must survive: the value was actually read.
    Without this the fix could degenerate into caveating every scan."""
    b, ctx = fixture_scan(config({**AUTHZ_SET,
                                  "allow.everyone.if.no.acl.found": entry("false")}))
    hits = fire("KAFKA.TOPIC.AUTO_CREATE_ENABLED", b, ctx)
    assert hits[0].severity == "low"
    assert "no security boundary is crossed" in hits[0].detail
    assert "NOT established by this scan" not in hits[0].detail


def test_auto_create_escalates_when_allow_everyone_is_readably_true():
    b, ctx = fixture_scan(config({**AUTHZ_SET,
                                  "allow.everyone.if.no.acl.found": entry("true")}))
    hits = fire("KAFKA.TOPIC.AUTO_CREATE_ENABLED", b, ctx)
    assert hits[0].severity == "high" and "Escalated to high" in hits[0].detail


def test_auto_create_does_not_caveat_a_redacted_but_DEFAULT_allow_everyone():
    """is_default=true means the value is the shipped `false` and was never touched — redacted or
    not, that is knowledge, not a gap. Caveating it would be noise on every hardened cluster."""
    b, ctx = fixture_scan(hardened_config({"auto.create.topics.enable": "true",
                                           **AUTHZ_SET}))
    hits = fire("KAFKA.TOPIC.AUTO_CREATE_ENABLED", b, ctx)
    assert hits[0].severity == "low"
    assert "no security boundary is crossed" in hits[0].detail
    assert "NOT established by this scan" not in hits[0].detail


# ═══ KAFKA.TOPIC.RETENTION_UNBOUNDED ══════════════════════════════════════
def unbounded_topic_config(**over) -> dict:
    cfg = {"cleanup.policy": entry("delete", source=5, is_default=True),
           "retention.ms": entry("-1"),
           "retention.bytes": entry("-1", source=5, is_default=True)}
    cfg.update(over)
    return cfg


def test_retention_unbounded_fires_with_the_observed_values():
    t = topic("customer-pii", cfg=unbounded_topic_config())
    hits = fire("KAFKA.TOPIC.RETENTION_UNBOUNDED", t)
    assert len(hits) == 1 and (hits[0].severity or "low") == "low"
    assert "retention.ms=-1" in hits[0].observation
    assert "retention.bytes=-1" in hits[0].observation
    assert "cleanup.policy='delete'" in hits[0].observation


def test_retention_unbounded_does_not_fire_when_bounded_by_size():
    """retention.ms=-1 with retention.bytes>0 is BOUNDED — segments age out by size, so the
    'indefinitely' claim would simply be false."""
    t = topic("orders", cfg=unbounded_topic_config(retention_bytes=None,
                                                   **{"retention.bytes": entry("536870912")}))
    assert fire("KAFKA.TOPIC.RETENTION_UNBOUNDED", t) == []


def test_retention_unbounded_does_not_fire_when_bounded_by_time():
    t = topic("orders", cfg=unbounded_topic_config(**{"retention.ms": entry("604800000")}))
    assert fire("KAFKA.TOPIC.RETENTION_UNBOUNDED", t) == []


def test_retention_unbounded_does_not_fire_on_a_compacted_topic():
    """Compaction retains the latest value per key by design — a different question entirely."""
    t = topic("orders", cfg=unbounded_topic_config(
        **{"cleanup.policy": entry("compact")}))
    assert fire("KAFKA.TOPIC.RETENTION_UNBOUNDED", t) == []


def test_retention_unbounded_does_not_fire_when_topic_config_is_unreadable():
    assert fire("KAFKA.TOPIC.RETENTION_UNBOUNDED", topic("orders", cfg={})) == []


def test_retention_unbounded_is_info_with_tiered_storage():
    t = topic("orders", cfg=unbounded_topic_config(
        **{"remote.storage.enable": entry("true"),
           "local.retention.ms": entry("86400000")}))
    hits = fire("KAFKA.TOPIC.RETENTION_UNBOUNDED", t)
    assert hits[0].severity == "info"
    assert "intended infinite-retention architecture" in hits[0].observation


# ═══ KAFKA.DURABILITY.MIN_INSYNC_REPLICAS_ONE ═════════════════════════════
def test_min_insync_replicas_one_fires_on_a_replicated_topic():
    t = topic("payments", cfg={"min.insync.replicas": entry("1")}, rf=3)
    hits = fire("KAFKA.DURABILITY.MIN_INSYNC_REPLICAS_ONE", t)
    assert len(hits) == 1 and hits[0].severity == "medium"
    assert "replication.factor=3" in hits[0].observation
    assert "min.insync.replicas=1" in hits[0].observation


def test_min_insync_replicas_one_does_not_fire_when_set_to_two():
    t = topic("payments", cfg={"min.insync.replicas": entry("2")}, rf=3)
    assert fire("KAFKA.DURABILITY.MIN_INSYNC_REPLICAS_ONE", t) == []


def test_min_insync_replicas_one_does_not_fire_on_an_unreplicated_topic():
    """With RF=1 there is nothing to be in sync with; the setting has no durability effect."""
    t = topic("payments", cfg={"min.insync.replicas": entry("1")}, rf=1)
    assert fire("KAFKA.DURABILITY.MIN_INSYNC_REPLICAS_ONE", t) == []


def test_min_insync_replicas_one_does_not_fire_when_replication_factor_is_unknown():
    t = topic("payments", cfg={"min.insync.replicas": entry("1")}, rf=None)
    assert fire("KAFKA.DURABILITY.MIN_INSYNC_REPLICAS_ONE", t) == []


def test_min_insync_replicas_one_is_low_on_an_internal_topic():
    t = topic("__consumer_offsets", cfg={"min.insync.replicas": entry("1")}, rf=3, internal=True)
    assert fire("KAFKA.DURABILITY.MIN_INSYNC_REPLICAS_ONE", t)[0].severity == "low"


# ═══ KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION ═════════════════════════════
UNCLEAN = "unclean.leader.election.enable"


def test_unclean_leader_election_fires_on_fixture_broker():
    b, ctx = fixture_scan()
    hits = fire("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", b, ctx)
    assert len(hits) == 1 and (hits[0].severity or "medium") == "medium"
    assert f"{UNCLEAN}='true'" in hits[0].observation
    assert "process.roles='broker,controller'" in hits[0].observation   # why static is authoritative


def test_unclean_leader_election_does_not_fire_when_false():
    b, ctx = fixture_scan(config({UNCLEAN: "false"}))
    assert fire("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", b, ctx) == []


def test_unclean_leader_election_does_not_fire_when_absent():
    b, ctx = fixture_scan(config({UNCLEAN: DELETE}))
    assert fire("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", b, ctx) == []


def test_unclean_leader_election_prefers_the_cluster_dynamic_config():
    """KRaft resolves this cluster-wide; the empty-resource-name snapshot is authoritative."""
    b = broker(config({UNCLEAN: "false"}),
               cluster_dynamic={UNCLEAN: entry("true", source=2)})
    ctx = scan(b, topic("orders", rf=3))
    hits = fire("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", b, ctx)
    assert len(hits) == 1
    assert "cluster-wide dynamic config" in hits[0].observation


def test_unclean_leader_election_is_info_on_a_broker_only_kraft_node():
    """KRaft never consults a BROKER's static config for this key, so the value may be inert —
    the dominant false-positive path for this rule."""
    b = broker(config({"process.roles": "broker"}), cluster_dynamic={})
    ctx = scan(b, topic("orders", rf=3))
    hits = fire("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "info"
    assert "may be inert" in hits[0].observation
    assert "does not set it" in hits[0].observation


def test_unclean_leader_election_suppressed_when_no_topic_is_replicated():
    """With RF=1 everywhere there is no out-of-sync replica to promote."""
    b = broker()
    ctx = scan(b, topic("orders", rf=1), topic("payments", rf=1))
    assert fire("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", b, ctx) == []


def test_unclean_leader_election_fires_on_a_topic_override():
    t = topic("orders", cfg={UNCLEAN: entry("true")}, rf=3)
    hits = fire("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", t)
    assert len(hits) == 1
    assert f"Topic orders: {UNCLEAN}='true'" in hits[0].observation


def test_unclean_leader_election_does_not_fire_on_a_topic_inheriting_the_default():
    t = topic("orders", cfg={UNCLEAN: entry("false", source=5, is_default=True)}, rf=3)
    assert fire("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", t) == []


def test_unclean_leader_election_does_not_fire_on_an_unreplicated_topic():
    t = topic("orders", cfg={UNCLEAN: entry("true")}, rf=1)
    assert fire("KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION", t) == []


# ═══ KAFKA.ZK.LEGACY_MODE_* ═══════════════════════════════════════════════
def zk_config(**over) -> dict:
    base = {"process.roles": DELETE,
            "zookeeper.connect": entry("zk-0:2181,zk-1:2181"),
            "zookeeper.set.acl": entry("false", source=5, is_default=True),
            "zookeeper.ssl.client.enable": entry("false", source=5, is_default=True)}
    base.update(over)
    return config(base)


def test_zk_unsecured_znodes_fires_and_quotes_the_connect_string():
    b, ctx = fixture_scan(zk_config())
    hits = fire("KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES", b, ctx)
    assert len(hits) == 1 and (hits[0].severity or "medium") == "medium"
    assert "zk-0:2181,zk-1:2181" in hits[0].observation
    assert "zookeeper.set.acl='false'" in hits[0].observation


def test_zk_plaintext_client_fires_and_quotes_the_connect_string():
    b, ctx = fixture_scan(zk_config())
    hits = fire("KAFKA.ZK.LEGACY_MODE_PLAINTEXT_ZK", b, ctx)
    assert len(hits) == 1
    assert "zk-0:2181,zk-1:2181" in hits[0].observation
    assert "zookeeper.ssl.client.enable='false'" in hits[0].observation


def test_zk_rules_do_not_fire_on_a_kraft_cluster():
    """The fixture is KRaft: zookeeper.connect is still RETURNED, with a null value. A
    key-existence test fires on every 3.x KRaft broker."""
    assert "zookeeper.connect" in _FIXTURE["config"]
    assert _FIXTURE["config"]["zookeeper.connect"]["value"] is None
    b, ctx = fixture_scan()
    assert fire("KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES", b, ctx) == []
    assert fire("KAFKA.ZK.LEGACY_MODE_PLAINTEXT_ZK", b, ctx) == []


def test_zk_unsecured_znodes_does_not_fire_when_acls_are_set():
    b, ctx = fixture_scan(zk_config(**{"zookeeper.set.acl": entry("true")}))
    assert fire("KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES", b, ctx) == []


def test_zk_plaintext_client_does_not_fire_when_zk_tls_is_on():
    b, ctx = fixture_scan(zk_config(**{"zookeeper.ssl.client.enable": entry("true")}))
    assert fire("KAFKA.ZK.LEGACY_MODE_PLAINTEXT_ZK", b, ctx) == []


def test_zk_unsecured_znodes_notes_the_migration_cve_only_when_migrating():
    b, ctx = fixture_scan(zk_config(
        **{"zookeeper.metadata.migration.enable": entry("true")}))
    hits = fire("KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES", b, ctx)
    assert "mid-migration to KRaft" in hits[0].observation
    assert "CVE-2024-27309" in hits[0].remediation

    b, ctx = fixture_scan(zk_config())
    hits = fire("KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES", b, ctx)
    assert "stale legacy ZooKeeper mode" in hits[0].observation
    assert "CVE-2024-27309" not in hits[0].remediation


def test_zk_arms_are_independent_rules_with_distinct_evidence():
    """Split so the TLS arm cannot emit the znode-ACL arm's evidence, and vice versa."""
    b, ctx = fixture_scan(zk_config(**{"zookeeper.set.acl": entry("true")}))
    assert fire("KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES", b, ctx) == []
    assert len(fire("KAFKA.ZK.LEGACY_MODE_PLAINTEXT_ZK", b, ctx)) == 1


# ═══ severity normalisation ═══════════════════════════════════════════════
def test_multiple_hits_on_one_resource_collapse_to_the_worst_severity():
    """Findings are fingerprinted on (rule, resource), so N Hits collapse into ONE row whose
    severity is whichever was written last. The group must be normalised or the recorded
    severity depends on iteration order."""
    b, ctx = fixture_scan(config({
        "listeners": "A://127.0.0.1:9092,B://:9093,CONTROLLER://:9094",
        "advertised.listeners": "A://127.0.0.1:9092,B://8.8.8.8:9093",
        "inter.broker.listener.name": "B",
        "listener.security.protocol.map": "CONTROLLER:PLAINTEXT,A:PLAINTEXT,B:PLAINTEXT"}))
    hits = fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)
    assert len(hits) == 2
    # On its own A is low (loopback-bound) and B is critical (advertised on a routable IP).
    # Both must be recorded critical, since the two Hits collapse into one finding row.
    assert {h.severity for h in hits} == {"critical"}
    assert {h.source_ref["listener"] for h in hits} == {"A", "B"}


# ═══ Listener-name case normalisation ═════════════════════════════════════
# The broker puts EVERY listener name through ListenerName.normalised() =
# toUpperCase(Locale.ROOT) — the entries of `listeners`, the keys of
# `listener.security.protocol.map`, `controller.listener.names` and `inter.broker.listener.name`.
# Case is therefore never significant on a real broker, and each config below is one a real
# broker accepts and boots with. A case-sensitive compare in the pack fails OPEN (the listener
# vanishes from every transport rule) or mis-scopes a listener into the wrong rule. Every fixture
# in this file writes listener names in uppercase consistently, which is exactly why these
# regressions could hide.
CASE_ONLY = {"listeners": "External://0.0.0.0:9092",
             "listener.security.protocol.map": "EXTERNAL:PLAINTEXT",
             "advertised.listeners": DELETE,
             "controller.listener.names": DELETE,
             "inter.broker.listener.name": DELETE}


def test_plaintext_listener_is_found_when_listeners_case_differs_from_the_protocol_map():
    """`listeners=External://` + `listener.security.protocol.map=EXTERNAL:PLAINTEXT` is a legal
    broker config resolving to PLAINTEXT. A case-sensitive map lookup returns None and the
    listener silently disappears from the rule — an open, unauthenticated listener scanned clean.
    """
    b, ctx = fixture_scan(config(CASE_ONLY))
    hits = fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)
    assert [h.source_ref["listener"] for h in hits] == ["External"]


def test_a_listener_named_ssl_but_remapped_to_plaintext_is_reported_as_plaintext():
    """The inverse, and worse: a case-sensitive map lookup misses `ssl:PLAINTEXT` and falls back
    to the exact name-test _resolve's docstring forbids, so the listener resolves to 'SSL'. That
    does not merely miss the PLAINTEXT listener — it writes an affirmatively FALSE claim into the
    append-only ledger via SSL.CLIENT_AUTH_NOT_REQUIRED ("TLS provides encryption only") about a
    listener with no encryption at all.
    """
    cfg = config({"listeners": "SSL://10.0.0.5:9093",
                  "listener.security.protocol.map": "ssl:PLAINTEXT",
                  "advertised.listeners": DELETE,
                  "controller.listener.names": DELETE,
                  "inter.broker.listener.name": DELETE})
    b, ctx = fixture_scan(cfg)
    assert [h.source_ref["listener"] for h in fire("KAFKA.LISTENER.PLAINTEXT", b, ctx)] == ["SSL"]
    assert fire("KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", b, ctx) == []


def test_no_authorizer_escalates_to_critical_on_a_case_mismatched_plaintext_listener():
    """_anonymous_listeners must see the same listener the transport rules do, or an open
    PLAINTEXT listener silently de-escalates NO_AUTHORIZER from critical back to high."""
    b, ctx = fixture_scan(config(CASE_ONLY))
    hits = fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx)
    assert sev(hits, "KAFKA.AUTHZ.NO_AUTHORIZER") == ["critical"]
    assert "External (PLAINTEXT)" in hits[0].observation


def test_a_lowercase_controller_listener_is_not_reported_as_a_client_listener():
    """`controller.listener.names=CONTROLLER` matches `listeners=controller://` on the broker.
    A case-sensitive membership test classifies the controller listener as client-facing: it
    fabricates a User:ANONYMOUS client listener in the ledger, escalates NO_AUTHORIZER to
    critical on that phantom, and tells the operator to remap a KRaft controller listener to
    SASL_SSL — a remediation that risks the quorum.
    """
    cfg = config({"listeners": "controller://:9093,INTERNAL://10.0.0.5:9092",
                  "listener.security.protocol.map": "controller:PLAINTEXT,INTERNAL:SASL_SSL",
                  "controller.listener.names": "CONTROLLER",
                  "advertised.listeners": DELETE,
                  "inter.broker.listener.name": DELETE})
    b, ctx = fixture_scan(cfg)
    assert fire("KAFKA.LISTENER.PLAINTEXT", b, ctx) == []
    hits = fire("KAFKA.AUTHZ.NO_AUTHORIZER", b, ctx)
    assert sev(hits, "KAFKA.AUTHZ.NO_AUTHORIZER") == ["high"]   # not escalated by a phantom
    assert "controller" not in hits[0].observation


def test_interbroker_plaintext_is_found_when_the_inter_broker_name_case_differs():
    """inter.broker.listener.name is normalised by the broker too; a case-sensitive _resolve
    returns None and the rule returns [] on genuinely unencrypted replication traffic."""
    cfg = config({"listeners": "INTERNAL://10.0.0.5:9092",
                  "listener.security.protocol.map": "INTERNAL:PLAINTEXT",
                  "inter.broker.listener.name": "internal",
                  "advertised.listeners": DELETE,
                  "controller.listener.names": DELETE})
    b, ctx = fixture_scan(cfg)
    hits = fire("KAFKA.INTERBROKER.PLAINTEXT", b, ctx)
    assert len(hits) == 1 and "internal mapped to PLAINTEXT" in hits[0].observation


def test_advertised_listeners_matches_the_listener_regardless_of_case():
    """`advertised.listeners` is an independent operator-written string. Keyed case-sensitively,
    a routable advertised host is not found and a publicly-advertised PLAINTEXT listener is filed
    high instead of critical."""
    cfg = config({"listeners": "EXTERNAL://0.0.0.0:9092",
                  "listener.security.protocol.map": "EXTERNAL:PLAINTEXT",
                  "advertised.listeners": "external://93.184.216.34:9092",
                  "controller.listener.names": DELETE,
                  "inter.broker.listener.name": DELETE,
                  **AUTHZ_SET})
    b, ctx = fixture_scan(cfg)
    assert sev(fire("KAFKA.LISTENER.PLAINTEXT", b, ctx), "KAFKA.LISTENER.PLAINTEXT") == ["critical"]


# ═══ KAFKA.AUTHZ.SUPER_USERS_BREADTH ══════════════════════════════════════
def test_super_users_breadth_silent_when_absent():
    """super.users is absent from a stock describe_configs response — the rule must stay silent,
    never KeyError."""
    b, ctx = fixture_scan()
    assert fire("KAFKA.AUTHZ.SUPER_USERS_BREADTH", b, ctx) == []


def test_super_users_breadth_low_for_a_small_operator_list():
    b, ctx = fixture_scan(config({"super.users": "User:admin;User:broker"}))
    hits = fire("KAFKA.AUTHZ.SUPER_USERS_BREADTH", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "low"
    assert "2 principal(s)" in hits[0].observation


def test_super_users_breadth_medium_above_five():
    many = ";".join(f"User:svc{i}" for i in range(6))
    b, ctx = fixture_scan(config({"super.users": many}))
    hits = fire("KAFKA.AUTHZ.SUPER_USERS_BREADTH", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "medium"


def test_super_users_breadth_critical_for_wildcard_principal():
    b, ctx = fixture_scan(config({"super.users": "User:admin;User:*"}))
    hits = fire("KAFKA.AUTHZ.SUPER_USERS_BREADTH", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "critical"
    assert "User:*" in hits[0].observation


def test_super_users_breadth_critical_for_anonymous_names_listeners():
    """ANONYMOUS in super.users + the fixture's PLAINTEXT listeners = unauthenticated god mode."""
    b, ctx = fixture_scan(config({"super.users": "User:ANONYMOUS"}))
    hits = fire("KAFKA.AUTHZ.SUPER_USERS_BREADTH", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "critical"
    assert "User:ANONYMOUS" in hits[0].observation
    assert "INTERNAL" in hits[0].observation or "EXTERNAL" in hits[0].observation


def test_super_users_splits_on_semicolon_in_breadth_rule():
    """A DN with commas is ONE principal — semicolon is the delimiter, so this is 2 not 3."""
    b, ctx = fixture_scan(config({"super.users": "User:admin;User:CN=broker,OU=eng,O=acme"}))
    hits = fire("KAFKA.AUTHZ.SUPER_USERS_BREADTH", b, ctx)
    assert len(hits) == 1 and "2 principal(s)" in hits[0].observation


# ═══ KAFKA.DELEGATION_TOKEN.INSECURE_TRANSPORT ════════════════════════════
_TOKEN_ENABLED = {"delegation.token.master.key":
                  entry(None, source=4, is_default=False, is_sensitive=True)}


def test_delegation_token_silent_when_at_default():
    """The fixture's master key is is_default=true (feature off) — no finding."""
    b, ctx = fixture_scan()
    assert fire("KAFKA.DELEGATION_TOKEN.INSECURE_TRANSPORT", b, ctx) == []


def test_delegation_token_fires_high_with_a_plaintext_listener():
    b, ctx = fixture_scan(config(_TOKEN_ENABLED))
    hits = fire("KAFKA.DELEGATION_TOKEN.INSECURE_TRANSPORT", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "high"
    assert "delegation tokens are enabled" in hits[0].observation
    assert hits[0].source_ref["config_key"] == "delegation.token.master.key"


def test_delegation_token_uses_deprecated_secret_key_alias():
    cfg = config({"delegation.token.master.key": DELETE,
                  "delegation.token.secret.key":
                      entry(None, source=4, is_default=False, is_sensitive=True)})
    b, ctx = fixture_scan(cfg)
    assert len(fire("KAFKA.DELEGATION_TOKEN.INSECURE_TRANSPORT", b, ctx)) == 1


def test_delegation_token_does_not_fire_when_all_listeners_are_tls():
    """Tokens enabled but every client listener is SSL/SASL_SSL — no interceptable transport."""
    b = broker(hardened_config(_TOKEN_ENABLED))
    ctx = scan(b, topic("orders", rf=3))
    assert fire("KAFKA.DELEGATION_TOKEN.INSECURE_TRANSPORT", b, ctx) == []


def test_delegation_token_does_not_fire_when_key_absent():
    cfg = config({"delegation.token.master.key": DELETE})
    b, ctx = fixture_scan(cfg)
    assert fire("KAFKA.DELEGATION_TOKEN.INSECURE_TRANSPORT", b, ctx) == []


# ═══ KAFKA.ZK.KRAFT_MIGRATION_ACL_GAP ═════════════════════════════════════
def test_migration_gap_silent_when_not_migrating():
    """The fixture has zookeeper.metadata.migration.enable=false — no finding."""
    b, ctx = fixture_scan()
    assert fire("KAFKA.ZK.KRAFT_MIGRATION_ACL_GAP", b, ctx) == []


def test_migration_gap_fires_when_migrating_without_authorizer():
    b, ctx = fixture_scan(config({"zookeeper.metadata.migration.enable": "true"}))
    hits = fire("KAFKA.ZK.KRAFT_MIGRATION_ACL_GAP", b, ctx)
    assert len(hits) == 1
    # fixture authorizer is unset AND fixture listeners mint ANONYMOUS -> critical
    assert hits[0].severity == "critical"
    assert "migration is in progress" in hits[0].observation
    assert hits[0].assessable is True


def test_migration_gap_high_without_anonymous_listeners():
    """Authorizer unset while migrating, but no listener mints ANONYMOUS -> high, not critical."""
    cfg = config({"zookeeper.metadata.migration.enable": "true",
                  "listener.security.protocol.map":
                      "CONTROLLER:SSL,INTERNAL:SSL,EXTERNAL:SSL",
                  "ssl.client.auth": entry("required")})
    b, ctx = fixture_scan(cfg)
    hits = fire("KAFKA.ZK.KRAFT_MIGRATION_ACL_GAP", b, ctx)
    assert len(hits) == 1 and hits[0].severity == "high"


def test_migration_gap_not_assessable_when_authorizer_is_set():
    """Migrating with an authorizer here, but the controller side is unreachable -> coverage gap."""
    cfg = config({"zookeeper.metadata.migration.enable": "true", **AUTHZ_SET})
    b, ctx = fixture_scan(cfg)
    hits = fire("KAFKA.ZK.KRAFT_MIGRATION_ACL_GAP", b, ctx)
    assert len(hits) == 1 and hits[0].assessable is False and hits[0].assessment_reason


def test_migration_gap_absent_authorizer_key_is_inconclusive():
    cfg = config({"zookeeper.metadata.migration.enable": "true",
                  "authorizer.class.name": DELETE})
    b, ctx = fixture_scan(cfg)
    assert fire("KAFKA.ZK.KRAFT_MIGRATION_ACL_GAP", b, ctx) == []
