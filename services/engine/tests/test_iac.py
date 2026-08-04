"""Integration-as-code connector + rulepack. Offline: no filesystem walk, no repository.

Golden manifests feed the connector's OWN pure parse layer, so the detectors run against exactly
what collect() would have produced. Every rule gets FIRE / DOES-NOT-FIRE, and the two properties
that matter most for a static analyser are pinned explicitly:

  * a ${VAR} reference is the CORRECT pattern and must never be reported (the false positive
    that would make the pack unusable), and
  * a secret's VALUE never leaves the connector — findings carry a fingerprint, never the text.
"""
from vectasec.connect.iac import _parse_image, parse_iac
from vectasec.contracts import ScanContext
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS, DETECTORS
import vectasec.detect.iac  # noqa: F401 — registers the rulepack

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("SUPPLY.IAC.")}

EXPECTED_RULES = {
    "SUPPLY.IAC.LITERAL_SECRET", "SUPPLY.IAC.DEFAULT_CREDENTIAL",
    "SUPPLY.IAC.ANONYMOUS_ACCESS", "SUPPLY.IAC.PLAINTEXT_LISTENER",
    "SUPPLY.IAC.PUBLIC_PORT_BINDING", "SUPPLY.IAC.PRIVILEGED_CONTAINER",
    "SUPPLY.IAC.UNPINNED_IMAGE", "SUPPLY.IAC.NOT_ASSESSED",
}

# The manifest this product exists to find: a Kafka/RabbitMQ stack straight off a quickstart.
_BAD_COMPOSE = """
services:
  kafka:
    image: confluentinc/cp-kafka:latest
    privileged: true
    ports:
      - "9092:9092"
    environment:
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND: "true"
  rabbitmq:
    image: rabbitmq:3.13.7-management
    ports:
      - "127.0.0.1:15672:15672"
    environment:
      RABBITMQ_DEFAULT_PASS: guest
  app:
    image: mycorp/orders-api:1.4.2
    ports:
      - "8080:8080"
    environment:
      DB_PASSWORD: ${DB_PASSWORD}
      API_TOKEN: sk-live-9f3a2b7c1d4e5f60718293a4
"""

# The same stack, done correctly. Nothing here may fire.
_GOOD_COMPOSE = """
services:
  kafka:
    image: confluentinc/cp-kafka:7.5.0@sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999
    ports:
      - "127.0.0.1:9092:9092"
    environment:
      KAFKA_LISTENERS: SASL_SSL://0.0.0.0:9092
      KAFKA_ADVERTISED_LISTENERS: SASL_SSL://kafka:9092
      KAFKA_PASSWORD: ${KAFKA_PASSWORD}
"""

_K8S = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: redis
          image: redis:latest
          securityContext:
            privileged: true
          ports:
            - containerPort: 6379
          env:
            - name: REDIS_ALLOW_EMPTY_PASSWORD
              value: "yes"
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: redis-secret
                  key: password
"""


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def _fire(rule_id, resource, resources=None):
    return RULES[rule_id].fn(resource, _ctx(resources or [resource]))


def _workload(col, name):
    return next(r for r in col.resources
                if r.kind == "iac_workload" and (r.raw or {}).get("workload") == name)


def _bad():
    return parse_iac({"docker-compose.yml": _BAD_COMPOSE})


# ── registration ──────────────────────────────────────────────────────────────
def test_connector_and_all_rules_registered():
    assert "iac" in CONNECTORS
    assert EXPECTED_RULES == set(RULES)


def test_no_connector_field_is_secret():
    """The iac connector reads manifests; it never authenticates to anything, so a secret field
    here would mean something has gone wrong in its design."""
    assert not any(f.secret for f in CONNECTOR_FIELDS["iac"])


# ── parse layer ───────────────────────────────────────────────────────────────
def test_compose_services_become_distinct_workloads():
    col = _bad()
    kinds = {r.kind for r in col.resources}
    assert kinds == {"iac_file", "iac_workload"}, "must not reuse a live-system kind"
    names = {(r.raw or {}).get("workload") for r in col.resources if r.kind == "iac_workload"}
    assert names == {"kafka", "rabbitmq", "app"}


def test_image_parsing_separates_tag_and_digest():
    assert _parse_image("redis:latest") == {
        "repository": "redis", "tag": "latest", "digest": None,
        "mutable_tag": True, "digest_pinned": False}
    pinned = _parse_image("confluentinc/cp-kafka:7.5.0@sha256:abc")
    assert pinned["tag"] == "7.5.0" and pinned["digest_pinned"] is True
    assert pinned["mutable_tag"] is False
    # a registry:port prefix must not be mistaken for a tag
    assert _parse_image("registry.local:5000/kafka")["repository"] == "registry.local:5000/kafka"
    # no tag at all is implicitly :latest — same mutability, less visible
    assert _parse_image("redis")["mutable_tag"] is True


def test_file_resource_records_parse_success_and_workload_count():
    f = next(r for r in _bad().resources if r.kind == "iac_file")
    assert f.raw["parsed"] is True and f.raw["workload_count"] == 3
    assert f.raw["format"] == "compose"


# ── the two properties that make or break a static analyser ───────────────────
def test_variable_reference_is_never_reported_as_a_secret():
    """${DB_PASSWORD} is the CORRECT pattern. Reporting it would be the single loudest false
    positive in the pack and would train users to ignore every real hit."""
    app = _workload(_bad(), "app")
    keys = {s["key"] for s in app.raw["literal_secrets"]}
    assert "DB_PASSWORD" not in keys, "a ${VAR} reference must never be a finding"
    assert "API_TOKEN" in keys, "a real literal must still be caught"


def test_secret_value_never_leaves_the_connector():
    """The whole resource tree is searched for the literal, because a security product that
    copies your secrets into its own database has moved the problem, not solved it."""
    col = _bad()
    blob = repr([r.raw for r in col.resources]) + repr([r.labels for r in col.resources])
    assert "sk-live-9f3a2b7c1d4e5f60718293a4" not in blob
    app = _workload(col, "app")
    token = next(s for s in app.raw["literal_secrets"] if s["key"] == "API_TOKEN")
    assert len(token["fingerprint"]) == 12 and token["length"] == 32
    assert token["line"], "a finding must point at a line a human can open"


def test_k8s_secret_key_ref_is_a_reference_not_a_literal():
    redis = _workload(parse_iac({"deploy.yaml": _K8S}), "redis/redis")
    assert not redis.raw["literal_secrets"], "secretKeyRef is the correct pattern"


# ── rules: fire ───────────────────────────────────────────────────────────────
def test_literal_secret_fires_with_fingerprint_not_value():
    hits = _fire("SUPPLY.IAC.LITERAL_SECRET", _workload(_bad(), "app"))
    assert hits and "API_TOKEN" in hits[0].observation
    assert "sk-live-9f3a2b7c1d4e5f60718293a4" not in hits[0].observation


def test_default_credential_fires_on_guest():
    hits = _fire("SUPPLY.IAC.DEFAULT_CREDENTIAL", _workload(_bad(), "rabbitmq"))
    assert hits and "RABBITMQ_DEFAULT_PASS" in hits[0].observation


def test_anonymous_access_fires_on_allow_everyone():
    hits = _fire("SUPPLY.IAC.ANONYMOUS_ACCESS", _workload(_bad(), "kafka"))
    assert hits and "ALLOW_EVERYONE_IF_NO_ACL_FOUND" in hits[0].observation


def test_plaintext_listener_fires():
    hits = _fire("SUPPLY.IAC.PLAINTEXT_LISTENER", _workload(_bad(), "kafka"))
    assert hits and "PLAINTEXT" in hits[0].observation


def test_public_port_binding_fires_on_broker_but_not_on_loopback_bound():
    col = _bad()
    assert _fire("SUPPLY.IAC.PUBLIC_PORT_BINDING", _workload(col, "kafka"))
    assert not _fire("SUPPLY.IAC.PUBLIC_PORT_BINDING", _workload(col, "rabbitmq")), \
        "127.0.0.1-bound port is the remediation, not the finding"


def test_public_port_binding_ignores_non_integration_workloads():
    """A web app on 0.0.0.0 is the point of a web app. Firing there would train people to
    ignore the rule."""
    assert not _fire("SUPPLY.IAC.PUBLIC_PORT_BINDING", _workload(_bad(), "app"))


def test_privileged_and_unpinned_fire():
    kafka = _workload(_bad(), "kafka")
    assert _fire("SUPPLY.IAC.PRIVILEGED_CONTAINER", kafka)
    hits = _fire("SUPPLY.IAC.UNPINNED_IMAGE", kafka)
    assert hits and "latest" in hits[0].observation


def test_k8s_deployment_is_parsed_and_rules_fire():
    redis = _workload(parse_iac({"deploy.yaml": _K8S}), "redis/redis")
    assert redis.raw["source_format"] == "kubernetes"
    assert _fire("SUPPLY.IAC.PRIVILEGED_CONTAINER", redis)
    assert _fire("SUPPLY.IAC.ANONYMOUS_ACCESS", redis)
    assert _fire("SUPPLY.IAC.UNPINNED_IMAGE", redis)
    # hostNetwork lifts containerPort onto the node, so the port rule must see it
    assert _fire("SUPPLY.IAC.PUBLIC_PORT_BINDING", redis)


# ── rules: stay silent on a correct manifest ──────────────────────────────────
def test_a_correct_manifest_fires_nothing():
    col = parse_iac({"docker-compose.yml": _GOOD_COMPOSE})
    kafka = _workload(col, "kafka")
    for rule_id in EXPECTED_RULES - {"SUPPLY.IAC.NOT_ASSESSED"}:
        assert not _fire(rule_id, kafka), f"{rule_id} fired on a correctly-written manifest"


def test_digest_pinned_image_is_not_unpinned_even_with_a_tag():
    kafka = _workload(parse_iac({"docker-compose.yml": _GOOD_COMPOSE}), "kafka")
    assert kafka.raw["image"]["digest_pinned"] is True
    assert not _fire("SUPPLY.IAC.UNPINNED_IMAGE", kafka)


# ── coverage honesty ──────────────────────────────────────────────────────────
def test_unparseable_manifest_is_a_coverage_gap_not_silence():
    col = parse_iac({"broken.yaml": "services: [this: is: not: valid"})
    f = next(r for r in col.resources if r.kind == "iac_file")
    assert f.raw["parsed"] is False
    hits = _fire("SUPPLY.IAC.NOT_ASSESSED", f)
    assert hits and hits[0].assessable is False
    assert "could not be parsed" in hits[0].assessment_reason


def test_unreadable_file_is_still_reported():
    col = parse_iac({}, unreadable={"secret.yaml": "PermissionError: denied"})
    f = next(r for r in col.resources if r.kind == "iac_file")
    assert f.raw["parsed"] is False
    assert _fire("SUPPLY.IAC.NOT_ASSESSED", f)


def test_parsed_file_does_not_fire_the_coverage_rule():
    f = next(r for r in _bad().resources if r.kind == "iac_file")
    assert not _fire("SUPPLY.IAC.NOT_ASSESSED", f)


# ── Kafka Connect connector JSON ──────────────────────────────────────────────
def test_kafka_connect_config_is_parsed_and_secret_found():
    doc = ('{"name": "sink-1", "config": {"connector.class": "io.confluent.JdbcSinkConnector", '
           '"connection.password": "hunter2", "connection.url": "jdbc:postgresql://db/orders"}}')
    col = parse_iac({"sink-1.json": doc})
    w = _workload(col, "sink-1")
    assert w.raw["source_format"] == "kafka-connect"
    assert {s["key"] for s in w.raw["literal_secrets"]} == {"connection.password"}
    assert "hunter2" not in repr([r.raw for r in col.resources])
