"""Kafka Connect connector + rulepack — offline. Detectors run on parse_connector/parse_cluster
output from golden REST dicts. A key discipline verified here: connector secret VALUES are never
stored, only key presence + externalized-or-inline booleans.
"""
import json

from vectasec.contracts import Collected, ScanContext
from vectasec.identity import derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
from vectasec.connect.kafka_connect import parse_cluster, parse_connector
import vectasec.detect.kafka_connect as rp

BASE = "http://connect:8083"


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=list(resources))


CFG_INLINE = {
    "connector.class": "io.confluent.connect.jdbc.JdbcSourceConnector",
    "connection.url": "jdbc:postgresql://db/app",
    "connection.password": "s3cr3t-P@ss",
    "tasks.max": "1",
}
CFG_EXTERNALIZED = {
    "connector.class": "io.confluent.connect.jdbc.JdbcSourceConnector",
    "connection.password": "${file:/opt/secrets/creds.properties:db_password}",
    "tasks.max": "1",
}
CFG_JAAS = {
    "connector.class": "io.confluent.connect.s3.S3SinkConnector",
    "producer.override.sasl.jaas.config": "org.apache.kafka.common.security.plain.PlainLoginModule required;",
}
CFG_NO_SECRETS = {"connector.class": "FileStreamSource", "file": "/tmp/x", "topic": "t"}


def cluster(*, tls_url=False, anonymous_readable=False, connectors_readable=True):
    return parse_cluster(BASE, {"version": "3.7.0", "kafka_cluster_id": "abc"}, tls_url=tls_url,
                         anonymous_readable=anonymous_readable,
                         connectors_readable=connectors_readable)


def test_connector_registered_and_secret_marked():
    assert "kafka_connect" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["kafka_connect"]}
    assert fields["password"].secret and fields["url"].required


# ── the parse layer never stores a secret VALUE ────────────────────────────────
def test_parse_connector_records_key_presence_never_the_value():
    r = parse_connector(BASE, "pg-source", CFG_INLINE)
    assert "connection.password" in r.raw["inline_secret_keys"]
    # the literal secret must not appear anywhere in the resource
    assert "s3cr3t-P@ss" not in json.dumps(r.raw)
    # secret_keys maps key -> externalized? (False for an inline literal)
    assert r.raw["secret_keys"]["connection.password"] is False


def test_parse_connector_treats_externalized_reference_as_safe():
    r = parse_connector(BASE, "pg-source", CFG_EXTERNALIZED)
    assert r.raw["inline_secret_keys"] == []                       # ${...} is not inline
    assert r.raw["secret_keys"]["connection.password"] is True     # externalized


# ── KAFKA_CONNECT.REST.UNAUTHENTICATED ─────────────────────────────────────────
def test_rest_unauthenticated_fires_critical():
    c = cluster(anonymous_readable=True)
    hits = rp.rest_unauthenticated(c, _ctx([c]))
    assert len(hits) == 1 and "CVE-2023-25194" in hits[0].source_ref.get("cve", "")


def test_rest_authenticated_does_not_fire():
    assert rp.rest_unauthenticated(cluster(anonymous_readable=False), _ctx([])) == []


def test_rest_not_assessable_when_connectors_unreadable():
    c = cluster(connectors_readable=False)
    hits = rp.rest_unauthenticated(c, _ctx([c]))
    assert len(hits) == 1 and hits[0].assessable is False


# ── KAFKA_CONNECT.TLS.DISABLED ─────────────────────────────────────────────────
def test_tls_disabled_fires_on_http():
    c = cluster(tls_url=False)
    assert len(rp.tls_disabled(c, _ctx([c]))) == 1


def test_tls_disabled_silent_on_https():
    assert rp.tls_disabled(cluster(tls_url=True), _ctx([])) == []


# ── KAFKA_CONNECT.CONNECTOR.PLAINTEXT_SECRET ───────────────────────────────────
def test_plaintext_secret_fires_on_inline():
    r = parse_connector(BASE, "pg-source", CFG_INLINE)
    hits = rp.connector_plaintext_secret(r, _ctx([r]))
    assert len(hits) == 1 and "connection.password" in hits[0].observation
    assert "s3cr3t-P@ss" not in hits[0].observation                # value never leaks into a finding


def test_plaintext_secret_silent_on_externalized():
    r = parse_connector(BASE, "pg-source", CFG_EXTERNALIZED)
    assert rp.connector_plaintext_secret(r, _ctx([r])) == []


def test_plaintext_secret_not_assessable_when_config_unreadable():
    r = parse_connector(BASE, "denied", None)
    hits = rp.connector_plaintext_secret(r, _ctx([r]))
    assert len(hits) == 1 and hits[0].assessable is False


# ── KAFKA_CONNECT.CONNECTOR.JAAS_OVERRIDE ──────────────────────────────────────
def test_jaas_override_fires():
    r = parse_connector(BASE, "s3-sink", CFG_JAAS)
    hits = rp.connector_jaas_override(r, _ctx([r]))
    assert len(hits) == 1 and "producer.override.sasl.jaas.config" in hits[0].observation


def test_jaas_override_silent_without_override():
    r = parse_connector(BASE, "clean", CFG_NO_SECRETS)
    assert rp.connector_jaas_override(r, _ctx([r])) == []


# ── NHI: connector-stored credentials → credential metadata ────────────────────
def test_nhi_connector_secret_becomes_identity_and_credential():
    r = parse_connector(BASE, "pg-source", CFG_INLINE)
    col = derive_identities("kafka_connect", Collected(resources=[r]))
    ids = [x for x in col.resources if x.kind == "identity"]
    creds = [x for x in col.resources if x.kind == "credential"]
    assert len(ids) == 1 and ids[0].raw["identity_type"] == "connector"
    assert len(creds) == 1
    # inline literal -> plaintext True; still no value stored
    assert creds[0].raw["plaintext"] is True
    assert "s3cr3t-P@ss" not in json.dumps(creds[0].raw)
    assert any(e.kind == "credential_of" for e in col.edges)


def test_nhi_externalized_secret_is_not_plaintext():
    r = parse_connector(BASE, "pg-source", CFG_EXTERNALIZED)
    col = derive_identities("kafka_connect", Collected(resources=[r]))
    creds = [x for x in col.resources if x.kind == "credential"]
    assert len(creds) == 1 and creds[0].raw["plaintext"] is False


def test_nhi_connector_without_secrets_yields_no_identity():
    r = parse_connector(BASE, "clean", CFG_NO_SECRETS)
    col = derive_identities("kafka_connect", Collected(resources=[r]))
    assert not [x for x in col.resources if x.kind in ("identity", "credential")]


# ── installed-plugin inventory (/connector-plugins) ───────────────────────────
def test_parse_plugins_inventories_class_type_and_version():
    from vectasec.connect.kafka_connect import parse_plugins
    out = parse_plugins(BASE, [
        {"class": "io.debezium.connector.postgresql.PostgresConnector",
         "type": "source", "version": "2.5.0.Final"},
        {"class": "org.apache.kafka.connect.transforms.Cast$Value", "type": "transformation"},
    ])
    assert [r.kind for r in out] == ["kafka_connect_plugin"] * 2
    dbz = out[0]
    assert dbz.name == "PostgresConnector"
    assert dbz.labels["product"] == "io.debezium.connector.postgresql.postgresconnector"
    assert dbz.labels["version"] == "2.5.0.Final" and dbz.raw["version"] == "2.5.0.Final"
    assert dbz.raw["cluster_ext"] == f"kafka-connect-{BASE}"


def test_a_versionless_plugin_never_inherits_the_worker_version():
    """Older workers omit the field; some serialize the literal "null". Either way the
    component must carry NO version — an inherited one would drive CVE matching against a
    number nobody stated (sbom.component_for refuses versionless components by design)."""
    from vectasec.connect.kafka_connect import parse_plugins
    from vectasec.sbom import component_for
    for reported in (None, "", "null"):
        (r,) = parse_plugins(BASE, [{"class": "a.b.C", "type": "sink", "version": reported}])
        assert "version" not in r.labels and "version" not in r.raw
        assert component_for({"kind": r.kind, "name": r.name, "ext_id": r.ext_id,
                              "labels": r.labels, "raw": r.raw}) is None


def test_a_versioned_plugin_becomes_an_sbom_component():
    from vectasec.connect.kafka_connect import parse_plugins
    from vectasec.sbom import component_for
    (r,) = parse_plugins(BASE, [{"class": "io.debezium.connector.postgresql.PostgresConnector",
                                 "type": "source", "version": "2.5.0.Final"}])
    comp = component_for({"kind": r.kind, "name": r.name, "ext_id": r.ext_id,
                          "labels": r.labels, "raw": r.raw})
    assert comp is not None and comp["version"] == "2.5.0.Final"
    # No purl and no CPE exists for a Connect plugin class — fabricating either would point
    # a feed at the wrong artifact. The component is named, versioned, and honestly bare.
    assert "purl" not in comp and "cpe" not in comp


def test_plugins_garbage_shapes_are_dropped():
    from vectasec.connect.kafka_connect import parse_plugins
    assert parse_plugins(BASE, None) == []
    assert parse_plugins(BASE, "nope") == []
    assert parse_plugins(BASE, [{"type": "source"}, "x", {}]) == []


def test_unreadable_plugin_inventory_files_a_gap_not_an_empty_inventory():
    c = parse_cluster(BASE, {"version": "3.7.0"}, tls_url=False, anonymous_readable=False,
                      connectors_readable=True, plugins_readable=False)
    hits = rp.plugins_not_readable(c, _ctx([c]))
    assert len(hits) == 1 and hits[0].assessable is False
    assert "/connector-plugins" in hits[0].source_ref["endpoint"]


def test_pre_inventory_rows_are_unknown_not_a_refusal():
    """plugins_readable=None marks a cluster row collected before this inventory existed.
    Filing a gap on every stale row would mint findings no rescan of old data can close."""
    c = cluster()                      # helper predates the kwarg -> None
    assert rp.plugins_not_readable(c, _ctx([c])) == []
    ok = parse_cluster(BASE, {}, tls_url=False, anonymous_readable=False,
                       connectors_readable=True, plugins_readable=True)
    assert rp.plugins_not_readable(ok, _ctx([ok])) == []
