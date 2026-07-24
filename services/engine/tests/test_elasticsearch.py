"""Elasticsearch/OpenSearch connector + rulepack + NHI. Offline: no httpx, no live cluster.

Golden snapshot dicts (shaped exactly as connect/elasticsearch.py assembles from its httpx
envelopes) feed the connector's OWN pure _build_resources, so the detectors here run against the
resources the connector actually emits — a shape drift fails HERE first. Every rule gets a FIRE,
a DOES-NOT-FIRE, and (where it has one) a NOT-ASSESSABLE case.
"""
from vectasec.connect.elasticsearch import _build_resources, _flatten_settings, _values_under
from vectasec.contracts import Collected, ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import DETECTORS
import vectasec.detect.elasticsearch  # noqa: F401 — registers the rulepack

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("ELASTICSEARCH.")}

EXPECTED_RULES = {
    "ELASTICSEARCH.SECURITY.DISABLED", "ELASTICSEARCH.SECURITY.ANONYMOUS_ACCESS", "ELASTICSEARCH.SECURITY.ANONYMOUS_ROLE",
    "ELASTICSEARCH.TLS.HTTP_DISABLED", "ELASTICSEARCH.TLS.TRANSPORT_DISABLED", "ELASTICSEARCH.TLS.TRANSPORT_NO_VERIFY",
    "ELASTICSEARCH.HTTP.CORS_WILDCARD", "ELASTICSEARCH.AUDIT.DISABLED", "ELASTICSEARCH.SNAPSHOT.REPO_PLAINTEXT_URL",
    "ELASTICSEARCH.CLUSTER.NOT_ASSESSED", "ELASTICSEARCH.INDEX.ANON_LISTABLE",
}

_SECURE_SETTINGS = {
    "xpack.security.enabled": "true",
    "xpack.security.http.ssl.enabled": "true",
    "xpack.security.transport.ssl.enabled": "true",
    "xpack.security.transport.ssl.verification_mode": "full",
    "xpack.security.audit.enabled": "true",
}


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def build(**snap) -> Collected:
    settings = dict(_SECURE_SETTINGS)
    settings.update(snap.pop("settings", {}))
    base = {
        "distribution": "elasticsearch", "version": "8.13.0", "cluster_name": "prod",
        "base_url": "https://es:9200", "scheme": "https",
        "settings": settings, "settings_readable": True,
        "anon_root_status": 401, "anon_indices_status": 401, "anon_indices": [],
        "authenticate_status": 200, "authenticate_not_enabled": False,
        "indices": [], "snapshot_repos": {}, "users": [], "roles": [],
        "endpoint_outcomes": {"node_settings": "ok", "cluster_settings": "ok", "indices": "ok",
                              "security_users": "ok", "security_roles": "ok", "snapshots": "ok"},
    }
    base.update(snap)
    return _build_resources(base)


def cluster(**snap):
    return next(r for r in build(**snap).resources if r.kind == "es_cluster")


def es_indices(**snap):
    return [r for r in build(**snap).resources if r.kind == "es_index"]


def fire(rule_id, resource, ctx=None):
    d = RULES[rule_id]
    assert resource.kind in d.kinds, f"{rule_id} does not apply to {resource.kind}"
    return d.fn(resource, ctx or _ctx([resource])) or []


# ── pack shape ────────────────────────────────────────────────────────────────
def test_expected_rules_registered():
    assert set(RULES) == EXPECTED_RULES


def test_rules_only_run_on_es_kinds():
    for d in RULES.values():
        assert all(k.startswith("es_") for k in d.kinds), d.rule_id


# ── helpers ─────────────────────────────────────────────────────────────────--
def test_flatten_precedence_node_over_cluster():
    node = {"xpack.security.enabled": "false"}
    clus = {"defaults": {"xpack.security.enabled": "true"}, "persistent": {}, "transient": {}}
    assert _flatten_settings(node, clus)["xpack.security.enabled"] == "false"


def test_values_under_collects_flat_array():
    s = {"xpack.security.authc.anonymous.roles.0": "r1",
         "xpack.security.authc.anonymous.roles.1": "r2"}
    assert sorted(_values_under(s, "xpack.security.authc.anonymous.roles")) == ["r1", "r2"]


# ── ES.SECURITY.DISABLED ────────────────────────────────────────────────────--
def test_security_disabled_fires_on_xpack_false():
    hits = fire("ELASTICSEARCH.SECURITY.DISABLED", cluster(settings={"xpack.security.enabled": "false"}))
    assert len(hits) == 1 and hits[0].assessable and "disabled" in hits[0].observation


def test_security_disabled_quiet_when_enabled():
    assert fire("ELASTICSEARCH.SECURITY.DISABLED", cluster()) == []


def test_security_disabled_not_assessable_when_unknown():
    # xpack.security.enabled unreadable (None) and no conclusive authenticate probe → unknown
    c = cluster(settings={"xpack.security.enabled": None}, authenticate_status=None,
                settings_readable=False)
    hits = fire("ELASTICSEARCH.SECURITY.DISABLED", c)
    assert len(hits) == 1 and hits[0].assessable is False


def test_security_disabled_opensearch_plugin_off():
    c = cluster(distribution="opensearch",
                settings={"plugins.security.disabled": "true", "xpack.security.enabled": None})
    hits = fire("ELASTICSEARCH.SECURITY.DISABLED", c)
    assert len(hits) == 1 and hits[0].assessable and "disabled" in hits[0].observation


# ── ES.SECURITY.ANONYMOUS_ACCESS ───────────────────────────────────────────--
def test_anonymous_access_fires_on_200():
    hits = fire("ELASTICSEARCH.SECURITY.ANONYMOUS_ACCESS", cluster(anon_root_status=200))
    assert len(hits) == 1 and hits[0].severity is None  # decorator severity critical


def test_anonymous_access_quiet_on_401():
    assert fire("ELASTICSEARCH.SECURITY.ANONYMOUS_ACCESS", cluster(anon_root_status=401)) == []


def test_anonymous_access_not_assessable_on_transport_error():
    hits = fire("ELASTICSEARCH.SECURITY.ANONYMOUS_ACCESS", cluster(anon_root_status=None))
    assert len(hits) == 1 and hits[0].assessable is False


# ── ES.SECURITY.ANONYMOUS_ROLE ─────────────────────────────────────────────--
def test_anonymous_role_fires_when_set():
    c = cluster(settings={"xpack.security.authc.anonymous.roles.0": "public_read"})
    hits = fire("ELASTICSEARCH.SECURITY.ANONYMOUS_ROLE", c)
    assert len(hits) == 1 and "public_read" in hits[0].observation


def test_anonymous_role_quiet_when_unset():
    assert fire("ELASTICSEARCH.SECURITY.ANONYMOUS_ROLE", cluster()) == []


# ── ES.TLS.HTTP_DISABLED ────────────────────────────────────────────────────
def test_http_tls_fires_when_false():
    hits = fire("ELASTICSEARCH.TLS.HTTP_DISABLED",
                cluster(settings={"xpack.security.http.ssl.enabled": "false"}))
    assert len(hits) == 1 and hits[0].assessable


def test_http_tls_quiet_when_true():
    assert fire("ELASTICSEARCH.TLS.HTTP_DISABLED", cluster()) == []


def test_http_tls_observed_plaintext_when_setting_unreadable_and_http():
    c = cluster(settings={"xpack.security.http.ssl.enabled": None}, scheme="http")
    hits = fire("ELASTICSEARCH.TLS.HTTP_DISABLED", c)
    assert len(hits) == 1 and hits[0].assessable and "plaintext" in hits[0].observation


def test_http_tls_not_assessable_when_unreadable_and_https():
    c = cluster(settings={"xpack.security.http.ssl.enabled": None}, scheme="https")
    hits = fire("ELASTICSEARCH.TLS.HTTP_DISABLED", c)
    assert len(hits) == 1 and hits[0].assessable is False


# ── ES.TLS.TRANSPORT_DISABLED / NO_VERIFY ──────────────────────────────────--
def test_transport_tls_fire_and_pass():
    assert len(fire("ELASTICSEARCH.TLS.TRANSPORT_DISABLED",
                    cluster(settings={"xpack.security.transport.ssl.enabled": "false"}))) == 1
    assert fire("ELASTICSEARCH.TLS.TRANSPORT_DISABLED", cluster()) == []


def test_transport_tls_not_assessable_when_unreadable():
    c = cluster(settings={"xpack.security.transport.ssl.enabled": None}, settings_readable=False)
    hits = fire("ELASTICSEARCH.TLS.TRANSPORT_DISABLED", c)
    assert len(hits) == 1 and hits[0].assessable is False


def test_transport_no_verify_fires_only_when_tls_on():
    hits = fire("ELASTICSEARCH.TLS.TRANSPORT_NO_VERIFY",
                cluster(settings={"xpack.security.transport.ssl.verification_mode": "none"}))
    assert len(hits) == 1 and "none" in hits[0].detail
    # transport TLS off → the DISABLED rule owns it, verification mode is moot
    assert fire("ELASTICSEARCH.TLS.TRANSPORT_NO_VERIFY", cluster(settings={
        "xpack.security.transport.ssl.enabled": "false",
        "xpack.security.transport.ssl.verification_mode": "none"})) == []
    assert fire("ELASTICSEARCH.TLS.TRANSPORT_NO_VERIFY", cluster()) == []   # mode full


# ── ES.HTTP.CORS_WILDCARD ───────────────────────────────────────────────────
def test_cors_wildcard_fire_and_pass():
    hits = fire("ELASTICSEARCH.HTTP.CORS_WILDCARD",
                cluster(settings={"http.cors.enabled": "true", "http.cors.allow-origin": "*"}))
    assert len(hits) == 1
    assert fire("ELASTICSEARCH.HTTP.CORS_WILDCARD", cluster(settings={
        "http.cors.enabled": "true", "http.cors.allow-origin": "https://app.example.com"})) == []
    assert fire("ELASTICSEARCH.HTTP.CORS_WILDCARD", cluster()) == []   # cors disabled


# ── ES.AUDIT.DISABLED ───────────────────────────────────────────────────────
def test_audit_disabled_fire_and_pass():
    hits = fire("ELASTICSEARCH.AUDIT.DISABLED", cluster(settings={"xpack.security.audit.enabled": "false"}))
    assert len(hits) == 1
    assert fire("ELASTICSEARCH.AUDIT.DISABLED", cluster()) == []   # audit on
    # security disabled entirely → audit rule is silent (the bigger finding owns it)
    assert fire("ELASTICSEARCH.AUDIT.DISABLED", cluster(settings={
        "xpack.security.enabled": "false", "xpack.security.audit.enabled": "false"})) == []


# ── ES.SNAPSHOT.REPO_PLAINTEXT_URL ─────────────────────────────────────────--
def test_snapshot_url_plaintext_fire_and_pass():
    repos = {"backups": {"type": "url", "settings": {"url": "http://nfs.internal/snap"}},
             "s3repo": {"type": "s3", "settings": {"bucket": "b"}},
             "secure": {"type": "url", "settings": {"url": "https://nfs.internal/snap"}}}
    hits = fire("ELASTICSEARCH.SNAPSHOT.REPO_PLAINTEXT_URL", cluster(snapshot_repos=repos))
    assert len(hits) == 1 and "backups" in hits[0].observation
    assert fire("ELASTICSEARCH.SNAPSHOT.REPO_PLAINTEXT_URL", cluster()) == []


# ── ES.CLUSTER.NOT_ASSESSED ─────────────────────────────────────────────────
def test_cluster_not_assessed_reports_forbidden_endpoints():
    c = cluster(endpoint_outcomes={"node_settings": "ok", "security_users": "forbidden",
                                   "snapshots": "error"})
    hits = fire("ELASTICSEARCH.CLUSTER.NOT_ASSESSED", c)
    assert len(hits) == 2 and all(h.assessable is False for h in hits)


def test_cluster_not_assessed_quiet_when_all_ok():
    assert fire("ELASTICSEARCH.CLUSTER.NOT_ASSESSED", cluster()) == []


# ── ES.INDEX.ANON_LISTABLE ─────────────────────────────────────────────────--
def test_index_anon_listable_high_and_system_critical():
    idxs = es_indices(indices=[{"index": "logs-2024", "health": "green"},
                               {"index": ".security-7", "health": "green"},
                               {"index": "private", "health": "green"}],
                      anon_indices=["logs-2024", ".security-7"], anon_indices_status=200)
    by_name = {r.name: r for r in idxs}
    logs = fire("ELASTICSEARCH.INDEX.ANON_LISTABLE", by_name["logs-2024"])
    assert len(logs) == 1 and logs[0].severity == "high"
    sec = fire("ELASTICSEARCH.INDEX.ANON_LISTABLE", by_name[".security-7"])
    assert len(sec) == 1 and sec[0].severity == "critical"
    assert fire("ELASTICSEARCH.INDEX.ANON_LISTABLE", by_name["private"]) == []   # not in the anon listing


def test_index_not_anon_listable_when_probe_did_not_run():
    idxs = es_indices(indices=[{"index": "logs", "health": "green"}],
                      anon_indices=["logs"], anon_indices_status=401)
    assert fire("ELASTICSEARCH.INDEX.ANON_LISTABLE", idxs[0]) == []


# ── NHI ─────────────────────────────────────────────────────────────────────
def test_elasticsearch_extractor_registered():
    assert "elasticsearch" in IDENTITY_EXTRACTORS


def test_users_become_identity_credential_and_role_grants():
    users = [
        {"username": "svc-reader", "roles": ["reader"], "enabled": True, "reserved": False,
         "has_password": True, "hashing": "unknown"},
        {"username": "elastic", "roles": ["superuser"], "enabled": True, "reserved": True,
         "has_password": True, "hashing": "unknown"},
    ]
    col = derive_identities("elasticsearch", Collected(resources=build(users=users).resources))
    ids = [r for r in col.resources if r.kind == "identity"]
    creds = [r for r in col.resources if r.kind == "credential"]
    grants = [r for r in col.resources if r.kind == "grant"]
    assert len(ids) == 2 and len(creds) == 2 and len(grants) == 2
    elastic = next(i for i in ids if i.name == "elastic")
    assert elastic.raw["identity_type"] == "superuser" and "reserved" in elastic.raw["tags"]
    superuser_grant = next(g for g in grants if g.raw["action"] == "role"
                           and g.raw["target"] == "superuser")
    assert superuser_grant.raw["wildcard"] is True
    reader_grant = next(g for g in grants if g.raw["target"] == "reader")
    assert reader_grant.raw["wildcard"] is False
    # credential_of edges link each credential to its identity
    assert sum(1 for e in col.edges if e.kind == "credential_of") == 2


def test_opensearch_user_hash_reduced_to_boolean_not_stored():
    # simulate the OpenSearch normalization result (hash already dropped by the connector)
    users = [{"username": "admin", "roles": ["all_access"], "enabled": True, "reserved": True,
              "has_password": True, "hashing": "bcrypt"}]
    col = derive_identities("elasticsearch", Collected(resources=build(users=users).resources))
    cred = next(r for r in col.resources if r.kind == "credential")
    assert cred.raw["hashing"] == "bcrypt" and cred.raw["plaintext"] is False
    assert "hash" not in cred.raw  # only metadata crossed the boundary
