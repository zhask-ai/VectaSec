"""Apache Pulsar connector + rulepack tests. Offline: httpx is never constructed, no cluster is
touched. Detectors run against the pure build_resources() output from the golden Admin-API
snapshot fixture, so a shape drift between connector and rulepack fails here first.

Every detector is exercised firing, not-firing, and (where it has one) reporting a not-assessable
coverage gap. The NHI extractor is checked on exactly what the connector emits.
"""
import copy
import json
import pathlib

from vectasec.connect.pulsar import build_resources
from vectasec.contracts import Collected, ScanContext
from vectasec.detect import pulsar as pd
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS

FIX = json.loads((pathlib.Path(__file__).parent / "fixtures" / "pulsar_admin.json").read_text())


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def collected(variant, mutate=None) -> Collected:
    snap = copy.deepcopy(FIX[variant])
    if mutate:
        mutate(snap)
    return build_resources(snap)


def local_cluster(col: Collected):
    return next(r for r in col.resources if r.kind == "pulsar_cluster" and r.raw["is_local"])


def cluster(col: Collected, name: str):
    return next(r for r in col.resources if r.kind == "pulsar_cluster" and r.raw["name"] == name)


def namespace(col: Collected, full: str):
    return next(r for r in col.resources if r.kind == "pulsar_namespace" and r.raw["namespace"] == full)


def topic(col: Collected, fqtn: str):
    return next(r for r in col.resources if r.kind == "pulsar_topic" and r.raw["fqtn"] == fqtn)


# ── registration ────────────────────────────────────────────────────────────────
def test_connector_and_extractor_registered():
    assert "pulsar" in CONNECTORS and "pulsar" in IDENTITY_EXTRACTORS


def test_only_token_field_is_secret():
    fields = {f.key: f for f in CONNECTOR_FIELDS["pulsar"]}
    assert fields["token"].secret is True
    assert fields["admin_url"].required is True
    assert not fields["broker_config"].secret


# ── parse layer ──────────────────────────────────────────────────────────────────
def test_parse_marks_local_cluster_and_distinct_kinds():
    col = collected("insecure")
    assert local_cluster(col).raw["name"] == "standalone"
    # peer cluster carries no broker config (avoids N-duplicated broker findings)
    assert cluster(col, "peer-west").raw["runtime_config"] is None
    kinds = {r.kind for r in col.resources}
    assert {"pulsar_cluster", "pulsar_namespace", "pulsar_topic"} <= kinds


# ── PULSAR.AUTH.AUTHENTICATION_DISABLED ──────────────────────────────────────────
def test_authentication_disabled_fires_only_on_local_and_passes_hardened():
    col = collected("insecure")
    assert pd.authentication_disabled(local_cluster(col), _ctx([]))
    assert pd.authentication_disabled(cluster(col, "peer-west"), _ctx([])) == []
    assert pd.authentication_disabled(local_cluster(collected("hardened")), _ctx([])) == []


def test_authentication_disabled_unreadable_config_is_not_assessable():
    def blind(snap):
        snap["runtime_config"] = {}
        snap["config_source"] = None
        snap["admin_readable"] = False
        snap["clusters"] = [{"name": "standalone", "data": {}}]
    hits = pd.authentication_disabled(local_cluster(collected("insecure", blind)), _ctx([]))
    assert hits and hits[0].assessable is False and hits[0].assessment_reason


# ── PULSAR.AUTH.AUTHORIZATION_DISABLED ───────────────────────────────────────────
def test_authorization_disabled_fires_and_passes():
    assert pd.authorization_disabled(local_cluster(collected("insecure")), _ctx([]))
    assert pd.authorization_disabled(local_cluster(collected("hardened")), _ctx([])) == []


# ── PULSAR.BROKER.TLS_DISABLED ───────────────────────────────────────────────────
def test_broker_tls_disabled_fires_and_passes():
    assert pd.broker_tls_disabled(local_cluster(collected("insecure")), _ctx([]))
    assert pd.broker_tls_disabled(local_cluster(collected("hardened")), _ctx([])) == []


# ── PULSAR.PROXY.TLS_DISABLED ────────────────────────────────────────────────────
def test_proxy_tls_disabled_fires_passes_and_skips_when_absent():
    assert pd.proxy_tls_disabled(local_cluster(collected("insecure")), _ctx([]))
    assert pd.proxy_tls_disabled(local_cluster(collected("hardened")), _ctx([])) == []
    # no proxy.conf supplied → nothing to assess (proxies are optional, not a gap)
    no_proxy = collected("insecure", lambda s: s.update(proxy_config=None))
    assert pd.proxy_tls_disabled(local_cluster(no_proxy), _ctx([])) == []


# ── PULSAR.TENANT.ADMIN_ROLE_SHARED ──────────────────────────────────────────────
def test_tenant_admin_role_shared_fires_and_passes():
    hits = pd.tenant_admin_role_shared(local_cluster(collected("insecure")), _ctx([]))
    assert hits and "shared-admin" in hits[0].observation
    assert pd.tenant_admin_role_shared(local_cluster(collected("hardened")), _ctx([])) == []


# ── PULSAR.CLUSTER.NO_TLS_ENDPOINT ───────────────────────────────────────────────
def test_cluster_no_tls_endpoint_fires_on_plain_only_cluster():
    col = collected("insecure")
    assert pd.cluster_no_tls_endpoint(cluster(col, "standalone"), _ctx([]))
    assert pd.cluster_no_tls_endpoint(cluster(col, "peer-west"), _ctx([])) == []
    assert pd.cluster_no_tls_endpoint(cluster(collected("hardened"), "standalone"), _ctx([])) == []


# ── PULSAR.VERSION.FUNCTIONS_WORKER_CVE ──────────────────────────────────────────
def test_functions_worker_cve_fires_and_version_boundaries():
    assert pd.functions_worker_cve(local_cluster(collected("insecure")), _ctx([]))   # 3.1.2 < 3.1.3
    # patched patch level
    patched = collected("insecure", lambda s: s.update(version="3.1.3"))
    assert pd.functions_worker_cve(local_cluster(patched), _ctx([])) == []
    # functions worker off → CVE does not apply even on an affected version
    off = collected("insecure", lambda s: s["runtime_config"].update(functionsWorkerEnabled="false"))
    assert pd.functions_worker_cve(local_cluster(off), _ctx([])) == []


def test_functions_worker_cve_unknown_version_is_not_assessable():
    unk = collected("insecure", lambda s: s.update(version=None))
    hits = pd.functions_worker_cve(local_cluster(unk), _ctx([]))
    assert hits and hits[0].assessable is False


# ── PULSAR.NAMESPACE.ANONYMOUS_GRANT / BROAD_GRANT ───────────────────────────────
def test_namespace_anonymous_grant_fires_only_on_anon_role():
    col = collected("insecure")
    assert pd.namespace_anonymous_grant(namespace(col, "public/default"), _ctx([]))
    assert pd.namespace_anonymous_grant(namespace(col, "finance/ledger"), _ctx([])) == []


def test_namespace_broad_grant_fires_on_full_action_set_not_anon():
    col = collected("insecure")
    hits = pd.namespace_broad_grant(namespace(col, "public/default"), _ctx([]))
    assert hits and "approle" in hits[0].observation and "anon" not in str(hits[0].detail)
    assert pd.namespace_broad_grant(namespace(col, "finance/ledger"), _ctx([])) == []


# ── PULSAR.TOPIC.PUBLIC_DEFAULT_NAMESPACE ────────────────────────────────────────
def test_topic_public_default_fires_and_passes():
    col = collected("insecure")
    assert pd.topic_public_default(topic(col, "persistent://public/default/orders"), _ctx([]))
    assert pd.topic_public_default(topic(col, "persistent://finance/ledger/entries"), _ctx([])) == []


# ── NHI ──────────────────────────────────────────────────────────────────────────
def _derived():
    return derive_identities("pulsar", collected("insecure"))


def test_roles_become_identities_and_shared_admin_is_deduped():
    col = _derived()
    ids = {r.name for r in col.resources if r.kind == "identity"}
    assert {"shared-admin", "fin-admin", "anon", "approle", "ledger-app"} == ids
    shared = [r for r in col.resources if r.kind == "identity" and r.name == "shared-admin"]
    assert len(shared) == 1     # one identity though it admins two tenants


def test_grants_carry_wildcard_flag_and_edges_resolve():
    col = _derived()
    grants = [g for g in col.resources if g.kind == "grant"]
    # full-action-set namespace grant is wildcard; consume-only is not
    approle_id = next(i.ext_id for i in col.resources if i.name == "approle")
    approle_grant = next(g for g in grants if g.raw["identity_ext_id"] == approle_id)
    assert approle_grant.raw["wildcard"] is True
    ledger_id = next(i.ext_id for i in col.resources if i.name == "ledger-app")
    ledger_grant = next(g for g in grants if g.raw["identity_ext_id"] == ledger_id)
    assert ledger_grant.raw["wildcard"] is False
    # tenant-admin grants are wildcard and resolve granted_to edges
    granted_to = {(e.src_ext_id, e.dst_ext_id) for e in col.edges if e.kind == "granted_to"}
    for g in grants:
        assert (g.ext_id, g.raw["identity_ext_id"]) in granted_to


def test_no_credentials_emitted_absence_not_silence():
    col = _derived()
    assert not [r for r in col.resources if r.kind == "credential"]
