"""Offline golden-fixture tests for the Kubernetes connector + rulepack.

Fixtures are plain-dict snapshots mirroring the JSON-wire shapes the K8s API returns
(metadata/spec camelCase, CRD items exactly as CustomObjectsApi hands them back). They flow
through connect/k8s._build_resources — the same pure normalisation the live collect uses — and
the produced Resources are handed to the detectors, so connector reduction and rules are
exercised together, end to end, with no cluster.

Every detector gets a fires-on-bad AND a silent-on-good pair; the negative is the load-bearing
one. The credential-reduction discipline gets its own test: a fixture secret carries a real
base64 token value, and that value must be absent from every byte the connector emits.
"""
import json

from vectasec.connect.k8s import (_build_resources, _CORE_KEYS, _GWAPI_KEYS, _ISTIO_KEYS,
                                  _LINKERD_KEYS)
from vectasec.contracts import ScanContext
from vectasec.identity import derive_identities
from vectasec.registry import DETECTORS
import vectasec.detect.k8s  # noqa: F401  — registers the K8S.* detectors

TOKEN_B64 = "U1VQRVJTRUNSRVQtVE9LRU4="   # the value that must never survive collection

_ALL_KEYS = (*_CORE_KEYS, *_ISTIO_KEYS, *_LINKERD_KEYS, *_GWAPI_KEYS)


# ── snapshot builders ─────────────────────────────────────────────────────────
def S(**sections) -> dict:
    """A snapshot with every section absent unless given. A list value means outcome ok."""
    snap = {k: {"outcome": "absent", "items": [], "error": None} for k in _ALL_KEYS}
    snap["version"] = "v1.30.2"
    for k, v in sections.items():
        assert k in _ALL_KEYS, k
        snap[k] = {"outcome": "ok", "items": v, "error": None} if isinstance(v, list) else v
    return snap


def m(name, ns=None, labels=None, annotations=None) -> dict:
    md = {"name": name}
    if ns:
        md["namespace"] = ns
    if labels:
        md["labels"] = labels
    if annotations:
        md["annotations"] = annotations
    return md


def forbidden() -> dict:
    return {"outcome": "forbidden", "items": [], "error": "HTTP 403"}


def istio_bad() -> dict:
    """Istio installed, PERMISSIVE mesh-wide, allow-all authz, DR DISABLE, plaintext edge."""
    return S(
        namespaces=[
            {"metadata": m("istio-system")},
            {"metadata": m("prod", labels={"istio-injection": "enabled"})},
            {"metadata": m("payments", labels={"istio.io/rev": "1-22"})},
            {"metadata": m("dev")},
        ],
        istio_peer_authentications=[
            {"metadata": m("default", "istio-system"),
             "spec": {"mtls": {"mode": "PERMISSIVE"}}},
        ],
        istio_authorization_policies=[
            {"metadata": m("allow-all", "prod"), "spec": {"rules": [{}]}},
        ],
        istio_destination_rules=[
            {"metadata": m("db-plain", "prod"),
             "spec": {"host": "db.prod.svc.cluster.local",
                      "trafficPolicy": {"tls": {"mode": "DISABLE"}}}},
        ],
        istio_gateways=[
            {"metadata": m("edge", "istio-system"),
             "spec": {"selector": {"istio": "ingressgateway"},
                      "servers": [{"port": {"number": 80, "name": "http", "protocol": "HTTP"},
                                   "hosts": ["*"]}]}},
        ],
        istio_virtual_services=[
            {"metadata": m("web", "prod"),
             "spec": {"hosts": ["shop.example.com"], "gateways": ["istio-system/edge"],
                      "http": [{"route": [{"destination": {"host": "web"}}]}]}},
        ],
    )


def istio_clean() -> dict:
    """STRICT mesh-wide, real authz rules, ISTIO_MUTUAL DR, https-redirecting gateway."""
    return S(
        namespaces=[
            {"metadata": m("istio-system")},
            {"metadata": m("prod", labels={"istio-injection": "enabled"})},
        ],
        istio_peer_authentications=[
            {"metadata": m("default", "istio-system"), "spec": {"mtls": {"mode": "STRICT"}}},
        ],
        istio_authorization_policies=[
            {"metadata": m("web-allow", "prod"),
             "spec": {"selector": {"matchLabels": {"app": "web"}},
                      "rules": [{"from": [{"source": {"principals": [
                          "cluster.local/ns/prod/sa/frontend"]}}],
                          "to": [{"operation": {"methods": ["GET"]}}]}]}},
        ],
        istio_destination_rules=[
            {"metadata": m("db-mtls", "prod"),
             "spec": {"host": "db.prod.svc.cluster.local",
                      "trafficPolicy": {"tls": {"mode": "ISTIO_MUTUAL"}}}},
        ],
        istio_gateways=[
            {"metadata": m("edge", "istio-system"),
             "spec": {"servers": [
                 {"port": {"number": 80, "name": "http", "protocol": "HTTP"},
                  "hosts": ["*"], "tls": {"httpsRedirect": True}},
                 {"port": {"number": 443, "name": "https", "protocol": "HTTPS"},
                  "hosts": ["shop.example.com"],
                  "tls": {"mode": "SIMPLE", "credentialName": "shop-cert"}}]}},
        ],
    )


def rbac_bad() -> dict:
    """cluster-admin SA, wildcard bound role, anonymous binding, bound default SA,
    legacy long-lived token secret (with a token value that must be dropped)."""
    return S(
        namespaces=[{"metadata": m("ci")}, {"metadata": m("app")}],
        service_accounts=[
            {"metadata": m("deployer", "ci")},
            {"metadata": m("default", "app")},
        ],
        sa_token_secrets=[
            {"metadata": {"name": "deployer-token-abc12", "namespace": "ci",
                          "annotations": {"kubernetes.io/service-account.name": "deployer"},
                          "creationTimestamp": "2023-04-01T00:00:00Z"},
             "type": "kubernetes.io/service-account-token",
             "data": {"token": TOKEN_B64, "ca.crt": "Zm9v"}},
        ],
        cluster_roles=[
            {"metadata": m("cluster-admin"),
             "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]},
            {"metadata": m("super"),
             "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]},
            {"metadata": m("view"),
             "rules": [{"verbs": ["get", "list"], "resources": ["pods"], "apiGroups": [""]}]},
        ],
        cluster_role_bindings=[
            {"metadata": m("ci-admin"),
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
             "subjects": [{"kind": "ServiceAccount", "name": "deployer", "namespace": "ci"}]},
            {"metadata": m("bob-super"),
             "roleRef": {"kind": "ClusterRole", "name": "super"},
             "subjects": [{"kind": "User", "name": "bob"}]},
            {"metadata": m("anon-view"),
             "roleRef": {"kind": "ClusterRole", "name": "view"},
             "subjects": [{"kind": "Group", "name": "system:unauthenticated"}]},
        ],
        roles=[
            {"metadata": m("editor", "app"),
             "rules": [{"verbs": ["get", "update"], "resources": ["configmaps"],
                        "apiGroups": [""]}]},
        ],
        role_bindings=[
            {"metadata": m("default-editor", "app"),
             "roleRef": {"kind": "Role", "name": "editor"},
             "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "app"}]},
        ],
    )


def exposure() -> dict:
    """Services / ingress / Gateway API / Linkerd surface — no Istio installed at all."""
    return S(
        namespaces=[{"metadata": m("prod")}, {"metadata": m("edge")}, {"metadata": m("lk")}],
        services=[
            {"metadata": m("web", "prod"),
             "spec": {"type": "LoadBalancer",
                      "ports": [{"name": "http", "port": 80, "protocol": "TCP"}]},
             "status": {"loadBalancer": {"ingress": [{"ip": "203.0.113.9"}]}}},
            {"metadata": m("api", "prod"),
             "spec": {"type": "LoadBalancer",
                      "ports": [{"port": 8443, "appProtocol": "http"}]}},
            {"metadata": m("tls", "prod"),
             "spec": {"type": "LoadBalancer",
                      "ports": [{"port": 443, "appProtocol": "https"}]}},
            {"metadata": m("np", "prod"),
             "spec": {"type": "NodePort", "ports": [{"port": 8080, "nodePort": 30080}]}},
            {"metadata": m("internal", "prod"),
             "spec": {"type": "ClusterIP", "ports": [{"port": 80}]}},
        ],
        ingresses=[
            {"metadata": m("shop", "prod"),
             "spec": {"rules": [{"host": "shop.example.com", "http": {"paths": [
                 {"backend": {"service": {"name": "web", "port": {"number": 80}}}}]}}]}},
            {"metadata": m("secure", "prod"),
             "spec": {"tls": [{"hosts": ["s.example.com"], "secretName": "s-tls"}],
                      "rules": [{"host": "s.example.com"}]}},
        ],
        gateway_classes=[
            {"metadata": m("envoy"),
             "spec": {"controllerName": "gateway.envoyproxy.io/gatewayclass-controller"}},
        ],
        gateways=[
            {"metadata": m("plain", "edge"),
             "spec": {"gatewayClassName": "envoy",
                      "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]}},
            {"metadata": m("mixed", "edge"),
             "spec": {"gatewayClassName": "envoy", "listeners": [
                 {"name": "http", "port": 80, "protocol": "HTTP"},
                 {"name": "https", "port": 443, "protocol": "HTTPS",
                  "tls": {"mode": "Terminate", "certificateRefs": [{"name": "cert"}]}}]}},
        ],
        http_routes=[
            {"metadata": m("r-plain", "edge"),
             "spec": {"parentRefs": [{"name": "plain"}],
                      "hostnames": ["a.example.com"], "rules": [{}]}},
            {"metadata": m("r-mixed", "edge"),
             "spec": {"parentRefs": [{"name": "mixed"}], "rules": [{}]}},
            {"metadata": m("r-section", "edge"),
             "spec": {"parentRefs": [{"name": "mixed", "sectionName": "http"}], "rules": [{}]}},
            {"metadata": m("r-orphan", "edge"),
             "spec": {"parentRefs": [{"name": "ghost"}], "rules": [{}]}},
        ],
        linkerd_servers=[
            {"metadata": m("api", "lk"),
             "spec": {"port": 8080, "podSelector": {"matchLabels": {"app": "api"}}}},
        ],
        linkerd_server_authorizations=[
            {"metadata": m("open", "lk"),
             "spec": {"server": {"name": "api"}, "client": {"unauthenticated": True}}},
            {"metadata": m("probe", "lk"),
             "spec": {"server": {"name": "api"},
                      "client": {"unauthenticated": True,
                                 "networks": [{"cidr": "10.0.0.0/8"}]}}},
            {"metadata": m("meshed", "lk"),
             "spec": {"server": {"name": "api"},
                      "client": {"meshTLS": {"serviceAccounts": [{"name": "web"}]}}}},
        ],
    )


# ── helpers ───────────────────────────────────────────────────────────────────
def build(snapshot):
    return _build_resources(snapshot)


def hits_for(rule_id, resources):
    d = next(x for x in DETECTORS if x.rule_id == rule_id)
    ctx = ScanContext(connection_id="c", tenant_id="t", resources=resources, config={})
    out = []
    for r in resources:
        if r.kind in d.kinds:
            out.extend(d.fn(r, ctx) or [])
    return out


def rule(rule_id):
    return next(x for x in DETECTORS if x.rule_id == rule_id)


# ── connector normalisation ───────────────────────────────────────────────────
def test_kinds_are_distinct_and_prefixed():
    for snap in (istio_bad(), rbac_bad(), exposure()):
        for r in build(snap).resources:
            assert r.kind.startswith(("k8s_", "mesh_")), r.kind
            assert r.kind not in ("broker", "user", "topic", "consumer", "node")


def test_all_edges_resolve_to_collected_resources():
    # An edge whose endpoint doesn't match an emitted Resource is silently dropped by
    # scan.py's _persist_edges — endpoints must exist.
    for snap in (istio_bad(), rbac_bad(), exposure()):
        col = build(snap)
        ext_ids = {r.ext_id for r in col.resources}
        for e in col.edges:
            assert e.src_ext_id in ext_ids and e.dst_ext_id in ext_ids, (e.src_ext_id, e.dst_ext_id)


def test_expected_edges_exist():
    col = build(istio_bad())
    kinds = {(e.src_ext_id, e.dst_ext_id, e.kind) for e in col.edges}
    assert ("mesh-pa-istio-system-default", "k8s-ns-istio-system", "applies_to") in kinds
    assert ("mesh-authz-prod-allow-all", "k8s-ns-prod", "applies_to") in kinds
    assert ("mesh-gw-istio-system-edge", "mesh-vs-prod-web", "serves") in kinds

    col = build(exposure())
    kinds = {(e.src_ext_id, e.dst_ext_id, e.kind) for e in col.edges}
    assert ("gwapi-gw-edge-plain", "gwapi-route-edge-r-plain", "serves") in kinds
    assert ("mesh-serverauthz-lk-open", "mesh-server-lk-api", "authorizes") in kinds

    col = build(rbac_bad())
    kinds = {(e.src_ext_id, e.dst_ext_id, e.kind) for e in col.edges}
    assert ("k8s-crb-ci-admin", "k8s-sa-ci-deployer", "binds") in kinds
    assert ("k8s-satoken-ci-deployer-token-abc12", "k8s-sa-ci-deployer", "token_of") in kinds


def test_secret_values_never_survive_collection():
    col = derive_identities("k8s", build(rbac_bad()))
    blob = json.dumps([{"labels": r.labels, "raw": r.raw, "name": r.name}
                      for r in col.resources])
    assert TOKEN_B64 not in blob
    sec = next(r for r in col.resources if r.kind == "k8s_sa_token_secret")
    assert sec.raw["has_token"] is True          # presence recorded, value dropped


def test_cluster_presence_flags():
    c = next(r for r in build(istio_bad()).resources if r.kind == "k8s_cluster")
    assert c.raw["istio_present"] and not c.raw["linkerd_present"]
    c = next(r for r in build(exposure()).resources if r.kind == "k8s_cluster")
    assert not c.raw["istio_present"]
    assert c.raw["linkerd_present"] and c.raw["gateway_api_present"]


def test_clusterip_services_are_not_collected():
    names = [r.raw["name"] for r in build(exposure()).resources if r.kind == "k8s_service"]
    assert "internal" not in names and "web" in names


def test_boring_bindings_are_skipped():
    snap = S(cluster_roles=[{"metadata": m("view"), "rules": [
                 {"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}]}],
             cluster_role_bindings=[{"metadata": m("humans-view"),
                                     "roleRef": {"kind": "ClusterRole", "name": "view"},
                                     "subjects": [{"kind": "Group", "name": "devs"}]}])
    assert not [r for r in build(snap).resources if r.kind == "k8s_cluster_role_binding"]


# ── Istio mTLS ────────────────────────────────────────────────────────────────
def test_mtls_permissive_fires_and_strict_is_silent():
    hits = hits_for("K8S.MESH.MTLS_NOT_STRICT", build(istio_bad()).resources)
    assert len(hits) == 1 and "PERMISSIVE" in hits[0].observation
    assert hits[0].severity is None            # rule default (high) applies
    assert hits_for("K8S.MESH.MTLS_NOT_STRICT", build(istio_clean()).resources) == []


def test_mtls_disable_is_critical():
    snap = S(namespaces=[{"metadata": m("istio-system")}],
             istio_peer_authentications=[{"metadata": m("off", "istio-system"),
                                          "spec": {"mtls": {"mode": "DISABLE"}}}])
    hits = hits_for("K8S.MESH.MTLS_NOT_STRICT", build(snap).resources)
    assert len(hits) == 1 and hits[0].severity == "critical"


def test_mtls_port_level_exemption_fires():
    snap = S(namespaces=[{"metadata": m("prod")}],
             istio_peer_authentications=[
                 {"metadata": m("api", "prod"),
                  "spec": {"selector": {"matchLabels": {"app": "api"}},
                           "mtls": {"mode": "STRICT"},
                           "portLevelMtls": {"8080": {"mode": "PERMISSIVE"}}}}])
    hits = hits_for("K8S.MESH.MTLS_NOT_STRICT", build(snap).resources)
    assert len(hits) == 1 and "portLevelMtls[8080]" in hits[0].observation


def test_no_mesh_wide_strict_fires_and_clean_is_silent():
    hits = hits_for("K8S.MESH.NO_MESH_WIDE_STRICT", build(istio_bad()).resources)
    assert len(hits) == 1 and hits[0].assessable
    assert hits_for("K8S.MESH.NO_MESH_WIDE_STRICT", build(istio_clean()).resources) == []
    # no Istio installed at all → nothing to say
    assert hits_for("K8S.MESH.NO_MESH_WIDE_STRICT", build(exposure()).resources) == []


def test_no_mesh_wide_strict_forbidden_is_not_assessable():
    snap = istio_bad()
    snap["istio_peer_authentications"] = forbidden()
    hits = hits_for("K8S.MESH.NO_MESH_WIDE_STRICT", build(snap).resources)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "403" in hits[0].observation


# ── Istio authorization ───────────────────────────────────────────────────────
def test_authz_allow_all_fires_on_empty_rule():
    hits = hits_for("K8S.MESH.AUTHZ_ALLOW_ALL", build(istio_bad()).resources)
    assert len(hits) == 1 and "empty rule" in hits[0].observation


def test_authz_wildcard_principal_fires():
    snap = S(namespaces=[{"metadata": m("prod")}],
             istio_authorization_policies=[
                 {"metadata": m("any-principal", "prod"),
                  "spec": {"rules": [{"from": [{"source": {"principals": ["*"]}}]}]}}])
    hits = hits_for("K8S.MESH.AUTHZ_ALLOW_ALL", build(snap).resources)
    assert len(hits) == 1 and 'principals ["*"]' in hits[0].observation


def test_authz_real_rules_deny_and_no_rules_are_silent():
    assert hits_for("K8S.MESH.AUTHZ_ALLOW_ALL", build(istio_clean()).resources) == []
    snap = S(namespaces=[{"metadata": m("prod")}],
             istio_authorization_policies=[
                 # DENY with empty rule = deny-all (hardening, not a hole)
                 {"metadata": m("deny-all", "prod"), "spec": {"action": "DENY", "rules": [{}]}},
                 # ALLOW with NO rules matches nothing in istio semantics
                 {"metadata": m("match-nothing", "prod"), "spec": {}}])
    assert hits_for("K8S.MESH.AUTHZ_ALLOW_ALL", build(snap).resources) == []


def test_meshed_namespace_without_authz_policy_fires():
    hits = hits_for("K8S.MESH.NS_NO_AUTHZ_POLICY", build(istio_bad()).resources)
    # payments is injected (istio.io/rev) with no policy; prod has one; dev isn't meshed
    assert len(hits) == 1 and "payments" in hits[0].observation
    assert hits_for("K8S.MESH.NS_NO_AUTHZ_POLICY", build(istio_clean()).resources) == []


def test_mesh_wide_authz_policy_in_root_namespace_covers_all():
    snap = istio_bad()
    snap["istio_authorization_policies"]["items"].append(
        {"metadata": m("deny-default", "istio-system"), "spec": {"action": "DENY", "rules": []}})
    assert hits_for("K8S.MESH.NS_NO_AUTHZ_POLICY", build(snap).resources) == []


# ── DestinationRule / Gateways ────────────────────────────────────────────────
def test_dr_tls_disable_fires_and_mutual_is_silent():
    hits = hits_for("K8S.MESH.DR_TLS_DISABLE", build(istio_bad()).resources)
    assert len(hits) == 1 and "DISABLE" in hits[0].observation
    assert hits_for("K8S.MESH.DR_TLS_DISABLE", build(istio_clean()).resources) == []


def test_dr_subset_tls_disable_fires():
    snap = S(namespaces=[{"metadata": m("prod")}],
             istio_destination_rules=[
                 {"metadata": m("canary", "prod"),
                  "spec": {"host": "svc", "subsets": [
                      {"name": "v2", "trafficPolicy": {"tls": {"mode": "DISABLE"}}}]}}])
    hits = hits_for("K8S.MESH.DR_TLS_DISABLE", build(snap).resources)
    assert len(hits) == 1 and "subsets[0]" in hits[0].detail


def test_istio_gateway_plaintext_wildcard_is_high_and_redirect_is_silent():
    hits = hits_for("K8S.MESH.GATEWAY_PLAINTEXT", build(istio_bad()).resources)
    assert len(hits) == 1 and hits[0].severity == "high"      # hosts ["*"]
    assert hits_for("K8S.MESH.GATEWAY_PLAINTEXT", build(istio_clean()).resources) == []


# ── Linkerd ───────────────────────────────────────────────────────────────────
def test_linkerd_unauthenticated_fires_meshtls_is_silent():
    hits = hits_for("K8S.MESH.LINKERD_UNAUTHENTICATED", build(exposure()).resources)
    assert len(hits) == 2                                     # open + probe, not meshed
    by_name = {h.source_ref["name"]: h for h in hits}
    assert by_name["open"].severity == "high"                 # unrestricted networks
    assert by_name["probe"].severity is None                  # node-CIDR scoped → rule default


# ── Gateway API ───────────────────────────────────────────────────────────────
def test_gwapi_plaintext_listeners_fire():
    hits = hits_for("K8S.GWAPI.LISTENER_PLAINTEXT", build(exposure()).resources)
    assert len(hits) == 2                                     # plain.http + mixed.http
    assert all("protocol HTTP" in h.observation for h in hits)


def test_gwapi_https_listener_is_silent():
    snap = S(gateways=[{"metadata": m("secure", "edge"),
                        "spec": {"gatewayClassName": "envoy", "listeners": [
                            {"name": "https", "port": 443, "protocol": "HTTPS",
                             "tls": {"mode": "Terminate"}}]}}])
    assert hits_for("K8S.GWAPI.LISTENER_PLAINTEXT", build(snap).resources) == []


def test_gwapi_route_plaintext_only():
    hits = hits_for("K8S.GWAPI.ROUTE_PLAINTEXT_ONLY", build(exposure()).resources)
    fired = {h.source_ref["name"] for h in hits}
    # r-plain: gateway has only HTTP; r-section: pinned to the HTTP listener by sectionName.
    # r-mixed can attach to the HTTPS listener; r-orphan's parent wasn't collected.
    assert fired == {"r-plain", "r-section"}


# ── Ingress / Services ────────────────────────────────────────────────────────
def test_ingress_without_tls_fires_with_tls_silent():
    hits = hits_for("K8S.INGRESS.NO_TLS", build(exposure()).resources)
    assert len(hits) == 1 and "shop.example.com" in hits[0].observation


def test_default_backend_only_ingress_is_silent():
    snap = S(ingresses=[{"metadata": m("fallback", "prod"),
                         "spec": {"defaultBackend": {"service": {"name": "web"}}}}])
    assert hits_for("K8S.INGRESS.NO_TLS", build(snap).resources) == []


def test_loadbalancer_plaintext_fires_https_silent():
    hits = hits_for("K8S.SVC.LB_PLAINTEXT", build(exposure()).resources)
    names = sorted(h.source_ref["name"] for h in hits)
    assert names == ["api", "web"]                 # appProtocol=http + port 80; tls svc silent
    assert any("203.0.113.9" in h.observation for h in hits)


def test_nodeport_fires_low_loadbalancer_silent():
    hits = hits_for("K8S.SVC.NODEPORT_EXPOSED", build(exposure()).resources)
    assert len(hits) == 1 and "30080" in hits[0].observation
    assert rule("K8S.SVC.NODEPORT_EXPOSED").severity == "low"


# ── RBAC / ServiceAccounts ────────────────────────────────────────────────────
def test_sa_cluster_admin_is_critical_user_is_high():
    resources = build(rbac_bad()).resources
    hits = hits_for("K8S.RBAC.SA_CLUSTER_ADMIN", resources)
    assert len(hits) == 1
    assert hits[0].severity is None                            # SA subject → rule default
    assert rule("K8S.RBAC.SA_CLUSTER_ADMIN").severity == "critical"

    snap = S(cluster_roles=[{"metadata": m("cluster-admin"),
                             "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]}],
             cluster_role_bindings=[{"metadata": m("root-alice"),
                                     "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                                     "subjects": [{"kind": "User", "name": "alice"}]}])
    hits = hits_for("K8S.RBAC.SA_CLUSTER_ADMIN", build(snap).resources)
    assert len(hits) == 1 and hits[0].severity == "high"


def test_wildcard_bound_fires_and_excludes_cluster_admin():
    hits = hits_for("K8S.RBAC.WILDCARD_BOUND", build(rbac_bad()).resources)
    assert len(hits) == 1 and "super" in hits[0].observation   # ci-admin excluded (rule 13's)
    assert "['*']" in hits[0].observation or "verbs=['*']" in hits[0].observation


def test_non_wildcard_binding_is_silent():
    # the app/default editor RoleBinding is emitted (SA subject) but carries no */* rule
    resources = build(rbac_bad()).resources
    rb = [r for r in resources if r.kind == "k8s_role_binding"]
    assert len(rb) == 1 and rb[0].raw["wildcard_rules"] is False
    assert all("default-editor" not in h.observation
               for h in hits_for("K8S.RBAC.WILDCARD_BOUND", resources))


def test_anonymous_binding_is_critical_all_authenticated_high():
    hits = hits_for("K8S.RBAC.ANONYMOUS_BOUND", build(rbac_bad()).resources)
    assert len(hits) == 1 and hits[0].severity is None         # unauthenticated → default critical
    snap = S(cluster_roles=[{"metadata": m("view"), "rules": [
                 {"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}]}],
             cluster_role_bindings=[{"metadata": m("everyone"),
                                     "roleRef": {"kind": "ClusterRole", "name": "view"},
                                     "subjects": [{"kind": "Group",
                                                   "name": "system:authenticated"}]}])
    hits = hits_for("K8S.RBAC.ANONYMOUS_BOUND", build(snap).resources)
    assert len(hits) == 1 and hits[0].severity == "high"


def test_default_sa_bound_fires_and_opted_out_is_silent():
    hits = hits_for("K8S.SA.DEFAULT_BOUND", build(rbac_bad()).resources)
    assert len(hits) == 1 and "editor" in hits[0].observation

    snap = rbac_bad()
    for sa in snap["service_accounts"]["items"]:
        if sa["metadata"]["name"] == "default":
            sa["automountServiceAccountToken"] = False
    assert hits_for("K8S.SA.DEFAULT_BOUND", build(snap).resources) == []

    # a default SA with automount on but NO binding grants nothing → silent
    snap = S(service_accounts=[{"metadata": m("default", "quiet")}])
    assert hits_for("K8S.SA.DEFAULT_BOUND", build(snap).resources) == []


def test_legacy_token_secret_fires_and_absent_is_silent():
    hits = hits_for("K8S.SA.LEGACY_TOKEN_SECRET", build(rbac_bad()).resources)
    assert len(hits) == 1 and "deployer" in hits[0].observation
    assert TOKEN_B64 not in hits[0].observation + hits[0].detail
    assert hits_for("K8S.SA.LEGACY_TOKEN_SECRET", build(istio_clean()).resources) == []


# ── coverage honesty ──────────────────────────────────────────────────────────
def test_collect_forbidden_files_not_assessable():
    snap = istio_bad()
    snap["cluster_role_bindings"] = forbidden()
    snap["sa_token_secrets"] = forbidden()
    hits = hits_for("K8S.COLLECT.FORBIDDEN", build(snap).resources)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "cluster_role_bindings" in hits[0].observation
    assert "sa_token_secrets" in hits[0].observation


def test_collect_forbidden_silent_when_readable():
    assert hits_for("K8S.COLLECT.FORBIDDEN", build(istio_bad()).resources) == []
    assert hits_for("K8S.COLLECT.FORBIDDEN", build(exposure()).resources) == []


# ── every rule carries remediation ────────────────────────────────────────────
def test_every_fired_hit_has_remediation_and_observation():
    for snap in (istio_bad(), rbac_bad(), exposure()):
        resources = build(snap).resources
        ctx = ScanContext(connection_id="c", tenant_id="t", resources=resources, config={})
        for d in DETECTORS:
            if not d.rule_id.startswith("K8S."):
                continue
            for r in resources:
                if r.kind not in d.kinds:
                    continue
                for h in (d.fn(r, ctx) or []):
                    assert h.observation.strip(), d.rule_id
                    assert h.remediation.strip(), d.rule_id


# ── K8S.MESH.JWT_NOT_ENFORCED ────────────────────────────────────────────────
def _jwt_snap(policies, ra_selector=None):
    ra_spec = {"jwtRules": [{"issuer": "https://auth.acme.io"}]}
    if ra_selector:
        ra_spec["selector"] = {"matchLabels": ra_selector}
    return S(namespaces=[{"metadata": m("istio-system")},
                         {"metadata": m("api", labels={"istio-injection": "enabled"})}],
             istio_request_authentications=[{"metadata": m("jwt", "api"), "spec": ra_spec}],
             istio_authorization_policies=policies)


def test_jwt_without_requiring_policy_fires():
    hits = hits_for("K8S.MESH.JWT_NOT_ENFORCED", build(_jwt_snap([])).resources)
    assert len(hits) == 1 and "no token" in hits[0].observation
    # A policy that does not mention request principals does not enforce either.
    other = [{"metadata": m("allow-ns", "api"),
              "spec": {"rules": [{"from": [{"source": {"namespaces": ["web"]}}]}]}}]
    assert len(hits_for("K8S.MESH.JWT_NOT_ENFORCED", build(_jwt_snap(other)).resources)) == 1


def test_jwt_with_deny_not_request_principals_is_silent():
    deny = [{"metadata": m("require-jwt", "api"), "spec": {
        "action": "DENY", "rules": [{"from": [{"source": {"notRequestPrincipals": ["*"]}}]}]}}]
    assert hits_for("K8S.MESH.JWT_NOT_ENFORCED", build(_jwt_snap(deny)).resources) == []
    allow = [{"metadata": m("allow-jwt", "api"), "spec": {
        "selector": {"matchLabels": {"app": "orders"}},
        "rules": [{"from": [{"source": {"requestPrincipals": ["https://auth.acme.io/*"]}}]}]}}]
    assert hits_for("K8S.MESH.JWT_NOT_ENFORCED",
                    build(_jwt_snap(allow, {"app": "orders"})).resources) == []


def test_jwt_policy_on_other_workload_does_not_count():
    other_app = [{"metadata": m("allow-jwt", "api"), "spec": {
        "selector": {"matchLabels": {"app": "billing"}},
        "rules": [{"from": [{"source": {"requestPrincipals": ["*"]}}]}]}}]
    assert len(hits_for("K8S.MESH.JWT_NOT_ENFORCED",
                        build(_jwt_snap(other_app, {"app": "orders"})).resources)) == 1


def test_jwt_rule_silent_when_policies_unreadable():
    snap = _jwt_snap([])
    snap["istio_authorization_policies"] = forbidden()
    assert hits_for("K8S.MESH.JWT_NOT_ENFORCED", build(snap).resources) == []


# ── K8S.MESH.AUTH_ONLY_AT_GATEWAY ────────────────────────────────────────────
_GW_JWT = {"metadata": m("require-jwt", "istio-system"), "spec": {
    "selector": {"matchLabels": {"istio": "ingressgateway"}}, "action": "DENY",
    "rules": [{"from": [{"source": {"notRequestPrincipals": ["*"]}}]}]}}


def _gw_snap(policies):
    return S(namespaces=[{"metadata": m("istio-system")},
                         {"metadata": m("shop", labels={"istio-injection": "enabled"})}],
             istio_virtual_services=[{"metadata": m("shop-vs", "shop"), "spec": {
                 "gateways": ["istio-system/public-gw"], "hosts": ["shop.acme.io"],
                 "http": [{"route": [{"destination": {"host": "orders.shop.svc.cluster.local"}}]}]}}],
             istio_authorization_policies=policies)


def test_gateway_only_auth_fires_when_backend_unguarded():
    hits = hits_for("K8S.MESH.AUTH_ONLY_AT_GATEWAY", build(_gw_snap([_GW_JWT])).resources)
    assert len(hits) == 1 and "shop" in hits[0].observation


def test_gateway_only_auth_silent_when_backend_has_policy_or_no_gateway_jwt():
    backend = {"metadata": m("shop-callers", "shop"), "spec": {
        "rules": [{"from": [{"source": {"principals": ["cluster.local/ns/istio-system/sa/gw"]}}]}]}}
    assert hits_for("K8S.MESH.AUTH_ONLY_AT_GATEWAY", build(_gw_snap([_GW_JWT, backend])).resources) == []
    assert hits_for("K8S.MESH.AUTH_ONLY_AT_GATEWAY", build(_gw_snap([])).resources) == []
    deny_all = {"metadata": m("deny", "shop"), "spec": {}}
    assert hits_for("K8S.MESH.AUTH_ONLY_AT_GATEWAY", build(_gw_snap([_GW_JWT, deny_all])).resources) == []
