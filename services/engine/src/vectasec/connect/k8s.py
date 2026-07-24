"""Kubernetes connector — read-only posture collection for the in-cluster integration layer.

One K8s API connection is the highest-leverage connector in the product: the same read unlocks
posture for Istio (PeerAuthentication / AuthorizationPolicy / DestinationRule / Gateway /
VirtualService), Linkerd (Server / ServerAuthorization), Gateway API (GatewayClass / Gateway /
HTTPRoute — the shared surface of Envoy Gateway, Traefik v3, Istio's gateway), classic Ingress,
Service exposure (LoadBalancer / NodePort), and the cluster's non-human identities
(ServiceAccounts, their token secrets, RBAC bindings). Only LIST/GET verbs are ever issued.

Credential-reduction discipline (same contract as the RabbitMQ/Redis connectors): the token
`data` of a service-account token Secret NEVER leaves `_secret_meta` — the snapshot holds only
name/namespace/annotations/creation time and a has_token boolean. No secret value is stored,
logged, or returned.

Kinds are DISTINCT and prefixed `k8s_` / `mesh_` (k8s_service_account, mesh_peer_authentication…)
— never the generic `broker`/`user` kinds, which would drag the Kafka/RabbitMQ rulepacks across
Kubernetes resources.

Missing CRDs are normal, not an error: a cluster without Istio answers 404 on the
security.istio.io group and simply yields fewer kinds. A 403 is recorded as outcome "forbidden"
so the rulepack can decline to assess (never "pass") what RBAC hid from it.

The connector is split so the whole normalisation is testable offline:
  collect(config)          talks to the cluster, assembles a plain-dict `snapshot`
  _build_resources(...)    pure: snapshot -> Collected (golden-fixture tested)

Dev-cluster note (kind): `kind create cluster --name vectasec-dev` writes a context named
`kind-vectasec-dev` into ~/.kube/config; point this connector at it with
config {"kubeconfig": "~/.kube/config", "context": "kind-vectasec-dev"}. Install Istio with
`istioctl install --set profile=demo` to light up the mesh_* kinds. Nothing is added to
docker-compose on purpose — a cluster is not a container.
"""
from ..contracts import Collected, Edge, Resource
from ..identity import identity_extractor, _mk_credential, _mk_grant, _mk_identity
from ..registry import ConnectorField, connector

# snapshot section keys, grouped by the stack they witness. Presence = the API group answered
# (ok) or exists-but-denied (forbidden); a 404 means the CRDs are simply not installed.
_ISTIO_KEYS = ("istio_peer_authentications", "istio_authorization_policies",
               "istio_destination_rules", "istio_gateways", "istio_virtual_services")
_LINKERD_KEYS = ("linkerd_servers", "linkerd_server_authorizations")
_GWAPI_KEYS = ("gateway_classes", "gateways", "http_routes")
_CORE_KEYS = ("namespaces", "services", "service_accounts", "sa_token_secrets", "ingresses",
              "cluster_role_bindings", "role_bindings", "cluster_roles", "roles")
# Runtime admission/egress posture axis — the same read-only K8s connection also witnesses
# NetworkPolicy (default-deny / allow-all), the admission-webhook gate (presence + failurePolicy)
# and, best-effort, a CNI-level egress policy engine (Cilium CRDs). PodSecurity enforce level
# rides on the existing k8s_namespace labels rather than a distinct kind.
_ADMISSION_KEYS = ("network_policies", "validating_webhooks", "mutating_webhooks",
                   "cilium_network_policies", "cilium_clusterwide_network_policies")

_SA_TOKEN_TYPE = "kubernetes.io/service-account-token"


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _section(snapshot: dict, key: str) -> tuple:
    sec = snapshot.get(key) or {}
    return sec.get("outcome", "absent"), (sec.get("items") or [])


def _meta(item: dict) -> tuple:
    md = (item or {}).get("metadata") or {}
    return md.get("name") or "", md.get("namespace") or ""


def _secret_meta(item: dict) -> dict:
    """Reduce a V1Secret (JSON-wire shape) to metadata. The token value dies here — `data` is
    read only to learn WHICH keys exist, never copied."""
    md = (item or {}).get("metadata") or {}
    ann = md.get("annotations") or {}
    data = (item or {}).get("data") or {}
    return {
        "name": md.get("name"),
        "namespace": md.get("namespace"),
        "type": (item or {}).get("type"),
        "service_account": ann.get("kubernetes.io/service-account.name"),
        "created": md.get("creationTimestamp"),
        "has_token": "token" in data,       # boolean, never the value
    }


def _reduce_rules(rules: list) -> list:
    return [{
        "verbs": r.get("verbs") or [],
        "resources": r.get("resources") or [],
        "api_groups": r.get("apiGroups") or [],
        "non_resource_urls": r.get("nonResourceURLs") or [],
    } for r in (rules or [])]


def _wildcard_rules(rules: list) -> bool:
    return any("*" in (r.get("verbs") or []) and "*" in (r.get("resources") or [])
               for r in (rules or []))


def _netpol_direction(rules, applies: bool, peer_key: str) -> str:
    """One direction of a NetworkPolicy, in policy terms:
      none      — this policyType does not apply to the selected pods
      deny_all  — the direction applies but carries NO allow rules ([] or absent) → default-deny
      allow_all — a rule with no peer (`from`/`to`) and no `ports` matches every source/dest
      restricted— rules exist and each names concrete peers/ports
    (an empty `{}` rule, or `{from: []}`, is the canonical allow-everything rule)."""
    if not applies:
        return "none"
    if not rules:                                     # None or [] → no allow rules
        return "deny_all"
    if any(not (r or {}).get(peer_key) and not (r or {}).get("ports") for r in rules):
        return "allow_all"
    return "restricted"


def _netpol_semantics(spec: dict) -> dict:
    """Reduce a NetworkPolicy spec to the booleans the detectors read. podSelector `{}` (or
    missing) selects every pod in the namespace; policyTypes is inferred the way the API server
    infers it when omitted (Ingress always applies; Egress only when an egress section exists)."""
    ps = spec.get("podSelector") or {}
    selects_all = not (ps.get("matchLabels") or ps.get("matchExpressions"))
    ingress, egress = spec.get("ingress"), spec.get("egress")
    declared = spec.get("policyTypes")
    if declared is not None:
        types = set(declared)
    else:
        types = {"Ingress"} | ({"Egress"} if egress is not None else set())
    ing = _netpol_direction(ingress, "Ingress" in types, "from")
    egr = _netpol_direction(egress, "Egress" in types, "to")
    return {
        "selects_all_pods": bool(selects_all),
        "policy_types": sorted(types),
        "ingress_effect": ing,
        "egress_effect": egr,
        "default_deny_ingress": bool(selects_all and ing == "deny_all"),
        "default_deny_egress": bool(selects_all and egr == "deny_all"),
        "allow_all_ingress": bool(selects_all and ing == "allow_all"),
        "allow_all_egress": bool(selects_all and egr == "allow_all"),
    }


def _anonymous_subject(subjects: list) -> bool:
    for s in subjects or []:
        if s.get("kind") == "User" and s.get("name") == "system:anonymous":
            return True
        if s.get("kind") == "Group" and s.get("name") in ("system:unauthenticated",
                                                          "system:authenticated"):
            return True
    return False


def _sa_subjects(subjects: list, default_ns: str = "") -> list:
    out = []
    for s in subjects or []:
        if s.get("kind") == "ServiceAccount" and s.get("name"):
            out.append({"name": s["name"], "namespace": s.get("namespace") or default_ns})
        elif s.get("kind") == "Group" and str(s.get("name") or "").startswith("system:serviceaccounts"):
            out.append({"name": s["name"], "namespace": "", "group": True})
    return out


def _build_resources(snapshot: dict, root_namespace: str = "istio-system") -> Collected:
    """Pure normalisation: plain-dict snapshot (JSON-wire K8s shapes) -> Collected."""
    resources: list[Resource] = []
    edges: list[Edge] = []

    outcomes = {k: _section(snapshot, k)[0]
                for k in (*_CORE_KEYS, *_ISTIO_KEYS, *_LINKERD_KEYS, *_GWAPI_KEYS,
                          *_ADMISSION_KEYS)}

    def present(keys) -> bool:
        # forbidden still proves the API group EXISTS (403, not 404) — the stack is present,
        # merely unreadable, and the rulepack must say "not assessable", not "not installed".
        return any(outcomes[k] in ("ok", "forbidden") for k in keys)

    # ── the cluster itself: version + collection outcomes (the not-assessable anchor) ──
    resources.append(Resource(
        kind="k8s_cluster",
        name=snapshot.get("cluster_name") or "cluster",
        ext_id="k8s-cluster",
        labels={"version": str(snapshot.get("version") or "?")},
        raw={
            "version": snapshot.get("version"),
            "outcomes": outcomes,
            "istio_present": present(_ISTIO_KEYS),
            "linkerd_present": present(_LINKERD_KEYS),
            "gateway_api_present": present(_GWAPI_KEYS),
            # runtime admission/egress posture axis
            "admission_present": present(("validating_webhooks", "mutating_webhooks")),
            "egress_crd_present": present(("cilium_network_policies",
                                           "cilium_clusterwide_network_policies")),
            "istio_root_namespace": root_namespace,
        },
    ))

    # ── namespaces (mesh membership lives on their labels/annotations) ──
    _, ns_items = _section(snapshot, "namespaces")
    for item in ns_items:
        name, _ = _meta(item)
        if not name:
            continue
        labels = (item.get("metadata") or {}).get("labels") or {}
        ann = (item.get("metadata") or {}).get("annotations") or {}
        istio_injection = labels.get("istio-injection") == "enabled" or "istio.io/rev" in labels
        linkerd_injection = ann.get("linkerd.io/inject") == "enabled"
        # PodSecurity admission enforce level rides on the namespace label (no distinct kind).
        pss_enforce = labels.get("pod-security.kubernetes.io/enforce")
        resources.append(Resource(
            kind="k8s_namespace", name=name, ext_id=f"k8s-ns-{name}",
            labels={"istio_injection": "true" if istio_injection else "false",
                    "linkerd_injection": "true" if linkerd_injection else "false",
                    "pss_enforce": pss_enforce or "unset"},
            raw={"name": name, "labels": labels,
                 "istio_injection": istio_injection, "linkerd_injection": linkerd_injection,
                 "pss_enforce": pss_enforce,
                 "pss_enforce_version": labels.get("pod-security.kubernetes.io/enforce-version")},
        ))

    # ── Services — only the exposed types; a ClusterIP service is not an exposure surface ──
    _, svc_items = _section(snapshot, "services")
    for item in svc_items:
        name, ns = _meta(item)
        spec = item.get("spec") or {}
        stype = spec.get("type") or "ClusterIP"
        if stype not in ("LoadBalancer", "NodePort"):
            continue
        ports = [{"name": p.get("name"), "port": p.get("port"), "node_port": p.get("nodePort"),
                  "protocol": p.get("protocol"), "app_protocol": p.get("appProtocol")}
                 for p in (spec.get("ports") or [])]
        lb = ((item.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []
        resources.append(Resource(
            kind="k8s_service", name=f"{ns}/{name}", ext_id=f"k8s-svc-{ns}-{name}",
            namespace=ns, labels={"type": stype},
            raw={"name": name, "namespace": ns, "type": stype, "ports": ports,
                 "external_ips": spec.get("externalIPs") or [],
                 "load_balancer_ingress": [e.get("ip") or e.get("hostname") for e in lb]},
        ))

    # ── ServiceAccounts + legacy token secrets (metadata ONLY — see _secret_meta) ──
    _, sa_items = _section(snapshot, "service_accounts")
    for item in sa_items:
        name, ns = _meta(item)
        if not name:
            continue
        resources.append(Resource(
            kind="k8s_service_account", name=f"{ns}/{name}", ext_id=f"k8s-sa-{ns}-{name}",
            namespace=ns,
            labels={"is_default": "true" if name == "default" else "false"},
            raw={"name": name, "namespace": ns, "is_default": name == "default",
                 "automount": item.get("automountServiceAccountToken"),
                 "secrets": [s.get("name") for s in (item.get("secrets") or []) if s.get("name")]},
        ))

    _, sec_items = _section(snapshot, "sa_token_secrets")
    for item in sec_items:
        meta = item if set(item) >= {"name", "namespace", "type"} else _secret_meta(item)
        if meta.get("type") != _SA_TOKEN_TYPE or not meta.get("name"):
            continue
        name, ns = meta["name"], meta.get("namespace") or ""
        resources.append(Resource(
            kind="k8s_sa_token_secret", name=f"{ns}/{name}", ext_id=f"k8s-satoken-{ns}-{name}",
            namespace=ns, labels={"service_account": meta.get("service_account") or "?"},
            raw=meta,
        ))
        if meta.get("service_account"):
            edges.append(Edge(src_ext_id=f"k8s-satoken-{ns}-{name}",
                              dst_ext_id=f"k8s-sa-{ns}-{meta['service_account']}",
                              kind="token_of"))

    # ── Ingresses ──
    _, ing_items = _section(snapshot, "ingresses")
    for item in ing_items:
        name, ns = _meta(item)
        spec = item.get("spec") or {}
        tls = [{"hosts": t.get("hosts") or [], "secret_name": t.get("secretName")}
               for t in (spec.get("tls") or [])]
        rules = []
        for r in spec.get("rules") or []:
            paths = (r.get("http") or {}).get("paths") or []
            rules.append({"host": r.get("host"),
                          "services": [((p.get("backend") or {}).get("service") or {}).get("name")
                                       for p in paths]})
        resources.append(Resource(
            kind="k8s_ingress", name=f"{ns}/{name}", ext_id=f"k8s-ing-{ns}-{name}",
            namespace=ns, labels={"tls": "true" if tls else "false"},
            raw={"name": name, "namespace": ns,
                 "ingress_class": spec.get("ingressClassName"), "tls": tls, "rules": rules},
        ))

    # ── NetworkPolicies — reduced to default-deny / allow-all semantics (the egress axis) ──
    _, np_items = _section(snapshot, "network_policies")
    for item in np_items:
        name, ns = _meta(item)
        if not name:
            continue
        sem = _netpol_semantics(item.get("spec") or {})
        resources.append(Resource(
            kind="k8s_networkpolicy", name=f"{ns}/{name}", ext_id=f"k8s-netpol-{ns}-{name}",
            namespace=ns,
            labels={"selects_all_pods": "true" if sem["selects_all_pods"] else "false"},
            raw={"name": name, "namespace": ns, **sem},
        ))

    # ── Admission webhooks — presence + failurePolicy (the bypassable-gate signal). The v1
    #    default for an unset failurePolicy is Fail, so only an explicit Ignore reads as fail-open.
    def _webhooks(key: str, wtype: str, prefix: str):
        _, items = _section(snapshot, key)
        for item in items:
            name, _ = _meta(item)
            if not name:
                continue
            hooks = [{"name": w.get("name"),
                      "failure_policy": w.get("failurePolicy") or "Fail",
                      "side_effects": w.get("sideEffects"),
                      "timeout_seconds": w.get("timeoutSeconds"),
                      "match_policy": w.get("matchPolicy"),
                      "rules_count": len(w.get("rules") or [])}
                     for w in (item.get("webhooks") or [])]
            resources.append(Resource(
                kind="k8s_admission_webhook", name=name, ext_id=f"{prefix}-{name}",
                labels={"webhook_type": wtype,
                        "fail_open": "true" if any(h["failure_policy"] == "Ignore"
                                                   for h in hooks) else "false"},
                raw={"name": name, "webhook_type": wtype, "webhooks": hooks},
            ))

    _webhooks("validating_webhooks", "validating", "k8s-vwh")
    _webhooks("mutating_webhooks", "mutating", "k8s-mwh")

    # ── RBAC: resolve each binding's role rules INLINE so detectors read evidence, not names ──
    _, cr_items = _section(snapshot, "cluster_roles")
    cluster_role_rules = {}
    for item in cr_items:
        name, _ = _meta(item)
        cluster_role_rules[name] = _reduce_rules(item.get("rules"))
    _, role_items = _section(snapshot, "roles")
    role_rules = {}
    for item in role_items:
        name, ns = _meta(item)
        role_rules[(ns, name)] = _reduce_rules(item.get("rules"))

    def _emit_binding(item: dict, cluster_scoped: bool):
        name, ns = _meta(item)
        role_ref = item.get("roleRef") or {}
        subjects = item.get("subjects") or []
        if role_ref.get("kind") == "Role":
            rules = role_rules.get((ns, role_ref.get("name")))
        else:
            rules = cluster_role_rules.get(role_ref.get("name"))
        wildcard = _wildcard_rules(rules or [])
        interesting = (role_ref.get("name") == "cluster-admin" or wildcard
                       or _anonymous_subject(subjects) or _sa_subjects(subjects, ns))
        if not interesting:
            return          # boring bindings (view to a human group…) are not posture surface
        kind = "k8s_cluster_role_binding" if cluster_scoped else "k8s_role_binding"
        ext = f"k8s-crb-{name}" if cluster_scoped else f"k8s-rb-{ns}-{name}"
        resources.append(Resource(
            kind=kind, name=name if cluster_scoped else f"{ns}/{name}", ext_id=ext,
            namespace=None if cluster_scoped else ns,
            labels={"role": str(role_ref.get("name") or "?"),
                    "wildcard_rules": "true" if wildcard else "false"},
            raw={"name": name, "namespace": None if cluster_scoped else ns,
                 "role_ref": {"kind": role_ref.get("kind"), "name": role_ref.get("name")},
                 "subjects": [{"kind": s.get("kind"), "name": s.get("name"),
                               "namespace": s.get("namespace")} for s in subjects],
                 "role_rules": rules or [],
                 "role_found": rules is not None,
                 "wildcard_rules": wildcard},
        ))
        for sa in _sa_subjects(subjects, ns):
            if not sa.get("group") and sa.get("namespace"):
                edges.append(Edge(src_ext_id=ext,
                                  dst_ext_id=f"k8s-sa-{sa['namespace']}-{sa['name']}",
                                  kind="binds"))

    _, crb_items = _section(snapshot, "cluster_role_bindings")
    for item in crb_items:
        _emit_binding(item, cluster_scoped=True)
    _, rb_items = _section(snapshot, "role_bindings")
    for item in rb_items:
        _emit_binding(item, cluster_scoped=False)

    # ── Istio CRDs ──
    def _mesh(kind: str, key: str, prefix: str, extra=None):
        _, items = _section(snapshot, key)
        for item in items:
            name, ns = _meta(item)
            spec = item.get("spec") or {}
            raw = {"name": name, "namespace": ns, "spec": spec}
            if extra:
                raw.update(extra(name, ns, spec))
            resources.append(Resource(
                kind=kind, name=f"{ns}/{name}" if ns else name,
                ext_id=f"{prefix}-{ns}-{name}" if ns else f"{prefix}-{name}",
                namespace=ns or None, labels={}, raw=raw))

    _mesh("mesh_peer_authentication", "istio_peer_authentications", "mesh-pa",
          extra=lambda n, ns, spec: {
              "mesh_wide": ns == root_namespace and not spec.get("selector")})
    _mesh("mesh_authorization_policy", "istio_authorization_policies", "mesh-authz")
    _mesh("mesh_destination_rule", "istio_destination_rules", "mesh-dr")
    _mesh("mesh_gateway", "istio_gateways", "mesh-gw")
    _mesh("mesh_virtual_service", "istio_virtual_services", "mesh-vs")

    # policy → namespace edges (the "what governs this namespace" lens in the graph)
    ns_exts = {r.ext_id for r in resources if r.kind == "k8s_namespace"}
    for r in resources:
        if r.kind in ("mesh_peer_authentication", "mesh_authorization_policy"):
            dst = f"k8s-ns-{(r.raw or {}).get('namespace')}"
            if dst in ns_exts:
                edges.append(Edge(src_ext_id=r.ext_id, dst_ext_id=dst, kind="applies_to"))

    # Istio gateway → virtual service edges (VS spec.gateways references "ns/name" or "name")
    gw_exts = {r.ext_id for r in resources if r.kind == "mesh_gateway"}
    for r in resources:
        if r.kind != "mesh_virtual_service":
            continue
        for g in ((r.raw or {}).get("spec") or {}).get("gateways") or []:
            if g == "mesh":
                continue
            gns, _, gname = g.rpartition("/")
            gns = gns or (r.raw or {}).get("namespace")
            src = f"mesh-gw-{gns}-{gname}"
            if src in gw_exts:
                edges.append(Edge(src_ext_id=src, dst_ext_id=r.ext_id, kind="serves"))

    # ── Linkerd policy CRDs ──
    _mesh("mesh_server", "linkerd_servers", "mesh-server")
    _mesh("mesh_server_authorization", "linkerd_server_authorizations", "mesh-serverauthz")
    server_exts = {r.ext_id for r in resources if r.kind == "mesh_server"}
    for r in resources:
        if r.kind != "mesh_server_authorization":
            continue
        sname = ((((r.raw or {}).get("spec") or {}).get("server")) or {}).get("name")
        dst = f"mesh-server-{(r.raw or {}).get('namespace')}-{sname}"
        if sname and dst in server_exts:
            edges.append(Edge(src_ext_id=r.ext_id, dst_ext_id=dst, kind="authorizes"))

    # ── Gateway API ──
    _, gc_items = _section(snapshot, "gateway_classes")
    for item in gc_items:
        name, _ = _meta(item)
        spec = item.get("spec") or {}
        resources.append(Resource(
            kind="k8s_gateway_class", name=name, ext_id=f"gwapi-class-{name}",
            labels={"controller": str(spec.get("controllerName") or "?")},
            raw={"name": name, "controller": spec.get("controllerName")}))

    _, gw_items = _section(snapshot, "gateways")
    for item in gw_items:
        name, ns = _meta(item)
        spec = item.get("spec") or {}
        listeners = [{"name": l.get("name"), "port": l.get("port"),
                      "protocol": l.get("protocol"), "hostname": l.get("hostname"),
                      "has_tls": bool(l.get("tls")),
                      "tls_mode": (l.get("tls") or {}).get("mode")}
                     for l in (spec.get("listeners") or [])]
        resources.append(Resource(
            kind="k8s_gateway", name=f"{ns}/{name}", ext_id=f"gwapi-gw-{ns}-{name}",
            namespace=ns, labels={"class": str(spec.get("gatewayClassName") or "?")},
            raw={"name": name, "namespace": ns,
                 "gateway_class": spec.get("gatewayClassName"), "listeners": listeners}))

    gwapi_exts = {r.ext_id for r in resources if r.kind == "k8s_gateway"}
    _, route_items = _section(snapshot, "http_routes")
    for item in route_items:
        name, ns = _meta(item)
        spec = item.get("spec") or {}
        parents = [{"name": p.get("name"), "namespace": p.get("namespace") or ns,
                    "section_name": p.get("sectionName")}
                   for p in (spec.get("parentRefs") or [])]
        ext = f"gwapi-route-{ns}-{name}"
        resources.append(Resource(
            kind="k8s_http_route", name=f"{ns}/{name}", ext_id=ext, namespace=ns,
            labels={},
            raw={"name": name, "namespace": ns, "parent_refs": parents,
                 "hostnames": spec.get("hostnames") or [],
                 "rules_count": len(spec.get("rules") or [])}))
        for p in parents:
            src = f"gwapi-gw-{p['namespace']}-{p['name']}"
            if src in gwapi_exts:
                edges.append(Edge(src_ext_id=src, dst_ext_id=ext, kind="serves"))

    return Collected(resources=resources, edges=edges)


@connector("k8s", fields=[
    ConnectorField("kubeconfig", "Kubeconfig path", placeholder="~/.kube/config",
                   help="Path to a kubeconfig the engine/worker can read. Leave empty with "
                        "in_cluster=true to use the pod's mounted service-account, or set "
                        "api_server+token instead. Only LIST/GET is ever issued."),
    ConnectorField("context", "Kubeconfig context", placeholder="kind-vectasec-dev",
                   help="Optional context name inside the kubeconfig."),
    ConnectorField("api_server", "API server URL", placeholder="https://10.0.0.1:6443",
                   help="Direct token auth: the cluster API endpoint (used when no kubeconfig)."),
    ConnectorField("token", "Bearer token", secret=True,
                   help="A read-only ServiceAccount token (bind it to the built-in `view` "
                        "ClusterRole plus get/list on RBAC and the mesh CRD groups)."),
    ConnectorField("ca_cert", "CA certificate path", placeholder="/etc/vectasec/k8s-ca.crt",
                   help="CA bundle for the API server when using api_server+token."),
    ConnectorField("in_cluster", "In-cluster", placeholder="false",
                   help="'true' when the engine runs inside the target cluster."),
])
def collect(config: dict) -> Collected:
    # Local imports: importing vectasec must stay dependency-light (config.py contract).
    import os

    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config
    from kubernetes.client.exceptions import ApiException

    timeout = float(config.get("timeout") or 20)

    if _truthy(config.get("in_cluster")):
        k8s_config.load_incluster_config()
        api_client = k8s_client.ApiClient()
    elif (config.get("api_server") or "").strip():
        conf = k8s_client.Configuration()
        conf.host = config["api_server"].strip()
        token = (config.get("token") or "").strip()
        if token:
            conf.api_key = {"authorization": f"Bearer {token}"}
        ca = (config.get("ca_cert") or "").strip()
        if ca:
            conf.ssl_ca_cert = os.path.expanduser(ca)
        else:
            conf.verify_ssl = not _truthy(config.get("insecure_skip_tls_verify"))
        api_client = k8s_client.ApiClient(conf)
    else:
        path = os.path.expanduser((config.get("kubeconfig") or "").strip()) or None
        k8s_config.load_kube_config(config_file=path,
                                    context=(config.get("context") or "").strip() or None)
        api_client = k8s_client.ApiClient()

    core = k8s_client.CoreV1Api(api_client)
    net = k8s_client.NetworkingV1Api(api_client)
    rbac = k8s_client.RbacAuthorizationV1Api(api_client)
    admission = k8s_client.AdmissionregistrationV1Api(api_client)
    custom = k8s_client.CustomObjectsApi(api_client)

    def _call(fn, reduce=None, **kw) -> dict:
        """One LIST, outcome recorded honestly: 403 must never read as 'nothing there'."""
        try:
            resp = fn(_request_timeout=timeout, **kw)
            items = api_client.sanitize_for_serialization(resp).get("items") or []
            if reduce:
                items = [reduce(i) for i in items]
            return {"outcome": "ok", "items": items, "error": None}
        except ApiException as ex:
            outcome = {403: "forbidden", 404: "absent"}.get(ex.status, "error")
            return {"outcome": outcome, "items": [], "error": f"HTTP {ex.status}"}
        except Exception as ex:
            return {"outcome": "error", "items": [], "error": f"{type(ex).__name__}: {ex}"}

    def _crd(group: str, versions: tuple, plural: str) -> dict:
        """Cluster-wide CRD list, trying versions newest-first. 404 on every version means the
        CRD is not installed (outcome 'absent') — a cluster without Istio is not an error."""
        last = {"outcome": "absent", "items": [], "error": None}
        for v in versions:
            try:
                resp = custom.list_cluster_custom_object(group, v, plural,
                                                         _request_timeout=timeout)
                return {"outcome": "ok", "items": resp.get("items") or [], "error": None}
            except ApiException as ex:
                if ex.status == 403:
                    return {"outcome": "forbidden", "items": [], "error": f"HTTP 403 {group}/{v}"}
                last = {"outcome": "absent" if ex.status == 404 else "error", "items": [],
                        "error": f"HTTP {ex.status} {group}/{v}"}
            except Exception as ex:
                last = {"outcome": "error", "items": [], "error": f"{type(ex).__name__}: {ex}"}
        return last

    snapshot: dict = {
        "namespaces": _call(core.list_namespace),
        "services": _call(core.list_service_for_all_namespaces),
        "service_accounts": _call(core.list_service_account_for_all_namespaces),
        # field_selector narrows server-side to legacy SA token secrets; _secret_meta reduces
        # each one BEFORE it enters the snapshot — token bytes never sit in memory beyond the
        # response object.
        "sa_token_secrets": _call(core.list_secret_for_all_namespaces, reduce=_secret_meta,
                                  field_selector=f"type={_SA_TOKEN_TYPE}"),
        "ingresses": _call(net.list_ingress_for_all_namespaces),
        # runtime admission/egress posture axis (read-only)
        "network_policies": _call(net.list_network_policy_for_all_namespaces),
        "validating_webhooks": _call(admission.list_validating_webhook_configuration),
        "mutating_webhooks": _call(admission.list_mutating_webhook_configuration),
        # best-effort: a CNI-level egress policy engine (Cilium). Absent (404) on most clusters.
        "cilium_network_policies": _crd("cilium.io", ("v2",), "ciliumnetworkpolicies"),
        "cilium_clusterwide_network_policies": _crd("cilium.io", ("v2",),
                                                    "ciliumclusterwidenetworkpolicies"),
        "cluster_roles": _call(rbac.list_cluster_role),
        "cluster_role_bindings": _call(rbac.list_cluster_role_binding),
        "roles": _call(rbac.list_role_for_all_namespaces),
        "role_bindings": _call(rbac.list_role_binding_for_all_namespaces),
        "istio_peer_authentications": _crd("security.istio.io", ("v1", "v1beta1"),
                                           "peerauthentications"),
        "istio_authorization_policies": _crd("security.istio.io", ("v1", "v1beta1"),
                                             "authorizationpolicies"),
        "istio_destination_rules": _crd("networking.istio.io", ("v1", "v1beta1", "v1alpha3"),
                                        "destinationrules"),
        "istio_gateways": _crd("networking.istio.io", ("v1", "v1beta1", "v1alpha3"), "gateways"),
        "istio_virtual_services": _crd("networking.istio.io", ("v1", "v1beta1", "v1alpha3"),
                                       "virtualservices"),
        "linkerd_servers": _crd("policy.linkerd.io", ("v1beta3", "v1beta2", "v1beta1"), "servers"),
        "linkerd_server_authorizations": _crd("policy.linkerd.io", ("v1beta1", "v1alpha1"),
                                              "serverauthorizations"),
        "gateway_classes": _crd("gateway.networking.k8s.io", ("v1", "v1beta1"), "gatewayclasses"),
        "gateways": _crd("gateway.networking.k8s.io", ("v1", "v1beta1"), "gateways"),
        "http_routes": _crd("gateway.networking.k8s.io", ("v1", "v1beta1"), "httproutes"),
    }

    try:
        snapshot["version"] = k8s_client.VersionApi(api_client).get_code(
            _request_timeout=timeout).git_version
    except Exception:
        snapshot["version"] = None

    root = (config.get("istio_root_namespace") or "istio-system").strip() or "istio-system"
    return _build_resources(snapshot, root_namespace=root)


# ── NHI derivation: ServiceAccounts → identity, token secrets → credential, bindings → grant ──
@identity_extractor("k8s")
def _from_k8s(resources: list) -> tuple:
    """The cluster's non-human identities in the normalized model:

      k8s_service_account      → identity (service_account) — named "<ns>/<name>" so the
                                 /identities view groups per-namespace duplicates apart
      k8s_sa_token_secret      → ONE credential per owning SA (type sa_token, count=N secrets;
                                 metadata only — the connector never collected a value)
      k8s_*role_binding        → one grant per (SA subject, roleRef), wildcard when the bound
                                 role carries *-verbs-on-*-resources or is cluster-admin

    Edges: credential --credential_of--> identity, grant --granted_to--> identity.
    """
    out: list[Resource] = []
    edges: list[Edge] = []
    id_by_sa: dict[tuple, Resource] = {}     # (namespace, name) -> identity

    for r in resources:
        if r.kind != "k8s_service_account":
            continue
        raw = r.raw or {}
        ns, name = raw.get("namespace") or "", raw.get("name") or r.name
        idr = _mk_identity("k8s", "service_account", f"{ns}/{name}", source_ext=r.ext_id,
                           extra={"namespace": ns, "automount": raw.get("automount"),
                                  "is_default": bool(raw.get("is_default"))})
        id_by_sa[(ns, name)] = idr
        out.append(idr)

    # Token secrets → one aggregated credential per SA (metadata only; count = how many
    # long-lived secrets exist for it). _mk_credential's ext_id is per (owner, type), so
    # aggregation is what keeps two secrets from colliding into one silently-overwritten row.
    tokens_by_sa: dict[tuple, list] = {}
    for r in resources:
        if r.kind != "k8s_sa_token_secret":
            continue
        raw = r.raw or {}
        sa = raw.get("service_account")
        if sa:
            tokens_by_sa.setdefault((raw.get("namespace") or "", sa), []).append(raw)
    for (ns, sa), secrets in tokens_by_sa.items():
        idr = id_by_sa.get((ns, sa))
        owner_ext = idr.ext_id if idr else f"identity:k8s:{ns}-{sa}"
        cred = _mk_credential(
            "k8s", owner_ext, "sa_token", name=f"{ns}/{sa}:sa-token",
            hashing="n/a", present=True, plaintext=False, count=len(secrets),
            extra={"secret_names": [s.get("name") for s in secrets],
                   "oldest_created": min((s.get("created") or "" for s in secrets),
                                         default=None)})
        out.append(cred)
        if idr:
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id,
                              kind="credential_of"))

    for r in resources:
        if r.kind not in ("k8s_cluster_role_binding", "k8s_role_binding"):
            continue
        raw = r.raw or {}
        role_ref = raw.get("role_ref") or {}
        role_name = role_ref.get("name") or "?"
        cluster_scoped = r.kind == "k8s_cluster_role_binding"
        target = "cluster" if cluster_scoped else f"namespace:{raw.get('namespace')}"
        wildcard = bool(raw.get("wildcard_rules")) or role_name == "cluster-admin"
        for s in raw.get("subjects") or []:
            if s.get("kind") != "ServiceAccount" or not s.get("name"):
                continue
            sns = s.get("namespace") or raw.get("namespace") or ""
            idr = id_by_sa.get((sns, s["name"]))
            owner_ext = idr.ext_id if idr else f"identity:k8s:{sns}-{s['name']}"
            g = _mk_grant("k8s", owner_ext, role_name, target, wildcard=wildcard,
                          scope="" if cluster_scoped else str(raw.get("namespace") or ""),
                          extra={"role_kind": role_ref.get("kind"),
                                 "binding": raw.get("name"), "via": r.ext_id})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=owner_ext, kind="granted_to"))
    return out, edges
