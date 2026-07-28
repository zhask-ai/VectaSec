"""Kubernetes / service-mesh detectors — the mesh, gateway, ingress, exposure and RBAC checks
scoped in docs/research/middleware-security-platform-capabilities.md (service mesh: mTLS not
enforced, allow-all authz, wildcard rules — plus the Gateway API / ingress / NHI surface the
same connection unlocks).

Rules run on the DISTINCT `k8s_*` / `mesh_*` kinds connect/k8s.py emits, so they never collide
with the Kafka/Kong `broker` or RabbitMQ `user` packs. Every rule reads real config evidence
from `raw` (a spec field, a resolved RBAC rule, a listener protocol) — never a name-based guess.
Where the collecting credential was FORBIDDEN a resource type, K8S.COLLECT.FORBIDDEN files a
not-assessable coverage gap on the cluster resource; silence never stands in for "denied".
"""
from ..contracts import Hit
from ..registry import detector


def _spec(r) -> dict:
    return (r.raw or {}).get("spec") or {}


def _cluster(ctx):
    for c in ctx.of_kind("k8s_cluster"):
        return c
    return None


def _outcome(ctx, key: str) -> str:
    c = _cluster(ctx)
    return (((c.raw or {}).get("outcomes") or {}).get(key, "absent")) if c else "absent"


# ── Istio: mTLS ───────────────────────────────────────────────────────────────
@detector(kinds=["mesh_peer_authentication"], rule_id="K8S.MESH.MTLS_NOT_STRICT",
          severity="high", title="Istio PeerAuthentication does not enforce mTLS")
def mtls_not_strict(r, ctx) -> list:
    """PERMISSIVE accepts plaintext alongside mTLS — every zero-trust claim the mesh makes rests
    on STRICT. DISABLE at any scope is graded critical: it actively turns mTLS off."""
    raw = r.raw or {}
    spec = _spec(r)
    hits = []
    scope = "mesh-wide" if raw.get("mesh_wide") else (
        f"namespace {raw.get('namespace')}" + (" (workload selector)" if spec.get("selector") else ""))
    mode = str(((spec.get("mtls") or {}).get("mode") or "")).upper()
    if mode in ("PERMISSIVE", "DISABLE"):
        hits.append(Hit(
            observation=(f"istio PeerAuthentication '{raw.get('name')}' sets spec.mtls.mode="
                         f"{mode}, so {scope} traffic is accepted "
                         + ("without mTLS at all" if mode == "DISABLE" else
                            "in plaintext as well as mTLS")),
            remediation=("Set `spec.mtls.mode: STRICT`. PERMISSIVE is a migration mode: any "
                         "workload (or attacker pod) can talk to the sidecar in plaintext, "
                         "bypassing peer identity entirely. Migrate namespace by namespace, "
                         "then lock the mesh-wide default to STRICT."),
            detail=f"scope={scope} mtls.mode={mode}",
            severity="critical" if mode == "DISABLE" else None,
            source_ref={"crd": "security.istio.io/PeerAuthentication",
                        "name": raw.get("name"), "namespace": raw.get("namespace"),
                        "field": "spec.mtls.mode"},
        ))
    for port, cfg in (spec.get("portLevelMtls") or {}).items():
        pmode = str(((cfg or {}).get("mode") or "")).upper()
        if pmode in ("PERMISSIVE", "DISABLE"):
            hits.append(Hit(
                observation=(f"istio PeerAuthentication '{raw.get('name')}' sets "
                             f"portLevelMtls[{port}].mode={pmode}, exempting port {port} "
                             f"from mTLS enforcement in {scope}"),
                remediation=("Remove the port-level exemption or set it STRICT; a single "
                             "PERMISSIVE port is the plaintext path an attacker will use."),
                detail=f"scope={scope} port={port} mode={pmode}",
                severity="critical" if pmode == "DISABLE" else None,
                source_ref={"crd": "security.istio.io/PeerAuthentication",
                            "name": raw.get("name"), "field": f"spec.portLevelMtls.{port}.mode"},
            ))
    return hits


@detector(kinds=["k8s_cluster"], rule_id="K8S.MESH.NO_MESH_WIDE_STRICT", severity="high",
          title="Istio mesh has no mesh-wide STRICT mTLS default")
def no_mesh_wide_strict(r, ctx) -> list:
    """Istio's out-of-the-box default is PERMISSIVE. Without a mesh-wide STRICT
    PeerAuthentication in the root namespace, every namespace nobody explicitly hardened
    accepts plaintext — absence of config IS the finding."""
    raw = r.raw or {}
    if not raw.get("istio_present"):
        return []
    root = raw.get("istio_root_namespace") or "istio-system"
    outcome = (raw.get("outcomes") or {}).get("istio_peer_authentications")
    if outcome == "forbidden":
        return [Hit(
            observation=("istio CRDs are installed but the scanning credential was denied "
                         "listing security.istio.io/peerauthentications (HTTP 403), so the "
                         "mesh-wide mTLS mode could not be read"),
            remediation=("Grant the scanner get/list on security.istio.io resources (the "
                         "istioctl-generated `istio-reader` ClusterRole covers it), then "
                         "re-scan to assess the mesh mTLS posture."),
            detail="outcome=forbidden resource=peerauthentications",
            assessable=False,
            assessment_reason="RBAC denied listing PeerAuthentication resources",
            source_ref={"api": "security.istio.io", "outcome": "forbidden"},
        )]
    for pa in ctx.of_kind("mesh_peer_authentication"):
        praw = pa.raw or {}
        mode = str((((praw.get("spec") or {}).get("mtls") or {}).get("mode") or "")).upper()
        if praw.get("mesh_wide") and mode == "STRICT":
            return []
    return [Hit(
        observation=(f"istio is installed but no PeerAuthentication in the root namespace "
                     f"'{root}' (without a selector) sets mtls.mode=STRICT — the mesh-wide "
                     f"default remains PERMISSIVE, accepting plaintext from any pod"),
        remediation=("Create a mesh-wide default:\n"
                     "  apiVersion: security.istio.io/v1\n  kind: PeerAuthentication\n"
                     "  metadata: {name: default, namespace: " + root + "}\n"
                     "  spec: {mtls: {mode: STRICT}}\n"
                     "then add namespace-scoped PERMISSIVE exceptions only where migration "
                     "genuinely requires them."),
        detail=f"root_namespace={root} mesh_wide_strict=absent",
        source_ref={"crd": "security.istio.io/PeerAuthentication", "scope": "mesh-wide"},
    )]


# ── Istio: authorization ──────────────────────────────────────────────────────
@detector(kinds=["mesh_authorization_policy"], rule_id="K8S.MESH.AUTHZ_ALLOW_ALL",
          severity="high", title="Istio AuthorizationPolicy allows all traffic")
def authz_allow_all(r, ctx) -> list:
    """In Istio semantics an ALLOW policy whose rules contain an EMPTY rule ({}) matches every
    request; principals: [\"*\"] is the same hole spelled differently. (An ALLOW policy with NO
    rules at all matches nothing — that is not this finding.)"""
    raw = r.raw or {}
    spec = _spec(r)
    action = str(spec.get("action") or "ALLOW").upper()
    if action != "ALLOW":
        return []
    hits = []
    scope = f"namespace {raw.get('namespace')}" + ("" if spec.get("selector") else " (no selector — every workload)")
    for i, rule in enumerate(spec.get("rules") or []):
        if not rule:      # {} — matches everything
            hits.append(Hit(
                observation=(f"istio AuthorizationPolicy '{raw.get('name')}' has an empty rule "
                             f"({{}}) with action ALLOW, which matches every request to {scope}"),
                remediation=("Replace the empty rule with explicit `from.source.principals` / "
                             "`to.operation` constraints, or delete the policy: an allow-all "
                             "AuthorizationPolicy also short-circuits any other ALLOW policy's "
                             "restrictions on the same workloads."),
                detail=f"rules[{i}]={{}} action=ALLOW scope={scope}",
                source_ref={"crd": "security.istio.io/AuthorizationPolicy",
                            "name": raw.get("name"), "field": f"spec.rules[{i}]"},
            ))
            continue
        for f in rule.get("from") or []:
            principals = ((f.get("source") or {}).get("principals")) or []
            if "*" in principals:
                hits.append(Hit(
                    observation=(f"istio AuthorizationPolicy '{raw.get('name')}' allows "
                                 f"source principals [\"*\"] — any authenticated workload "
                                 f"identity — to {scope}"),
                    remediation=("List the specific SPIFFE principals (`cluster.local/ns/…/sa/…`) "
                                 "that should reach these workloads instead of the wildcard."),
                    detail=f"rules[{i}].from.source.principals=* scope={scope}",
                    source_ref={"crd": "security.istio.io/AuthorizationPolicy",
                                "name": raw.get("name"),
                                "field": f"spec.rules[{i}].from.source.principals"},
                ))
    return hits


@detector(kinds=["k8s_namespace"], rule_id="K8S.MESH.NS_NO_AUTHZ_POLICY", severity="medium",
          title="Istio-injected namespace has no AuthorizationPolicy")
def ns_no_authz_policy(r, ctx) -> list:
    """A meshed namespace with zero AuthorizationPolicies (and none mesh-wide) runs allow-by-
    default: mTLS says WHO is calling, nothing says who MAY. The identity layer is doing work
    the authorization layer never uses."""
    raw = r.raw or {}
    if not raw.get("istio_injection"):
        return []
    c = _cluster(ctx)
    if not c or not (c.raw or {}).get("istio_present"):
        return []
    if _outcome(ctx, "istio_authorization_policies") != "ok":
        return []       # denied/absent listing is K8S.COLLECT.FORBIDDEN's finding, not a pass here
    root = (c.raw or {}).get("istio_root_namespace") or "istio-system"
    for p in ctx.of_kind("mesh_authorization_policy"):
        if (p.raw or {}).get("namespace") in (raw.get("name"), root):
            return []
    return [Hit(
        observation=(f"namespace '{raw.get('name')}' is istio-injected but no "
                     f"AuthorizationPolicy exists in it (or mesh-wide in '{root}') — all "
                     f"mesh traffic to its workloads is allowed by default"),
        remediation=("Adopt default-deny: apply an empty `spec: {}` AuthorizationPolicy in the "
                     "namespace (denies all), then add explicit ALLOW policies per workload. "
                     "mTLS without authorization authenticates attackers politely."),
        detail=f"namespace={raw.get('name')} authorization_policies=0",
        source_ref={"crd": "security.istio.io/AuthorizationPolicy",
                    "namespace": raw.get("name")},
    )]


# ── Istio: DestinationRule / Gateway ─────────────────────────────────────────
@detector(kinds=["mesh_destination_rule"], rule_id="K8S.MESH.DR_TLS_DISABLE", severity="high",
          title="Istio DestinationRule disables TLS to a destination")
def dr_tls_disable(r, ctx) -> list:
    """`tls.mode: DISABLE` in a DestinationRule silently overrides mesh mTLS for that host —
    the classic way a STRICT mesh still carries plaintext."""
    raw = r.raw or {}
    spec = _spec(r)
    hits = []

    def _check(tls: dict, where: str):
        mode = str(((tls or {}).get("mode") or "")).upper()
        if mode == "DISABLE":
            hits.append(Hit(
                observation=(f"istio DestinationRule '{raw.get('name')}' (host "
                             f"{spec.get('host')}) sets {where}.tls.mode=DISABLE, sending "
                             f"traffic to that destination in plaintext regardless of "
                             f"PeerAuthentication"),
                remediation=("Remove the DISABLE override or set `ISTIO_MUTUAL`. A "
                             "DestinationRule outranks the mesh-wide mTLS default, so this "
                             "one resource re-opens the plaintext path STRICT closed."),
                detail=f"host={spec.get('host')} {where}.tls.mode=DISABLE",
                source_ref={"crd": "networking.istio.io/DestinationRule",
                            "name": raw.get("name"), "field": f"{where}.tls.mode"},
            ))

    tp = spec.get("trafficPolicy") or {}
    _check(tp.get("tls") or {}, "trafficPolicy")
    for i, pl in enumerate(tp.get("portLevelSettings") or []):
        _check((pl or {}).get("tls") or {}, f"trafficPolicy.portLevelSettings[{i}]")
    for i, sub in enumerate(spec.get("subsets") or []):
        _check(((sub or {}).get("trafficPolicy") or {}).get("tls") or {},
               f"subsets[{i}].trafficPolicy")
    return hits


@detector(kinds=["mesh_gateway"], rule_id="K8S.MESH.GATEWAY_PLAINTEXT", severity="medium",
          title="Istio Gateway exposes a plaintext HTTP listener")
def mesh_gateway_plaintext(r, ctx) -> list:
    """An HTTP server on an istio Gateway without `tls.httpsRedirect` terminates edge traffic
    in cleartext. Wildcard hosts grade high: that listener answers for everything."""
    raw = r.raw or {}
    hits = []
    for i, server in enumerate(_spec(r).get("servers") or []):
        port = (server or {}).get("port") or {}
        if str(port.get("protocol") or "").upper() != "HTTP":
            continue
        tls = (server or {}).get("tls") or {}
        if tls.get("httpsRedirect"):
            continue
        hosts = (server or {}).get("hosts") or []
        # istio hosts are "hostname" or "namespace/hostname"; the hostname part being "*"
        # means this listener answers for every host.
        wildcard = any(str(h).split("/")[-1] == "*" for h in hosts)
        hits.append(Hit(
            observation=(f"istio Gateway '{raw.get('name')}' server[{i}] listens on port "
                         f"{port.get('number')} protocol HTTP for hosts {hosts} with no "
                         f"tls.httpsRedirect — edge traffic is accepted in plaintext"),
            remediation=("Add `tls: {httpsRedirect: true}` to the HTTP server and serve the "
                         "real listener on 443 with `tls.mode: SIMPLE` (or MUTUAL). A "
                         "plaintext edge listener exposes every credential and cookie the "
                         "routed apps exchange."),
            detail=f"server[{i}] port={port.get('number')} hosts={hosts}",
            severity="high" if wildcard else None,
            source_ref={"crd": "networking.istio.io/Gateway", "name": raw.get("name"),
                        "field": f"spec.servers[{i}]"},
        ))
    return hits


# ── Linkerd ───────────────────────────────────────────────────────────────────
@detector(kinds=["mesh_server_authorization"], rule_id="K8S.MESH.LINKERD_UNAUTHENTICATED",
          severity="medium", title="Linkerd ServerAuthorization admits unauthenticated clients")
def linkerd_unauthenticated(r, ctx) -> list:
    raw = r.raw or {}
    client = _spec(r).get("client") or {}
    if not client.get("unauthenticated"):
        return []
    networks = [n.get("cidr") if isinstance(n, dict) else n
                for n in (client.get("networks") or [])]
    open_net = (not networks) or any(str(n) in ("0.0.0.0/0", "::/0") for n in networks)
    return [Hit(
        observation=(f"linkerd ServerAuthorization '{raw.get('name')}' sets "
                     f"spec.client.unauthenticated=true"
                     + (f" restricted to networks {networks}" if networks and not open_net
                        else " with no network restriction — any source may connect without "
                             "a mesh identity")),
        remediation=("Require meshed clients (`spec.client.meshTLS`) and name the allowed "
                     "identities or service accounts; if unauthenticated access is genuinely "
                     "needed (e.g. kubelet probes), scope `networks` to the node CIDR only."),
        detail=f"unauthenticated=true networks={networks or 'unrestricted'}",
        severity="high" if open_net else None,
        source_ref={"crd": "policy.linkerd.io/ServerAuthorization", "name": raw.get("name"),
                    "field": "spec.client.unauthenticated"},
    )]


# ── Gateway API ───────────────────────────────────────────────────────────────
@detector(kinds=["k8s_gateway"], rule_id="K8S.GWAPI.LISTENER_PLAINTEXT", severity="medium",
          title="Gateway API listener accepts plaintext HTTP")
def gwapi_listener_plaintext(r, ctx) -> list:
    """Applies to whatever implements the Gateway (Envoy Gateway, Istio, Traefik v3, …). An
    HTTP-protocol listener carries no `tls` block by definition; whether the routes attached
    to it redirect to HTTPS is not observable from the Gateway, so the evidence stated is
    exactly the listener config."""
    raw = r.raw or {}
    hits = []
    for l in (raw.get("listeners") or []):
        if str(l.get("protocol") or "").upper() != "HTTP":
            continue
        hits.append(Hit(
            observation=(f"gateway '{raw.get('name')}' (class {raw.get('gateway_class')}) "
                         f"listener '{l.get('name')}' is protocol HTTP on port {l.get('port')}"
                         f" for hostname {l.get('hostname') or '* (unset)'} — no TLS at this "
                         f"listener"),
            remediation=("Serve traffic on an HTTPS listener with a certificateRef, and keep "
                         "the HTTP listener only if every attached HTTPRoute is a "
                         "RequestRedirect to HTTPS. Verify the redirect exists — the Gateway "
                         "itself does not enforce it."),
            detail=f"listener={l.get('name')} protocol=HTTP port={l.get('port')}",
            source_ref={"crd": "gateway.networking.k8s.io/Gateway", "name": raw.get("name"),
                        "field": f"spec.listeners[{l.get('name')}]"},
        ))
    return hits


@detector(kinds=["k8s_http_route"], rule_id="K8S.GWAPI.ROUTE_PLAINTEXT_ONLY", severity="medium",
          title="HTTPRoute is served only by plaintext listeners")
def gwapi_route_plaintext_only(r, ctx) -> list:
    """Cross-resource: the route's parent Gateways are resolved from this scan. Fires only when
    EVERY listener the route can attach to is plaintext HTTP — application traffic on this
    route has no TLS path at all."""
    raw = r.raw or {}
    parents = raw.get("parent_refs") or []
    if not parents:
        return []
    by_key = {((g.raw or {}).get("namespace"), (g.raw or {}).get("name")): g
              for g in ctx.of_kind("k8s_gateway")}
    resolved = []
    for p in parents:
        gw = by_key.get((p.get("namespace"), p.get("name")))
        if gw is None:
            return []          # parent not collected — cannot claim anything about it
        listeners = (gw.raw or {}).get("listeners") or []
        if p.get("section_name"):
            listeners = [l for l in listeners if l.get("name") == p["section_name"]]
        resolved.append((p, listeners))
    all_listeners = [l for _, ls in resolved for l in ls]
    if not all_listeners:
        return []
    if any(str(l.get("protocol") or "").upper() != "HTTP" for l in all_listeners):
        return []              # at least one TLS-capable attachment point exists
    parents_txt = [f"{p.get('namespace')}/{p.get('name')}" for p, _ in resolved]
    return [Hit(
        observation=(f"HTTPRoute '{raw.get('name')}' (hostnames {raw.get('hostnames') or ['*']}) "
                     f"attaches only to plaintext HTTP listeners on gateway(s) {parents_txt} — "
                     f"no HTTPS listener serves this route"),
        remediation=("Attach the route to an HTTPS listener (sectionName pointing at a TLS "
                     "listener with a certificateRef) and reduce the HTTP attachment to a "
                     "RequestRedirect filter."),
        detail=f"parents={parents_txt} listeners=HTTP-only",
        source_ref={"crd": "gateway.networking.k8s.io/HTTPRoute", "name": raw.get("name"),
                    "field": "spec.parentRefs"},
    )]


# ── Ingress ───────────────────────────────────────────────────────────────────
@detector(kinds=["k8s_ingress"], rule_id="K8S.INGRESS.NO_TLS", severity="medium",
          title="Ingress has no TLS configuration")
def ingress_no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("tls"):
        return []
    rules = raw.get("rules") or []
    if not rules:
        return []              # a default-backend-only ingress exposes no routed host here
    hosts = [x.get("host") or "* (all hosts)" for x in rules]
    services = sorted({s for x in rules for s in (x.get("services") or []) if s})
    return [Hit(
        observation=(f"ingress '{raw.get('name')}' routes host(s) {hosts} to service(s) "
                     f"{services or ['?']} with no spec.tls section — the controller serves "
                     f"these routes over plaintext HTTP"),
        remediation=("Add a `spec.tls` block with a certificate secret for each host "
                     "(cert-manager automates issuance) and enable the controller's "
                     "ssl-redirect so HTTP requests upgrade instead of being served."),
        detail=f"hosts={hosts} tls=absent",
        source_ref={"api": "networking.k8s.io/Ingress", "name": raw.get("name"),
                    "field": "spec.tls"},
    )]


# ── Service exposure ──────────────────────────────────────────────────────────
@detector(kinds=["k8s_service"], rule_id="K8S.SVC.LB_PLAINTEXT", severity="high",
          title="LoadBalancer Service exposes a plaintext port")
def svc_lb_plaintext(r, ctx) -> list:
    """Evidence-based plaintext markers only: `appProtocol: http` (explicit config) or
    well-known port 80. Port names are conventions, not evidence, and are not used."""
    raw = r.raw or {}
    if raw.get("type") != "LoadBalancer":
        return []
    hits = []
    lb = raw.get("load_balancer_ingress") or []
    for p in raw.get("ports") or []:
        plaintext = (str(p.get("app_protocol") or "").lower() == "http") or p.get("port") == 80
        if not plaintext:
            continue
        why = ("appProtocol=http" if str(p.get("app_protocol") or "").lower() == "http"
               else "port 80")
        hits.append(Hit(
            observation=(f"service '{raw.get('namespace')}/{raw.get('name')}' is "
                         f"type=LoadBalancer and exposes {why} "
                         f"(port {p.get('port')})"
                         + (f" on external address(es) {lb}" if lb else "")
                         + " — plaintext HTTP on a load-balanced, externally reachable port"),
            remediation=("Terminate TLS at this service (or front it with an Ingress/Gateway "
                         "HTTPS listener) and remove the raw HTTP port, or restrict the "
                         "LoadBalancer with `loadBalancerSourceRanges`. A cloud LB on port 80 "
                         "is an internet-facing plaintext endpoint by default."),
            detail=f"type=LoadBalancer port={p.get('port')} app_protocol={p.get('app_protocol')} lb={lb}",
            source_ref={"api": "v1/Service", "name": raw.get("name"),
                        "namespace": raw.get("namespace"), "field": "spec.ports"},
        ))
    return hits


@detector(kinds=["k8s_service"], rule_id="K8S.SVC.NODEPORT_EXPOSED", severity="low",
          title="NodePort Service exposes a port on every node")
def svc_nodeport(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("type") != "NodePort":
        return []
    node_ports = [p.get("node_port") for p in raw.get("ports") or [] if p.get("node_port")]
    return [Hit(
        observation=(f"service '{raw.get('namespace')}/{raw.get('name')}' is type=NodePort, "
                     f"binding node port(s) {node_ports} on every node's network interface"),
        remediation=("Prefer a ClusterIP service behind an Ingress/Gateway, or a LoadBalancer "
                     "with source ranges. NodePort bypasses the gateway layer entirely: "
                     "anything that can reach any node IP reaches the workload."),
        detail=f"type=NodePort node_ports={node_ports}",
        source_ref={"api": "v1/Service", "name": raw.get("name"),
                    "namespace": raw.get("namespace"), "field": "spec.type"},
    )]


# ── RBAC / service accounts ───────────────────────────────────────────────────
@detector(kinds=["k8s_cluster_role_binding"], rule_id="K8S.RBAC.SA_CLUSTER_ADMIN",
          severity="critical", title="cluster-admin is bound at cluster scope")
def rbac_cluster_admin(r, ctx) -> list:
    """cluster-admin to a ServiceAccount is critical — a workload token IS root on the cluster,
    and workload tokens leak (mounted files, CI logs, SSRF against the kubelet). The same
    binding to a human user/group files at high."""
    raw = r.raw or {}
    if (raw.get("role_ref") or {}).get("name") != "cluster-admin":
        return []
    hits = []
    for s in raw.get("subjects") or []:
        kind, name, ns = s.get("kind"), s.get("name"), s.get("namespace")
        is_sa = kind == "ServiceAccount" or (
            kind == "Group" and str(name or "").startswith("system:serviceaccounts"))
        subject_txt = f"{kind} {ns + '/' if ns else ''}{name}"
        hits.append(Hit(
            observation=(f"ClusterRoleBinding '{raw.get('name')}' binds cluster-admin to "
                         f"{subject_txt}"
                         + (" — every workload token under that subject has full cluster "
                            "control" if is_sa else "")),
            remediation=("Replace cluster-admin with a purpose-built (Cluster)Role listing the "
                         "exact verbs/resources needed. For controllers, scope with "
                         "RoleBindings per namespace. cluster-admin bindings should be "
                         "break-glass only, and audited."),
            detail=f"binding={raw.get('name')} subject={subject_txt}",
            severity=None if is_sa else "high",
            source_ref={"api": "rbac.authorization.k8s.io/ClusterRoleBinding",
                        "name": raw.get("name"), "roleRef": "cluster-admin"},
        ))
    return hits


@detector(kinds=["k8s_cluster_role_binding", "k8s_role_binding"],
          rule_id="K8S.RBAC.WILDCARD_BOUND", severity="high",
          title="Bound role carries wildcard verbs on wildcard resources")
def rbac_wildcard_bound(r, ctx) -> list:
    """Fires on the BINDING (a wildcard role nobody is bound to grants nothing) with the
    resolved rule as evidence. cluster-admin itself is K8S.RBAC.SA_CLUSTER_ADMIN's finding."""
    raw = r.raw or {}
    if (raw.get("role_ref") or {}).get("name") == "cluster-admin":
        return []
    if not raw.get("wildcard_rules"):
        # `role_found` is written by connect/k8s.py for exactly this case and, until now, read
        # by no detector: when listing clusterroles is 403'd the connector computes
        # wildcard=False from a role it never saw, so a `*`/`*` role bound to a ServiceAccount
        # reported as "no wildcard grants".
        if raw.get("role_found") is False:
            return [Hit(
                observation=(f"binding '{raw.get('name')}' references role "
                             f"'{(raw.get('role_ref') or {}).get('name')}', which could not be "
                             f"read, so its rules were never examined"),
                detail="Whether this binding grants wildcard permissions is unknown — the role "
                       "it points at was not readable, not empty.",
                remediation="Grant the scanning ServiceAccount get/list on roles and "
                            "clusterroles, then re-scan.",
                assessable=False,
                assessment_reason="the referenced role could not be read",
                source_ref={"binding": raw.get("name"), "signal": "role_not_readable"},
            )]
        return []
    rule = next((x for x in raw.get("role_rules") or []
                 if "*" in (x.get("verbs") or []) and "*" in (x.get("resources") or [])), {})
    subjects = [f"{s.get('kind')} {s.get('namespace') + '/' if s.get('namespace') else ''}{s.get('name')}"
                for s in raw.get("subjects") or []]
    scope = "cluster-wide" if r.kind == "k8s_cluster_role_binding" else \
        f"namespace {raw.get('namespace')}"
    return [Hit(
        observation=(f"binding '{raw.get('name')}' grants role "
                     f"'{(raw.get('role_ref') or {}).get('name')}' whose rules include "
                     f"verbs={rule.get('verbs')} resources={rule.get('resources')} "
                     f"apiGroups={rule.get('api_groups')} ({scope}) to {subjects}"),
        remediation=("Enumerate the verbs and resources the subject actually uses and replace "
                     "the `*`/`*` rule. Wildcard-on-wildcard is cluster-admin by another name "
                     "within its scope — including reading every Secret."),
        detail=f"role={(raw.get('role_ref') or {}).get('name')} rule=*/* scope={scope}",
        source_ref={"api": "rbac.authorization.k8s.io", "binding": raw.get("name"),
                    "field": "rules[verbs=*,resources=*]"},
    )]


# Bindings Kubernetes itself ships and every cluster has. `system:public-info-viewer` binds
# system:unauthenticated by design so unauthenticated clients can reach /version and /healthz;
# `system:basic-user` and `system:discovery` bind system:authenticated for self-review and API
# discovery. Firing on these produced one critical + three high findings on a PRISTINE cluster —
# and this rule's own remediation says anonymous should "retain nothing beyond the API discovery
# defaults", i.e. it was flagging exactly what it declares acceptable. A pack that alarms on
# every clean cluster is a pack people mute.
_K8S_BUILTIN_PUBLIC_ROLES = {
    "system:public-info-viewer",
    "system:basic-user",
    "system:discovery",
    "system:service-account-issuer-discovery",
}


@detector(kinds=["k8s_cluster_role_binding", "k8s_role_binding"],
          rule_id="K8S.RBAC.ANONYMOUS_BOUND", severity="critical",
          title="RBAC binding grants access to anonymous or all-authenticated principals")
def rbac_anonymous_bound(r, ctx) -> list:
    raw = r.raw or {}
    role_ref = raw.get("role_ref") or {}
    if str(role_ref.get("name") or "") in _K8S_BUILTIN_PUBLIC_ROLES:
        return []
    hits = []
    for s in raw.get("subjects") or []:
        name = s.get("name")
        anon = (s.get("kind") == "User" and name == "system:anonymous") or \
               (s.get("kind") == "Group" and name == "system:unauthenticated")
        broad = s.get("kind") == "Group" and name == "system:authenticated"
        if not (anon or broad):
            continue
        role = (raw.get("role_ref") or {}).get("name")
        hits.append(Hit(
            observation=(f"binding '{raw.get('name')}' grants role '{role}' to {s.get('kind')} "
                         f"'{name}'"
                         + (" — any UNAUTHENTICATED request to the API server holds this role"
                            if anon else
                            " — every authenticated principal, including every service "
                            "account token, holds this role")),
            remediation=("Remove the system:anonymous/system:unauthenticated subject (this was "
                         "the kubelet-exec exposure pattern in public-cluster breaches) or "
                         "narrow system:authenticated to the concrete groups that need the "
                         "role. Anonymous should retain nothing beyond the API discovery "
                         "defaults."),
            detail=f"binding={raw.get('name')} role={role} subject={s.get('kind')}:{name}",
            severity=None if anon else "high",
            source_ref={"api": "rbac.authorization.k8s.io", "binding": raw.get("name"),
                        "subject": name},
        ))
    return hits


@detector(kinds=["k8s_service_account"], rule_id="K8S.SA.DEFAULT_BOUND", severity="medium",
          title="Default ServiceAccount holds RBAC grants with token automount enabled")
def sa_default_bound(r, ctx) -> list:
    """The default SA is mounted into every pod that doesn't opt out. Granting it roles hands
    those permissions to EVERY workload in the namespace. Fires only when a collected binding
    actually names it — automount alone, with no power attached, is not reported."""
    raw = r.raw or {}
    if not raw.get("is_default") or raw.get("automount") is False:
        return []
    ns = raw.get("namespace")
    bound = []
    for b in (ctx.of_kind("k8s_cluster_role_binding") + ctx.of_kind("k8s_role_binding")):
        braw = b.raw or {}
        for s in braw.get("subjects") or []:
            if s.get("kind") == "ServiceAccount" and s.get("name") == "default" and \
                    (s.get("namespace") or braw.get("namespace")) == ns:
                bound.append((braw.get("name"), (braw.get("role_ref") or {}).get("name")))
    if not bound:
        return []
    return [Hit(
        observation=(f"the default ServiceAccount in namespace '{ns}' does not set "
                     f"automountServiceAccountToken=false and is bound to role(s) "
                     f"{[role for _, role in bound]} via {[b for b, _ in bound]} — every pod "
                     f"in the namespace that omits serviceAccountName runs with these grants"),
        remediation=("Create a dedicated ServiceAccount per workload and move the bindings to "
                     "it; set `automountServiceAccountToken: false` on the default SA so an "
                     "unconfigured pod carries no API credential at all."),
        detail=f"namespace={ns} bindings={[b for b, _ in bound]} automount={raw.get('automount')}",
        source_ref={"api": "v1/ServiceAccount", "namespace": ns, "name": "default"},
    )]


@detector(kinds=["k8s_sa_token_secret"], rule_id="K8S.SA.LEGACY_TOKEN_SECRET",
          severity="medium", title="Legacy long-lived ServiceAccount token secret exists")
def sa_legacy_token(r, ctx) -> list:
    """Secrets of type kubernetes.io/service-account-token are non-expiring bearer tokens —
    the pre-1.24 mechanism. Modern workloads get short-lived projected tokens; a long-lived
    secret is a credential that never rotates and outlives its pods."""
    raw = r.raw or {}
    return [Hit(
        observation=(f"secret '{raw.get('namespace')}/{raw.get('name')}' is type "
                     f"kubernetes.io/service-account-token for ServiceAccount "
                     f"'{raw.get('service_account')}' (created {raw.get('created') or '?'}) — "
                     f"a long-lived, non-expiring API bearer token at rest in etcd"),
        remediation=("Delete the secret and use short-lived tokens: in-cluster workloads get "
                     "projected tokens automatically (1.24+); external clients should call the "
                     "TokenRequest API (`kubectl create token`) with a bounded TTL. If a "
                     "long-lived token is unavoidable, scope its SA to minimal RBAC and "
                     "rotate on a schedule."),
        detail=f"secret={raw.get('namespace')}/{raw.get('name')} sa={raw.get('service_account')} created={raw.get('created')}",
        source_ref={"api": "v1/Secret", "type": "kubernetes.io/service-account-token",
                    "name": raw.get("name"), "namespace": raw.get("namespace")},
    )]


# ── Coverage honesty ──────────────────────────────────────────────────────────
@detector(kinds=["k8s_cluster"], rule_id="K8S.COLLECT.FORBIDDEN", severity="medium",
          title="Scanner credential was denied listing some resource types")
def collect_forbidden(r, ctx) -> list:
    """The third outcome, cluster-wide: every resource type the credential was 403'd on is a
    blind spot every other rule in this pack silently has. Filed as not-assessable — a
    coverage gap, never a vulnerability and never a pass."""
    outcomes = (r.raw or {}).get("outcomes") or {}
    denied = sorted(k for k, v in outcomes.items() if v == "forbidden")
    if not denied:
        return []
    return [Hit(
        observation=(f"the scanning credential was denied (HTTP 403) listing: "
                     f"{', '.join(denied)} — rules that read these resource types could not "
                     f"run against this cluster"),
        remediation=("Extend the scanner's ClusterRole with get/list on the denied API groups "
                     "(the built-in `view` role plus rbac.authorization.k8s.io and the mesh "
                     "CRD groups covers this pack), then re-scan."),
        detail=f"forbidden={denied}",
        assessable=False,
        assessment_reason=f"RBAC denied listing: {', '.join(denied)}",
        source_ref={"outcomes": {k: outcomes[k] for k in denied}},
    )]
