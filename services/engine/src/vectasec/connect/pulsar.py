"""Apache Pulsar connector — read-only Admin REST API (httpx) + optional broker/proxy config.

Pulsar is a core integration-layer broker (pub/sub + queues + Functions), so its posture belongs
in an integration-security tool. This connector issues only GETs against the Admin REST API and
writes nothing:

  /admin/v2/brokers/configuration/runtime   the broker's effective ServiceConfiguration — the
                                            authoritative source for authenticationEnabled,
                                            authorizationEnabled, tlsEnabled, functionsWorkerEnabled,
                                            anonymousUserRole, clusterName. Values come back as
                                            strings ("true"/"false"), which the parse layer keeps
                                            verbatim so a rule cites what the broker reported.
  /admin/v2/brokers/version                 the running broker version (drives the CVE check).
  /admin/v2/clusters, .../clusters/{c}      per-cluster service URLs (TLS-endpoint check).
  /admin/v2/tenants, .../tenants/{t}        tenant adminRoles / allowedClusters (shared-admin check).
  /admin/v2/namespaces/{t}, .../permissions namespace list + role→actions grants.
  /admin/v2/persistent/{t}/{ns}             topics under each namespace.

A `token` (secret=True) authenticates the admin calls and never enters a Resource. Where the
broker's runtime config is not reachable (older brokers, restricted admin role), the operator may
supply broker.conf / proxy.conf as JSON dicts; the parse layer merges them the same way.

The parse layer (build_resources) is pure: a plain-dict snapshot in, Collected out — httpx and a
live cluster stay out of the test suite. Kinds are DISTINCT (pulsar_cluster, pulsar_namespace,
pulsar_topic) so no other rulepack runs against a Pulsar resource by accident.
"""
import json

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

# The full Pulsar authorization-action set on a namespace grant. A role holding all of these has
# effective control of the namespace (data plane + functions/connectors/packages management).
_ALL_ACTIONS = frozenset({"produce", "consume", "functions", "sources", "sinks", "packages"})


def _load_dict(config: dict, key: str):
    raw = config.get(key)
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except (ValueError, TypeError):
            return None
    return None


def cfg_get(config, key):
    """A ServiceConfiguration value, normalised to a lowercase string. Runtime config returns
    strings; a hand-supplied broker.conf dict may carry real bools/ints — both collapse here."""
    if not isinstance(config, dict) or key not in config:
        return None
    return str(config.get(key)).strip().lower()


def _is_false(config, key) -> bool:
    return cfg_get(config, key) == "false"


def _is_true(config, key) -> bool:
    return cfg_get(config, key) == "true"


def build_resources(snapshot: dict) -> Collected:
    """Pure normalisation: plain-dict snapshot → Collected. No httpx here."""
    resources: list[Resource] = []
    edges: list[Edge] = []

    runtime = snapshot.get("runtime_config") or {}
    proxy = snapshot.get("proxy_config")
    config_source = snapshot.get("config_source")
    # The broker names its own cluster in runtime config; that value keeps its real case (cluster
    # names from /admin/v2/clusters are not lowercased, so cfg_get's normalisation is wrong here).
    local_cluster = runtime.get("clusterName") if isinstance(runtime, dict) else None
    anon_role = runtime.get("anonymousUserRole") if isinstance(runtime, dict) else None
    version = snapshot.get("version")

    tenants_index = {}
    for t in snapshot.get("tenants") or []:
        data = t.get("data") or {}
        tenants_index[t.get("name")] = {
            "admin_roles": data.get("adminRoles") or [],
            "allowed_clusters": data.get("allowedClusters") or [],
        }

    # ── clusters. The cluster the admin is local to carries the broker-wide config so the auth/
    # authz/TLS broker rules fire exactly once; peer clusters (geo-replication) carry only URLs.
    clusters = snapshot.get("clusters") or []
    for c in clusters:
        cname = c.get("name")
        data = c.get("data") or {}
        is_local = (cname == local_cluster) if local_cluster else (c is clusters[0])
        ext = f"pulsar-cluster-{cname}"
        resources.append(Resource(
            kind="pulsar_cluster",
            name=str(cname),
            ext_id=ext,
            labels={"local": "true" if is_local else "false"},
            raw={
                "name": cname,
                "is_local": is_local,
                "service_url": data.get("serviceUrl"),
                "service_url_tls": data.get("serviceUrlTls"),
                "broker_service_url": data.get("brokerServiceUrl"),
                "broker_service_url_tls": data.get("brokerServiceUrlTls"),
                # Broker-wide evidence, only on the local cluster to avoid N-duplicated findings.
                "runtime_config": runtime if is_local else None,
                "proxy_config": proxy if is_local else None,
                "config_source": config_source if is_local else None,
                "anonymous_user_role": anon_role if is_local else None,
                "broker_version": version if is_local else None,
                "tenants": tenants_index if is_local else None,
                "admin_readable": snapshot.get("admin_readable", True),
            },
        ))

    # ── namespaces + their permission grants ──
    ns_exts = {}
    for ns in snapshot.get("namespaces") or []:
        tenant = ns.get("tenant")
        full = ns.get("namespace")
        ext = f"pulsar-ns-{full}"
        ns_exts[full] = ext
        resources.append(Resource(
            kind="pulsar_namespace",
            name=str(full),
            ext_id=ext,
            namespace=str(tenant),
            labels={"tenant": str(tenant)},
            raw={
                "tenant": tenant,
                "namespace": full,
                "permissions": ns.get("permissions") or {},
                "permissions_readable": ns.get("permissions") is not None,
                "auth_policies": ns.get("policies"),
                "anonymous_user_role": anon_role,
            },
        ))
        for cluster_res in resources:
            if cluster_res.kind == "pulsar_cluster" and cluster_res.raw.get("is_local"):
                edges.append(Edge(src_ext_id=cluster_res.ext_id, dst_ext_id=ext, kind="contains"))
                break

    # ── topics ──
    for topic in snapshot.get("topics") or []:
        # topic is a fully-qualified name e.g. persistent://public/default/orders
        scheme, _, rest = str(topic).partition("://")
        parts = rest.split("/")
        if len(parts) < 3:
            continue
        tenant, namespace, tname = parts[0], parts[1], "/".join(parts[2:])
        full_ns = f"{tenant}/{namespace}"
        ext = f"pulsar-topic-{tenant}-{namespace}-{tname}"
        resources.append(Resource(
            kind="pulsar_topic",
            name=str(topic),
            ext_id=ext,
            namespace=full_ns,
            labels={"persistent": "true" if scheme == "persistent" else "false"},
            raw={
                "tenant": tenant,
                "namespace": full_ns,
                "topic": tname,
                "persistent": scheme == "persistent",
                "fqtn": topic,
            },
        ))
        if full_ns in ns_exts:
            edges.append(Edge(src_ext_id=ns_exts[full_ns], dst_ext_id=ext, kind="contains"))

    return Collected(resources=resources, edges=edges)


def _get(client: httpx.Client, path: str):
    try:
        r = client.get(path)
    except httpx.HTTPError as e:
        return {"ok": False, "status": None, "error": f"{type(e).__name__}: {e}"}
    if r.status_code != 200:
        return {"ok": False, "status": r.status_code, "error": f"http_{r.status_code}"}
    ctype = r.headers.get("content-type", "")
    if "json" in ctype:
        try:
            return {"ok": True, "status": 200, "data": r.json()}
        except ValueError:
            return {"ok": False, "status": 200, "error": "non_json_body"}
    return {"ok": True, "status": 200, "data": r.text.strip()}


@connector("pulsar", fields=[
    ConnectorField("admin_url", "Admin API URL", required=True,
                   placeholder="http://localhost:8080",
                   help="Pulsar Admin REST base URL (the web service port, 8080 by default). "
                        "GETs only. A superuser or a role with cluster/namespace read is enough."),
    ConnectorField("token", "Auth token", secret=True,
                   help="Bearer token for the Admin API when authentication is enabled. Used to "
                        "open the request, never stored in any resource."),
    ConnectorField("tls", "Use TLS", placeholder="false",
                   help="'true' if admin_url is https and the certificate should be verified."),
    ConnectorField("broker_config", "broker.conf (JSON)",
                   help="Optional. broker.conf as a JSON object, used when the runtime config "
                        "endpoint is not reachable."),
    ConnectorField("proxy_config", "proxy.conf (JSON)",
                   help="Optional. proxy.conf as a JSON object — enables the proxy-TLS check."),
])
def collect(config: dict) -> Collected:
    base = (config.get("admin_url") or "").rstrip("/")
    if not base:
        raise SystemExit("pulsar connector requires config['admin_url'] "
                         "(e.g. http://localhost:8080)")
    token = (config.get("token") or "").strip()
    verify = config.get("verify_tls", True)
    timeout = float(config.get("timeout") or 10)
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    snapshot: dict = {"outcomes": {}}
    with httpx.Client(base_url=base, timeout=timeout, verify=bool(verify),
                      follow_redirects=False, headers=headers) as client:
        runtime = _get(client, "/admin/v2/brokers/configuration/runtime")
        snapshot["outcomes"]["runtime_config"] = runtime.get("status")
        provided = _load_dict(config, "broker_config")
        if runtime.get("ok") and isinstance(runtime.get("data"), dict):
            snapshot["runtime_config"] = runtime["data"]
            snapshot["config_source"] = "admin_runtime"
        elif provided is not None:
            snapshot["runtime_config"] = provided
            snapshot["config_source"] = "broker_conf"
        else:
            snapshot["runtime_config"] = {}
            snapshot["config_source"] = None
        snapshot["admin_readable"] = runtime.get("status") not in (401, 403)

        snapshot["proxy_config"] = _load_dict(config, "proxy_config")

        ver = _get(client, "/admin/v2/brokers/version")
        snapshot["version"] = ver.get("data") if ver.get("ok") else None

        clusters = _get(client, "/admin/v2/clusters")
        cluster_names = clusters.get("data") if clusters.get("ok") and isinstance(clusters.get("data"), list) else []
        snapshot["clusters"] = []
        for cname in cluster_names:
            detail = _get(client, f"/admin/v2/clusters/{cname}")
            snapshot["clusters"].append(
                {"name": cname, "data": detail.get("data") if detail.get("ok") else {}})

        tenants = _get(client, "/admin/v2/tenants")
        tenant_names = tenants.get("data") if tenants.get("ok") and isinstance(tenants.get("data"), list) else []
        snapshot["tenants"] = []
        snapshot["namespaces"] = []
        snapshot["topics"] = []
        for tname in tenant_names:
            tdetail = _get(client, f"/admin/v2/tenants/{tname}")
            snapshot["tenants"].append(
                {"name": tname, "data": tdetail.get("data") if tdetail.get("ok") else {}})
            ns_list = _get(client, f"/admin/v2/namespaces/{tname}")
            for full_ns in (ns_list.get("data") or []) if ns_list.get("ok") else []:
                perms = _get(client, f"/admin/v2/namespaces/{full_ns}/permissions")
                pols = _get(client, f"/admin/v2/namespaces/{full_ns}")
                snapshot["namespaces"].append({
                    "tenant": tname,
                    "namespace": full_ns,
                    "permissions": perms.get("data") if perms.get("ok") else None,
                    "policies": pols.get("data") if pols.get("ok") else None,
                })
                topics = _get(client, f"/admin/v2/persistent/{full_ns}")
                for t in (topics.get("data") or []) if topics.get("ok") else []:
                    snapshot["topics"].append(t)

    return build_resources(snapshot)


# ── NHI: Pulsar tenant admin roles + namespace grants → identity / grant ──────
@identity_extractor("pulsar")
def _from_pulsar(resources: list) -> tuple:
    """Roles named in tenant admin lists and namespace permission grants → the normalized model:
    one identity per role (deduped), one grant per (role, target). Pulsar roles authenticate via
    tokens/certs the Admin API never returns, so no credential material is emitted — absence, not
    silence, exactly as Kafka records its principals."""
    out: list[Resource] = []
    edges: list[Edge] = []
    seen: dict[str, Resource] = {}

    def _identity(role: str, source_ext: str) -> Resource:
        idr = seen.get(role)
        if idr is None:
            idr = _mk_identity("pulsar", "service_account", role, source_ext=source_ext)
            seen[role] = idr
            out.append(idr)
        return idr

    for r in resources:
        if r.kind == "pulsar_cluster" and (r.raw or {}).get("is_local"):
            tenants = (r.raw or {}).get("tenants") or {}
            for tenant, info in tenants.items():
                for role in info.get("admin_roles") or []:
                    idr = _identity(role, r.ext_id)
                    g = _mk_grant("pulsar", idr.ext_id, "tenant-admin", f"tenant:{tenant}",
                                  wildcard=True, extra={"tenant": tenant})
                    out.append(g)
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))

    for r in resources:
        if r.kind != "pulsar_namespace":
            continue
        raw = r.raw or {}
        anon = raw.get("anonymous_user_role")
        for role, actions in (raw.get("permissions") or {}).items():
            action_set = frozenset(a.lower() for a in (actions or []))
            idr = _identity(role, r.ext_id)
            if anon and role == anon:
                idr.raw.setdefault("tags", []).append("anonymous_role")
            target = f"namespace:{raw.get('namespace')}"
            wildcard = action_set >= _ALL_ACTIONS
            g = _mk_grant("pulsar", idr.ext_id, ",".join(sorted(action_set)) or "none", target,
                          wildcard=wildcard, scope=str(raw.get("namespace") or ""),
                          extra={"actions": sorted(action_set), "namespace": raw.get("namespace")})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=r.ext_id, kind="grants_access"))
    return out, edges
