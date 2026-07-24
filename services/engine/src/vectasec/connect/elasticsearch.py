"""Elasticsearch / OpenSearch connector — read-only REST posture collection.

One HTTP connection reads the security-relevant surface of an Elasticsearch OR OpenSearch
cluster and writes nothing (only GETs are ever issued):

  GET /                       distribution (elasticsearch|opensearch) + version
  GET /_nodes/settings        the running node settings (xpack.security.*, plugins.security.*):
                              the authoritative source for security-enabled and TLS toggles
  GET /_cluster/settings      persistent/transient/defaults, merged under the node settings
  GET /_cat/indices           the index inventory
  GET /_security/_authenticate (ES) — a behavioural probe: 200 = a security realm is active,
                              a "security is not enabled" body = it is off
  GET /_security/user|role    (ES) / GET /_plugins/_security/api/internalusers|roles (OpenSearch)
                              the NHI material (identity.py normalizes it)
  GET /_snapshot              snapshot repositories + their settings

Two probes deliberately carry NO credentials — `GET /` and `GET /_cat/indices` are re-issued
unauthenticated to observe whether the cluster answers an anonymous client. That is the whole
finding for ES.SECURITY.ANONYMOUS_ACCESS / ES.INDEX.ANON_LISTABLE and cannot be read any other
way.

Credential-reduction discipline (same contract as the Redis/RabbitMQ/K8s connectors): OpenSearch
`/_plugins/_security/api/internalusers` returns each user's bcrypt `hash`; it is reduced to a
`has_password` boolean and a hashing name HERE, before anything reaches a Resource. The hash
value is never stored, logged, or returned.

Kinds are DISTINCT (es_cluster, es_index, es_user, es_role) so the Kafka/Kong/RabbitMQ/Redis
rulepacks never run against an Elasticsearch resource by accident — the same reason
connect/redis.py refuses to reuse the generic `broker`/`user` kinds.

The connector is split so the whole normalisation is testable offline:
  collect(config)         talks to the cluster, assembles a plain-dict `snapshot`
  _build_resources(...)   pure: snapshot -> Collected (golden-fixture tested)
"""
from urllib.parse import urlparse

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

# The reserved/built-in superuser names, flagged so a detector can escalate a wildcard grant
# held by the platform's own root identity. Not a default-name list (that lives in
# detect/identity.py) — these are the *superuser role* holders.
_SUPERUSER_ROLES = {"superuser", "all_access", "admin"}


# ── flat-setting helpers (pure) ───────────────────────────────────────────────
def _to_bool(v):
    """Tri-state read of a flat setting: True/False when determinable, None when absent/odd.
    Flat settings arrive as the strings 'true'/'false'; booleans pass through."""
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    return None


def _first_bool(settings: dict, keys):
    for k in keys:
        if k in settings:
            return _to_bool(settings[k])
    return None


def _values_under(settings: dict, prefix: str) -> list:
    """Every value whose key is `prefix` or `prefix.<n>` — flat_settings renders a list setting
    (anonymous.roles) as roles.0/roles.1, and a scalar as the bare key. Collects both."""
    out = []
    for k, v in settings.items():
        if k == prefix or k.startswith(prefix + "."):
            if isinstance(v, list):
                out.extend(str(x) for x in v)
            else:
                out.append(str(v))
    return out


def _flatten_settings(node_settings: dict, cluster_settings: dict) -> dict:
    """Merge cluster defaults/persistent/transient under the running node settings. Node settings
    reflect the actual static config (elasticsearch.yml) and win; transient wins among cluster
    tiers."""
    combined: dict = {}
    cs = cluster_settings or {}
    for tier in ("defaults", "persistent", "transient"):
        combined.update(cs.get(tier) or {})
    combined.update(node_settings or {})
    return combined


def _determine_security_disabled(distribution, settings: dict, snapshot: dict):
    """(disabled|None, reason). Explicit settings first, then the behavioural authenticate probe.
    None = no authoritative signal was readable → the detector answers not-assessable, never a
    clean pass."""
    xpack = settings.get("xpack.security.enabled")
    if _to_bool(xpack) is False:
        return True, "xpack.security.enabled=false"
    plugins_disabled = settings.get("plugins.security.disabled")
    if _to_bool(plugins_disabled) is True:
        return True, "plugins.security.disabled=true"
    if _to_bool(xpack) is True:
        return False, "xpack.security.enabled=true"
    if _to_bool(plugins_disabled) is False:
        return False, "plugins.security.disabled=false"
    if snapshot.get("authenticate_not_enabled"):
        return True, "GET /_security/_authenticate reports security is not enabled"
    if snapshot.get("authenticate_status") == 200:
        return False, "GET /_security/_authenticate returned 200 (a security realm is active)"
    return None, "no authoritative security-enablement setting or probe was readable"


# ── NHI parse helpers (pure — never store a hash value) ───────────────────────
def _normalise_es_users(data) -> list:
    """Elasticsearch GET /_security/user → a list of user dicts. ES never returns a password or
    hash, so has_password reflects that a native-realm user necessarily has one; hashing is
    unknown (the native realm's storage is not exposed)."""
    out = []
    for username, u in (data or {}).items():
        if not isinstance(u, dict):
            continue
        meta = u.get("metadata") or {}
        out.append({
            "username": username,
            "roles": list(u.get("roles") or []),
            "enabled": u.get("enabled"),
            "reserved": bool(meta.get("_reserved")),
            "has_password": True,
            "hashing": "unknown",
        })
    return out


def _normalise_os_users(data) -> list:
    """OpenSearch GET /_plugins/_security/api/internalusers → user dicts carrying a bcrypt `hash`.
    The hash VALUE is dropped here — only has_password + the algorithm name survive."""
    out = []
    for username, u in (data or {}).items():
        if not isinstance(u, dict):
            continue
        roles = list(u.get("backend_roles") or []) + list(u.get("opendistro_security_roles") or [])
        out.append({
            "username": username,
            "roles": roles,
            "enabled": not u.get("disabled", False),
            "reserved": bool(u.get("reserved") or u.get("static")),
            "has_password": bool(u.get("hash")),   # presence only; the hash never leaves here
            "hashing": "bcrypt" if u.get("hash") else "unknown",
        })
    return out


def _normalise_es_roles(data) -> list:
    out = []
    for name, r in (data or {}).items():
        if not isinstance(r, dict):
            continue
        indices = [{"names": list(i.get("names") or []),
                    "privileges": list(i.get("privileges") or [])}
                   for i in (r.get("indices") or [])]
        out.append({"name": name, "cluster": list(r.get("cluster") or []), "indices": indices})
    return out


def _normalise_os_roles(data) -> list:
    out = []
    for name, r in (data or {}).items():
        if not isinstance(r, dict):
            continue
        indices = [{"names": list(i.get("index_patterns") or []),
                    "privileges": list(i.get("allowed_actions") or [])}
                   for i in (r.get("index_permissions") or [])]
        out.append({"name": name, "cluster": list(r.get("cluster_permissions") or []),
                    "indices": indices})
    return out


# ── pure normalisation: snapshot -> Collected ─────────────────────────────────
def _build_resources(snapshot: dict) -> Collected:
    resources: list[Resource] = []
    edges: list[Edge] = []

    settings = snapshot.get("settings") or {}
    distribution = snapshot.get("distribution")
    settings_readable = bool(snapshot.get("settings_readable", bool(settings)))

    disabled, reason = _determine_security_disabled(distribution, settings, snapshot)

    http_ssl = _first_bool(settings, ("xpack.security.http.ssl.enabled",
                                      "plugins.security.ssl.http.enabled"))
    transport_ssl = _first_bool(settings, ("xpack.security.transport.ssl.enabled",
                                           "plugins.security.ssl.transport.enabled"))
    anonymous_roles = _values_under(settings, "xpack.security.authc.anonymous.roles")
    audit_enabled = _first_bool(settings, ("xpack.security.audit.enabled",))
    cors_enabled = _first_bool(settings, ("http.cors.enabled",))
    cors_allow_origin = settings.get("http.cors.allow-origin")
    transport_verification_mode = settings.get("xpack.security.transport.ssl.verification_mode")

    cluster_ext = "es-cluster"
    cluster = Resource(
        kind="es_cluster",
        name=snapshot.get("cluster_name") or snapshot.get("base_url") or "es-cluster",
        ext_id=cluster_ext,
        labels={"distribution": str(distribution or "?"),
                "version": str(snapshot.get("version") or "?")},
        raw={
            "distribution": distribution,
            "version": snapshot.get("version"),
            "cluster_name": snapshot.get("cluster_name"),
            "base_url": snapshot.get("base_url"),
            "scheme": snapshot.get("scheme"),
            "tls_verified": snapshot.get("tls_verified"),
            "security_disabled": disabled,
            "security_disabled_reason": reason,
            "http_ssl_enabled": http_ssl,
            "transport_ssl_enabled": transport_ssl,
            "anonymous_roles": anonymous_roles,
            "audit_enabled": audit_enabled,
            "cors_enabled": cors_enabled,
            "cors_allow_origin": cors_allow_origin,
            "transport_verification_mode": transport_verification_mode,
            "anon_root_status": snapshot.get("anon_root_status"),
            "anon_access": snapshot.get("anon_root_status") == 200,
            "settings_readable": settings_readable,
            "snapshot_repos": snapshot.get("snapshot_repos") or {},
            "endpoint_outcomes": snapshot.get("endpoint_outcomes") or {},
            "users_readable": snapshot.get("users_readable"),
            "roles_readable": snapshot.get("roles_readable"),
        },
    )
    resources.append(cluster)

    # ── indices: inventory + whether the unauthenticated _cat/indices probe returned them ──
    anon_names = set(snapshot.get("anon_indices") or [])
    anon_probe_ran = snapshot.get("anon_indices_status") == 200
    for idx in snapshot.get("indices") or []:
        name = idx.get("index") if isinstance(idx, dict) else str(idx)
        if not name:
            continue
        anon_listable = anon_probe_ran and name in anon_names
        resources.append(Resource(
            kind="es_index",
            name=name,
            ext_id=f"es-index-{name}",
            labels={"health": str((idx or {}).get("health") if isinstance(idx, dict) else "?"),
                    "system": "true" if name.startswith(".") else "false"},
            raw={
                "index": name,
                "health": (idx or {}).get("health") if isinstance(idx, dict) else None,
                "status": (idx or {}).get("status") if isinstance(idx, dict) else None,
                "docs_count": (idx or {}).get("docs.count") if isinstance(idx, dict) else None,
                "store_size": (idx or {}).get("store.size") if isinstance(idx, dict) else None,
                "system_index": name.startswith("."),
                "anon_listable": anon_listable,
                "cluster_ext": cluster_ext,
            },
        ))

    # ── users + roles (NHI material) ──
    for u in snapshot.get("users") or []:
        uname = u.get("username")
        if not uname:
            continue
        resources.append(Resource(
            kind="es_user",
            name=str(uname),
            ext_id=f"es-user-{uname}",
            labels={"enabled": "true" if u.get("enabled") else "false",
                    "reserved": "true" if u.get("reserved") else "false"},
            raw={**u, "cluster_ext": cluster_ext},
        ))
    for role in snapshot.get("roles") or []:
        rname = role.get("name")
        if not rname:
            continue
        resources.append(Resource(
            kind="es_role",
            name=str(rname),
            ext_id=f"es-role-{rname}",
            labels={},
            raw={**role, "cluster_ext": cluster_ext},
        ))

    return Collected(resources=resources, edges=edges)


# ── collection (httpx in, per-endpoint isolation) ─────────────────────────────
def _get(client, path, *, auth=None, headers=None):
    """One read → an envelope, never a bare value: a 401/403 must stay distinguishable from an
    empty result, or every rule gated on the endpoint silently passes."""
    import httpx
    try:
        r = client.get(path, auth=auth, headers=headers)
    except httpx.HTTPError as e:
        return {"ok": False, "status": None, "error": f"{type(e).__name__}: {e}"}
    body = None
    try:
        body = r.json()
    except ValueError:
        body = None
    return {"ok": r.status_code == 200, "status": r.status_code, "data": body,
            "text": None if body is not None else (r.text or "")}


def _outcome(env: dict) -> str:
    if env.get("ok"):
        return "ok"
    if env.get("status") in (401, 403):
        return "forbidden"
    return "error"


@connector("elasticsearch", fields=[
    ConnectorField("base_url", "Base URL", required=True, placeholder="https://localhost:9200",
                   help="Elasticsearch or OpenSearch REST endpoint. GET-only — no writes, no "
                        "document reads."),
    ConnectorField("username", "Username", placeholder="vectasec_ro",
                   help="Basic-auth user with a read/monitoring role (the `monitor` cluster "
                        "privilege plus read on the security indices for the NHI inventory)."),
    ConnectorField("password", "Password", secret=True,
                   help="Used to open the session; never persisted into any resource."),
    ConnectorField("api_key", "API key", secret=True,
                   help="Base64 'id:api_key' as an alternative to username/password "
                        "(Elasticsearch). Sent as the Authorization: ApiKey header."),
    ConnectorField("verify_tls", "Verify TLS", placeholder="true",
                   help="'false' only for a self-signed dev cluster."),
])
def collect(config: dict) -> Collected:
    import httpx

    base = (config.get("base_url") or "").strip().rstrip("/")
    if not base:
        raise SystemExit("elasticsearch connector requires config['base_url']")
    timeout = float(config.get("timeout") or 15)
    verify = _to_bool(config.get("verify_tls"))
    verify = True if verify is None else verify

    user = (config.get("username") or "").strip()
    password = config.get("password") or ""
    api_key = (config.get("api_key") or "").strip()
    auth = (user, password) if user else None
    headers = {"Authorization": f"ApiKey {api_key}"} if api_key else None

    scheme = urlparse(base).scheme or "http"

    with httpx.Client(base_url=base, timeout=timeout, verify=bool(verify),
                      follow_redirects=False) as client:
        root = _get(client, "/", auth=auth, headers=headers)
        anon_root = _get(client, "/")
        anon_indices = _get(client, "/_cat/indices?format=json&h=index")
        node_settings = _get(client, "/_nodes/settings?flat_settings=true",
                             auth=auth, headers=headers)
        cluster_settings = _get(client, "/_cluster/settings?include_defaults=true&flat_settings=true",
                                auth=auth, headers=headers)
        indices = _get(client, "/_cat/indices?format=json", auth=auth, headers=headers)
        authenticate = _get(client, "/_security/_authenticate", auth=auth, headers=headers)
        snapshots = _get(client, "/_snapshot", auth=auth, headers=headers)

        root_data = root.get("data") or {}
        version_block = root_data.get("version") or {}
        distribution = (version_block.get("distribution")
                        or ("opensearch" if "opensearch" in str(root_data.get("tagline", "")).lower()
                            else "elasticsearch"))

        if distribution == "opensearch":
            users_env = _get(client, "/_plugins/_security/api/internalusers",
                             auth=auth, headers=headers)
            roles_env = _get(client, "/_plugins/_security/api/roles", auth=auth, headers=headers)
            users = _normalise_os_users(users_env.get("data")) if users_env.get("ok") else []
            roles = _normalise_os_roles(roles_env.get("data")) if roles_env.get("ok") else []
        else:
            users_env = _get(client, "/_security/user", auth=auth, headers=headers)
            roles_env = _get(client, "/_security/role", auth=auth, headers=headers)
            users = _normalise_es_users(users_env.get("data")) if users_env.get("ok") else []
            roles = _normalise_es_roles(roles_env.get("data")) if roles_env.get("ok") else []

    node_flat: dict = {}
    for node in (node_settings.get("data") or {}).get("nodes", {}).values():
        node_flat.update((node or {}).get("settings") or {})

    cs_data = cluster_settings.get("data") or {}

    # ES answers /_security/_authenticate with a 400/403 body mentioning "security is not enabled"
    # when x-pack security is off — the behavioural signal used when the setting is unreadable.
    auth_text = (authenticate.get("text") or "")
    auth_body = authenticate.get("data")
    if isinstance(auth_body, dict):
        auth_text += " " + str(auth_body)
    authenticate_not_enabled = ("security is not enabled" in auth_text.lower()
                                or "no handler found" in auth_text.lower())

    snapshot = {
        "base_url": base,
        "scheme": scheme,
        "tls_verified": scheme == "https" and verify is True and root.get("status") is not None,
        "distribution": distribution,
        "version": version_block.get("number"),
        "cluster_name": root_data.get("cluster_name"),
        "settings": _flatten_settings(node_flat, cs_data),
        "settings_readable": node_settings.get("ok") or cluster_settings.get("ok"),
        "anon_root_status": anon_root.get("status"),
        "anon_indices_status": anon_indices.get("status"),
        "anon_indices": [i.get("index") for i in (anon_indices.get("data") or [])
                         if isinstance(i, dict)] if anon_indices.get("ok") else [],
        "authenticate_status": authenticate.get("status"),
        "authenticate_not_enabled": authenticate_not_enabled,
        "indices": indices.get("data") if indices.get("ok") else [],
        "indices_readable": indices.get("ok"),
        "snapshot_repos": snapshots.get("data") if snapshots.get("ok") else {},
        "users": users,
        "users_readable": users_env.get("ok"),
        "roles": roles,
        "roles_readable": roles_env.get("ok"),
        "endpoint_outcomes": {
            "node_settings": _outcome(node_settings),
            "cluster_settings": _outcome(cluster_settings),
            "indices": _outcome(indices),
            "security_users": _outcome(users_env),
            "security_roles": _outcome(roles_env),
            "snapshots": _outcome(snapshots),
        },
    }
    return _build_resources(snapshot)


# ── NHI: es_user → identity + credential, roles → grants ──────────────────────
@identity_extractor("elasticsearch")
def _from_elasticsearch(resources: list) -> tuple:
    """Elasticsearch/OpenSearch users and their roles in the normalized NHI model:

      es_user  → identity (service_account; type 'superuser' when it holds a superuser role) +
                 one credential per user with a password (metadata only — no hash value)
      user.roles → one grant per role, wildcard when the role is superuser/all_access/admin

    Edges: credential --credential_of--> identity, grant --granted_to--> identity. Roles are
    templates, not principals, so es_role emits no identity of its own; the generic NHI pack
    (grant_wildcard, identity_shared_default, credential_weak_hash) then runs on these.
    """
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "es_user":
            continue
        raw = r.raw or {}
        name = raw.get("username") or r.name
        roles = raw.get("roles") or []
        superuser = any(str(role).lower() in _SUPERUSER_ROLES for role in roles)
        itype = "superuser" if superuser else "service_account"
        idr = _mk_identity("elasticsearch", itype, name, source_ext=r.ext_id,
                           tags=(["reserved"] if raw.get("reserved") else []),
                           extra={"enabled": raw.get("enabled"), "reserved": raw.get("reserved")})
        out.append(idr)

        if raw.get("has_password"):
            cred = _mk_credential(
                "elasticsearch", idr.ext_id, "password", name=f"{name}:password",
                hashing=(raw.get("hashing") or "unknown"), present=True, plaintext=False,
                is_default=bool(raw.get("reserved")))
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

        for role in roles:
            g = _mk_grant("elasticsearch", idr.ext_id, "role", str(role),
                          wildcard=str(role).lower() in _SUPERUSER_ROLES,
                          extra={"role": str(role)})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
