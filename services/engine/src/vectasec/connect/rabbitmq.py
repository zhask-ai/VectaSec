"""RabbitMQ connector — read-only Management HTTP API (httpx, HTTP Basic).

Only GETs are issued. Two requests deliberately do not carry the scanner's credentials:
`GET /api/auth` is unauthenticated (that endpoint answering at all is the CVE), and the
`guest:guest` `GET /api/whoami` probe is the only way to observe the loopback restriction
from outside. Neither mutates broker state.

Credential material never leaves this module. `/api/users` returns `password_hash` for every
user and `/api/auth` may return an OAuth client secret; both are reduced to booleans here,
before anything reaches the `raw` dict that gets persisted to the ledger.

Onboarding note: RabbitMQ has no read-only-administrator tag. `/api/users` and
`/api/permissions` are administrator-only, so the PERMISSION.* and USER.* rules require a
credential that is inherently write-capable and self-restricted to GETs by this connector.
A `monitoring`-tagged credential covers everything else.
"""
import base64
import hashlib
import hmac
import ipaddress
import socket
from urllib.parse import urlparse

import httpx

from ..registry import connector
from ..contracts import Resource, Edge, Collected

# Named in the rulepack's suppression table: each one is a real deployment shape that the
# Management API provably cannot observe (proxies, meshes, backports, external auth).
_TOGGLES = (
    "proxy_terminates_tls", "transparent_tls_mesh", "backported_build",
    "external_auth_backend", "environment_scope", "provisioning_accounts",
    "managed_provider", "reachability_signal",
)

# /api/nodes returns ~100 mostly-metric fields; ?columns= is verified to work on this
# endpoint (it is silently ignored on /api/vhosts, so that call stays unfiltered).
_NODE_COLUMNS = ",".join((
    "name", "running", "type", "auth_mechanisms", "applications", "rabbitmq_version",
    "partitions", "enabled_plugins", "being_drained", "config_files",
))

_HASH_FNS = {
    "rabbit_password_hashing_sha256": "sha256",
    "rabbit_password_hashing_sha512": "sha512",
    "rabbit_password_hashing_md5": "md5",
}


def _norm_tags(tags) -> list:
    """JSON array on 3.9+, comma-separated string before that."""
    if isinstance(tags, str):
        return [t.strip() for t in tags.split(",") if t.strip()]
    return [str(t) for t in tags or []]


def _verify_password(password_hash, algorithm, candidate: str):
    """Offline check of a candidate password against RabbitMQ's stored hash.

    Runs here, at ingest, precisely so the hash can be dropped immediately — only the verdict
    survives. Construction per docs/passwords: 4-byte salt || digest(salt || utf8(password)),
    base64. Honours the per-user algorithm; a plugin-supplied module returns None (unknown),
    never False, because "cannot verify" is not "not the default".
    """
    name = _HASH_FNS.get(algorithm or "")
    if not name or not password_hash:
        return None
    try:
        raw = base64.b64decode(password_hash, validate=True)
    except ValueError:
        return None
    if len(raw) <= 4:
        return None
    salt, digest = raw[:4], raw[4:]
    return hmac.compare_digest(hashlib.new(name, salt + candidate.encode()).digest(), digest)


def _source_is_loopback(host: str):
    """Whether the broker will see this scanner as a loopback peer.

    The management listener has no proxy_protocol support, so the broker always sees the real
    TCP peer: connecting to a loopback address means we present as loopback, which invalidates
    the guest probe. None = unresolvable, treated as "don't know" (probe is skipped).
    """
    if not host:
        return None
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return None
    addrs = []
    for i in infos:
        try:
            addrs.append(ipaddress.ip_address(i[4][0]))
        except ValueError:
            continue
    return any(a.is_loopback for a in addrs) if addrs else None


def _get(client: httpx.Client, path: str, auth):
    """One read. Returns an envelope, never a bare value: a 401 must stay distinguishable
    from an empty result, or every rule gated on this endpoint silently passes."""
    try:
        r = client.get(path, auth=auth)
    except httpx.HTTPError as e:
        return {"ok": False, "status": None, "error": f"{type(e).__name__}: {e}"}
    if r.status_code != 200:
        return {"ok": False, "status": r.status_code, "error": f"http_{r.status_code}",
                "reason": _reason(r)}
    try:
        return {"ok": True, "status": 200, "data": r.json()}
    except ValueError:
        return {"ok": False, "status": 200, "error": "non_json_body"}


def _reason(r: httpx.Response):
    """401s on this API are inconsistent: `/api/overview` returns content-length 0 while
    the access-control layer's halt_response writes {"error":..,"reason":..}. Parse if there
    is a body; absence is recorded as None, never guessed at."""
    if not r.content:
        return None
    try:
        body = r.json()
    except ValueError:
        return None
    return body.get("reason") if isinstance(body, dict) else None


def _guest_probe(client: httpx.Client, src_loopback):
    """`GET /api/whoami` as guest:guest. Read-only, but only meaningful from a non-loopback
    source — from the broker host it produces a guaranteed false negative, so it is skipped."""
    if src_loopback is not False:
        return {"skipped": "scanner source address is loopback or unresolved; "
                           "a guest probe from loopback cannot distinguish a relaxed "
                           "loopback_users setting from the default"}
    res = _get(client, "/api/whoami", ("guest", "guest"))
    out = {"status": res.get("status"), "reason": res.get("reason")}
    if res.get("ok"):
        d = res.get("data") or {}
        out.update(name=d.get("name"), tags=_norm_tags(d.get("tags")),
                   is_internal_user=d.get("is_internal_user"))
    return out


def _auth_probe(client: httpx.Client):
    """Unauthenticated `GET /api/auth` — CVE-2026-57219. The secret's VALUE is never recorded:
    presence is the whole finding, and storing it would re-leak it into the ledger."""
    res = _get(client, "/api/auth", None)
    if not res.get("ok"):
        return {"status": res.get("status"), "error": res.get("error")}
    d = res.get("data") or {}
    secret = d.get("oauth_client_secret")
    return {
        "status": 200,
        # filter_empty_properties/1 omits the key entirely when unset, so "present and
        # non-empty" is exactly the server's own predicate for "a secret is configured".
        "oauth_client_secret_present": isinstance(secret, str) and secret != "",
        "oauth_enabled": d.get("oauth_enabled"),
        "oauth_client_id": d.get("oauth_client_id"),
        "keys": sorted(k for k in d if k != "oauth_client_secret"),
    }


def _rabbit_app_version(node: dict):
    """Per-node version lives in applications[name=="rabbit"].version — /api/nodes has no
    dedicated version field and `name` is a node id, not a version."""
    for app in node.get("applications") or []:
        if app.get("name") == "rabbit":
            return app.get("version")
    return node.get("rabbitmq_version")


@connector("rabbitmq")
def collect(config: dict) -> Collected:
    base = (config.get("url") or "").rstrip("/")
    if not base:
        raise SystemExit("rabbitmq connector requires config['url'] "
                         "(e.g. https://rabbit.example:15671)")
    auth = (config.get("username") or "", config.get("password") or "")
    verify = config.get("verify_tls", True)
    timeout = float(config.get("timeout") or 10)

    parsed = urlparse(base)
    scheme = parsed.scheme or "http"
    src_loopback = config.get("source_is_loopback")
    if src_loopback is None:
        src_loopback = _source_is_loopback(parsed.hostname or "")

    # Client carries no auth: every request states its own, so the two credential-less
    # probes cannot silently inherit the scanner's identity.
    with httpx.Client(base_url=base, timeout=timeout, verify=bool(verify),
                      follow_redirects=False, auth=None) as client:
        overview = _get(client, "/api/overview", auth)
        nodes = _get(client, f"/api/nodes?columns={_NODE_COLUMNS}", auth)
        users = _get(client, "/api/users", auth)
        vhosts = _get(client, "/api/vhosts", auth)       # ?columns= is ignored here
        perms = _get(client, "/api/permissions", auth)
        whoami = _get(client, "/api/whoami", auth)
        probes = {"auth": _auth_probe(client), "guest_whoami": _guest_probe(client, src_loopback)}

    ov = overview.get("data") if overview.get("ok") else None
    node_data = nodes.get("data") if nodes.get("ok") else None
    who = whoami.get("data") if whoami.get("ok") else None

    resources: list = []
    edges: list = []

    node_versions = {}
    for n in node_data or []:
        v = _rabbit_app_version(n)
        if v:
            node_versions[n.get("name")] = v

    # The cluster resource. /api/overview's listeners and contexts are cluster-wide (every
    # node's listeners are appended), so listener rules hang off this single resource — one
    # per node would fingerprint N copies of one real-world issue.
    cluster = Resource(
        kind="node",
        name=(ov or {}).get("cluster_name") or base,
        ext_id="cluster",
        labels={"role": "cluster", "url": base},
        raw={
            "role": "cluster",
            "url": base,
            "overview": ov,
            "overview_error": None if overview.get("ok") else overview.get("error"),
            "nodes_error": None if nodes.get("ok") else nodes.get("error"),
            "users_error": None if users.get("ok") else users.get("error"),
            "vhosts_error": None if vhosts.get("ok") else vhosts.get("error"),
            "permissions_error": None if perms.get("ok") else perms.get("error"),
            "node_versions": node_versions,
            "probes": probes,
            "scanner": {
                "scheme": scheme,
                # Suppression signal for MGMT.HTTP_API_NO_TLS: if OUR hop was verified TLS,
                # something upstream is terminating it and the rule cannot see the proxy.
                "tls_verified": scheme == "https" and verify is True
                                and overview.get("status") is not None,
                "source_is_loopback": src_loopback,
                "whoami": {"name": (who or {}).get("name"),
                           "tags": _norm_tags((who or {}).get("tags"))} if who else None,
            },
            "toggles": {k: config.get(k) for k in _TOGGLES},
        },
    )
    resources.append(cluster)

    for n in node_data or []:
        name = n.get("name") or ""
        resources.append(Resource(
            kind="node",
            name=name,
            ext_id=f"node-{name}",
            labels={"role": "node", "running": str(n.get("running"))},
            raw={
                "role": "node",
                "name": name,
                "running": n.get("running"),
                "type": n.get("type"),
                "auth_mechanisms": n.get("auth_mechanisms"),
                "rabbitmq_version": _rabbit_app_version(n),
                "partitions": n.get("partitions"),
                "enabled_plugins": n.get("enabled_plugins"),
                "being_drained": n.get("being_drained"),
                "config_files": n.get("config_files"),
            },
        ))
        edges.append(Edge(src_ext_id="cluster", dst_ext_id=f"node-{name}", kind="member"))

    for v in (vhosts.get("data") or []) if vhosts.get("ok") else []:
        name = v.get("name")
        resources.append(Resource(
            kind="vhost",
            name=name or "",
            ext_id=f"vhost-{name}",
            labels={"tracing": str(v.get("tracing"))},
            raw={
                "name": name,
                "tracing": v.get("tracing"),
                "description": v.get("description"),
                "tags": _norm_tags(v.get("tags")),
                "default_queue_type": v.get("default_queue_type"),
                "cluster_state": v.get("cluster_state"),
                "protected_from_deletion": v.get("protected_from_deletion"),
            },
        ))

    for u in (users.get("data") or []) if users.get("ok") else []:
        name = u.get("name")
        # The one place password_hash is touched. Verified offline against the well-known
        # default, then dropped — it is never returned, stored, logged or re-hashed.
        default_pw = (_verify_password(u.get("password_hash"), u.get("hashing_algorithm"), "guest")
                      if name == "guest" else None)
        tags = _norm_tags(u.get("tags"))
        resources.append(Resource(
            kind="user",
            name=name or "",
            ext_id=f"user-{name}",
            labels={"tags": ",".join(tags)},
            raw={
                "name": name,
                "tags": tags,
                "hashing_algorithm": u.get("hashing_algorithm"),
                # "" is how a password is cleared, i.e. an external-auth-backend user.
                "has_internal_password": bool(u.get("password_hash")),
                "default_password_confirmed": default_pw,
                "limits": u.get("limits") or {},
            },
        ))

    for p in (perms.get("data") or []) if perms.get("ok") else []:
        user, vhost = p.get("user"), p.get("vhost")
        ext_id = f"permission-{vhost}-{user}"
        resources.append(Resource(
            kind="permission",
            name=f"{user}@{vhost}",
            ext_id=ext_id,
            namespace=vhost,
            labels={"user": str(user), "vhost": str(vhost)},
            raw={
                "user": user, "vhost": vhost,
                "configure": p.get("configure"),
                "write": p.get("write"),
                "read": p.get("read"),
            },
        ))
        edges.append(Edge(src_ext_id=ext_id, dst_ext_id=f"user-{user}", kind="grants"))
        edges.append(Edge(src_ext_id=ext_id, dst_ext_id=f"vhost-{vhost}", kind="scopes"))

    return Collected(resources=resources, edges=edges)
