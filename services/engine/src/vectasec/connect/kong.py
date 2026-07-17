"""Kong connector — read-only Admin API over httpx.

Only GET is ever issued. Two clients exist on purpose: the credentialed one that collects the
inventory, and an anonymous one used solely for the KONG.ADMIN.UNAUTHENTICATED probes — a probe
that inherits a Kong-Admin-Token proves nothing about unauthenticated reachability.

config: {"url": "http://kong:8001", "admin_token": "...", "timeout": 10, "verify": true,
         "collect_consumer_credentials": true, "consumer_credential_limit": 200}
"""
import ipaddress
import re
from urllib.parse import urlsplit

import httpx

from ..registry import ConnectorField, connector
from ..contracts import Resource, Edge, Collected

# `GET /`.configuration is sanitised server-side (kong/api/routes/kong.lua calls remove_sensitive(),
# stripping pg_password, ssl_cert_key, $refs …) but still dumps the entire node config — prefixes,
# filesystem paths, every nginx directive. Only the keys the rulepack reads are kept, and only when
# Kong actually returned them: absence in `raw` has to keep meaning absence in the response, because
# the edition gates are built on exactly that (no `enforce_rbac` key ⇒ OSS ⇒ rule not applicable).
_CONFIG_KEYS = (
    "admin_listen", "proxy_listen", "enforce_rbac", "rbac_auth_header",
    "database", "role", "trusted_ips", "nginx_http_client_max_body_size",
)

# Unlike `.configuration`, plugin `config` is NOT redacted by the Admin API — a rate-limiting plugin
# hands back redis_password in cleartext. Scrub on the way in, before it can reach the resources
# table. A None stays None so "unset" remains distinguishable from "set to something": several rules
# turn on precisely that distinction.
_SECRET_KEY = re.compile(r"(password|passwd|secret|token|_key$|^key$)", re.I)

# Keys the rulepack reads, exempted from scrubbing. This is a guard, not decoration: redacting a key
# a rule reads disables that rule *silently* rather than failing loudly. Verified against a live
# node — a `credential` term in _SECRET_KEY matched cors's `credentials` boolean (and key-auth's
# `hide_credentials`), redacted it, and killed KONG.CORS.WILDCARD_WITH_CREDENTIALS outright while
# protecting no secret. None of these ever holds a credential value.
_RULE_KEYS = {"anonymous", "origins", "credentials", "policy", "fault_tolerant", "allow", "deny"}

_CREDENTIAL_PATHS = ("key-auth", "basic-auth", "jwt", "hmac-auth", "oauth2", "acls", "mtls-auth")

# Presence of any of these means consumers are mapped from an external IdP by claim/username and
# legitimately carry zero local credentials, so KONG.CONSUMER.NO_CREDENTIALS is skipped wholesale —
# and with it the O(consumers × credential-types) sweep, which is the most expensive call in the pack.
_EXTERNAL_IDENTITY_PLUGINS = {"openid-connect", "ldap-auth-advanced"}

_WILDCARD_HOSTS = {"0.0.0.0", "::", "*", "0.0.0.0/0"}


def _is_loopback(host: str) -> bool:
    h = (host or "").strip().strip("[]").lower()
    if h == "localhost":                       # not an IP literal; ip_address() rejects it
        return True
    try:
        return ipaddress.ip_address(h).is_loopback   # the whole of 127.0.0.0/8, plus ::1
    except ValueError:
        return False


def _scrub(value):
    if isinstance(value, dict):
        return {k: ((None if v is None else "[redacted]")
                    if k not in _RULE_KEYS and _SECRET_KEY.search(k) else _scrub(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _url(base: str, path: str) -> str:
    # Admin API paths are absolute ('/plugins'), and Kong's `next` cursor is a relative *path*, so
    # urljoin would wipe out a base URL served under a prefix (http://gw/kong-admin). Splice instead.
    s = urlsplit(base)
    return f"{s.scheme}://{s.netloc}{s.path.rstrip('/')}{path}"


def _get(client: httpx.Client, base: str, path: str) -> dict:
    r = client.get(_url(base, path))
    r.raise_for_status()
    return r.json()


def _paginate(client: httpx.Client, base: str, path: str, size: int = 1000) -> list:
    """Walk a list endpoint to exhaustion. `size=1000` is Kong's max_page_size, not "all".

    Two traps live here. Kong's `next` is a relative path, and it stays non-null on the last
    *populated* page — so the loop can only terminate on `next is None`, at the cost of one extra
    empty request. Short-circuiting on `len(data) < size` looks equivalent and is not: Kong does not
    guarantee it, and for the "no protective plugin resolves to this route" rules a truncated list
    produces false FAILs, not false PASSes. `offset` is an opaque cursor — never construct one.
    """
    out, nxt = [], f"{path}?size={size}"
    while nxt:
        body = _get(client, base, nxt)
        out.extend(body.get("data") or [])
        nxt = body.get("next")
    return out


def _workspaces(client: httpx.Client, base: str, edition) -> list:
    """Enterprise scopes /plugins, /routes, /services and /consumers per workspace. Collecting
    routes from every workspace while collecting plugins from `default` alone would false-FAIL every
    "route has no auth plugin" rule, so all four are walked per workspace or none are. OSS has no
    workspaces and 404s here.
    """
    if edition != "enterprise":
        return [("", "")]
    try:
        rows = _paginate(client, base, "/workspaces")
    except httpx.HTTPStatusError:
        return [("", "")]
    names = [w.get("name") for w in rows if w.get("name")]
    return [(n, f"/{n}") for n in names] or [("", "")]


def _probe_unauthenticated(base: str, timeout: float, verify) -> dict:
    """The two KONG.ADMIN.UNAUTHENTICATED probes, on a client carrying no token and no client cert.

    They are recorded separately because they answer different questions and must not be OR'd into
    one verdict: probe A is reachability (a 200 is the only possible OSS posture, not a defect on its
    own), probe B is whether Enterprise RBAC is actually enforcing. The probe origin is recorded
    because it is what separates "high" from "critical" on three rules — a 200 from a sidecar against
    127.0.0.1 is expected and safe; the same 200 from off-host is gateway takeover.
    """
    out = {"origin": "loopback" if _is_loopback(urlsplit(base).hostname or "") else "remote"}
    with httpx.Client(timeout=timeout, verify=verify, follow_redirects=False) as anon:
        try:
            r = anon.get(_url(base, "/"))
            body = r.json() if "application/json" in r.headers.get("content-type", "") else {}
            out["root"] = {"status": r.status_code, "tagline": body.get("tagline"),
                           "edition": body.get("edition"), "version": body.get("version")}
        except Exception as e:
            out["root"] = {"status": None, "error": f"{type(e).__name__}: {e}"}

        try:
            r = anon.get(_url(base, "/rbac/users"))
            if r.status_code == 200:
                # Deliberately not storing the body. A 200 here means the RBAC user list is
                # world-readable — the count *is* the whole finding, and copying the users into our
                # own store would only relocate the exposure.
                out["rbac_users"] = {"status": 200, "count": len(r.json().get("data") or [])}
            else:
                # The snippet is load-bearing on the 401 branch: RBAC-on is identified by the body
                # containing "Invalid RBAC credentials", and some versions return the longer
                # "...Token or User credentials required" — so the detector substring-matches.
                out["rbac_users"] = {"status": r.status_code, "body_snippet": r.text[:200]}
        except Exception as e:
            out["rbac_users"] = {"status": None, "error": f"{type(e).__name__}: {e}"}
    return out


def _consumer_credentials(client: httpx.Client, base: str, prefix: str, cid: str) -> dict:
    """Counts, never values: GET /consumers/{id}/key-auth returns the API key in cleartext and no
    rule needs it. ACL *group names* are the exception — they are not secrets, and
    KONG.AUTH.ANONYMOUS_FALLBACK cannot check config.deny/config.allow disjointness without them.

    404 is not emptiness. mtls-auth is Enterprise-only, so on OSS the endpoint does not exist; the
    status of each endpoint is recorded so the detector can require "every endpoint that answered 200
    was empty, and at least one answered 200" rather than reading a 404 as "no credentials".
    """
    out = {}
    for path in _CREDENTIAL_PATHS:
        try:
            r = client.get(_url(base, f"{prefix}/consumers/{cid}/{path}"))
        except Exception as e:
            out[path] = {"status": None, "error": f"{type(e).__name__}: {e}"}
            continue
        if r.status_code != 200:
            out[path] = {"status": r.status_code}
            continue
        data = r.json().get("data") or []
        entry = {"status": 200, "count": len(data)}
        if path == "acls":
            entry["groups"] = [a.get("group") for a in data if a.get("group")]
        out[path] = entry
    return out


def _consumer_groups(client: httpx.Client, base: str, prefix: str, cid: str) -> dict:
    try:
        r = client.get(_url(base, f"{prefix}/consumers/{cid}/consumer_groups"))
    except Exception as e:
        return {"status": None, "error": f"{type(e).__name__}: {e}"}
    if r.status_code != 200:
        return {"status": r.status_code}                      # 404 on OSS — groups are Enterprise
    return {"status": 200, "names": [g.get("name") for g in (r.json().get("data") or [])]}


@connector("kong", fields=[
    ConnectorField("url", "Admin API URL", required=True,
                   placeholder="http://localhost:8001",
                   help="Kong Admin API base URL. GETs only."),
    ConnectorField("admin_token", "Admin token", secret=True,
                   help="Kong-Admin-Token for RBAC-enabled gateways — use a read-only role."),
])
def collect(config: dict) -> Collected:
    base = config["url"].rstrip("/")
    timeout = float(config.get("timeout", 10))
    verify = config.get("verify", True)
    token = config.get("admin_token")
    headers = {"Kong-Admin-Token": token} if token else {}

    probes = _probe_unauthenticated(base, timeout, verify)

    with httpx.Client(timeout=timeout, verify=verify, headers=headers,
                      follow_redirects=False) as client:
        try:
            node = _get(client, base, "/")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise RuntimeError(
                    "Kong Admin API returned 401 to GET / — RBAC is enforcing. Supply "
                    "config['admin_token'] for a read-only RBAC user."
                ) from e
            raise

        edition = node.get("edition")
        cfg = node.get("configuration") or {}
        spaces = _workspaces(client, base, edition)

        plugins, routes, services, consumers = [], [], [], []
        for ws, prefix in spaces:
            for row in _paginate(client, base, f"{prefix}/plugins"):
                row["config"] = _scrub(row.get("config") or {})
                plugins.append((ws, row))
            for row in _paginate(client, base, f"{prefix}/routes"):
                routes.append((ws, row))
            for row in _paginate(client, base, f"{prefix}/services"):
                services.append((ws, row))
            for row in _paginate(client, base, f"{prefix}/consumers"):
                consumers.append((ws, row))

        # config.anonymous accepts a consumer id *or* a username, so both forms are collected —
        # an id-only match would miss every username-form reference.
        anon_refs = {a for _, p in plugins
                     if (a := (p.get("config") or {}).get("anonymous"))}

        ext_identity = any(p.get("name") in _EXTERNAL_IDENTITY_PLUGINS for _, p in plugins)
        limit = int(config.get("consumer_credential_limit", 200))
        sweep = (bool(config.get("collect_consumer_credentials", True))
                 and not ext_identity and len(consumers) <= limit)

        creds: dict = {}
        for ws, c in consumers:
            cid = c.get("id")
            # Even when the sweep is off, the anonymous consumer's ACL groups are still fetched:
            # KONG.AUTH.ANONYMOUS_FALLBACK cannot evaluate its mitigations without them, and it is a
            # handful of requests rather than O(consumers × types).
            if not cid or not (sweep or cid in anon_refs or c.get("username") in anon_refs):
                continue
            prefix = dict(spaces).get(ws, "")
            creds[cid] = {"credentials": _consumer_credentials(client, base, prefix, cid),
                          "consumer_groups": _consumer_groups(client, base, prefix, cid)}

    resources: list[Resource] = []
    edges: list[Edge] = []

    # fingerprint() is keyed on (tenant, rule_id, ext_id) and excludes the connection, so a node
    # ext_id has to be unique per target or two Kong connections in one tenant collapse into one
    # finding. The Admin API's host:port is the only identifier that is both unique per connection
    # and stable across restarts — `hostname` and `node_id` both churn when a container is recreated.
    s = urlsplit(base)
    node_ext = f"kong-node-{s.hostname}:{s.port or (443 if s.scheme == 'https' else 80)}"

    # kind="broker" is the rulepack's kind for node-level rules: contracts.py uses `broker` as the
    # generic "the server itself" kind (as the Kafka connector does), and the Kong node is that.
    resources.append(Resource(
        kind="broker",
        name=node.get("hostname") or s.hostname or "kong",
        ext_id=node_ext,
        labels={"edition": edition or "", "version": node.get("version") or ""},
        raw={
            "version": node.get("version"),
            "edition": edition,
            "hostname": node.get("hostname"),
            "node_id": node.get("node_id"),
            "configuration": {k: cfg[k] for k in _CONFIG_KEYS if k in cfg},
            "probes": probes,
            "workspaces": [ws for ws, _ in spaces],
            "consumer_credential_sweep": sweep,
        },
    ))

    for ws, sv in services:
        resources.append(Resource(
            kind="service", name=sv.get("name") or sv.get("id") or "?",
            ext_id=f"kong-service-{sv.get('id')}", namespace=ws or None,
            labels={"protocol": sv.get("protocol") or "", "host": sv.get("host") or ""},
            raw=sv,
        ))

    for ws, rt in routes:
        ext = f"kong-route-{rt.get('id')}"
        resources.append(Resource(
            kind="route", name=rt.get("name") or rt.get("id") or "?",
            ext_id=ext, namespace=ws or None,
            labels={"protocols": ",".join(rt.get("protocols") or [])},
            raw=rt,
        ))
        if (sid := (rt.get("service") or {}).get("id")):
            edges.append(Edge(src_ext_id=ext, dst_ext_id=f"kong-service-{sid}", kind="routes_to"))

    for ws, c in consumers:
        cid = c.get("id")
        resources.append(Resource(
            kind="consumer", name=c.get("username") or c.get("custom_id") or cid or "?",
            ext_id=f"kong-consumer-{cid}", namespace=ws or None,
            labels={"custom_id": c.get("custom_id") or ""},
            raw={**c, **creds.get(cid, {})},
        ))

    for ws, p in plugins:
        ext = f"kong-plugin-{p.get('id')}"
        resources.append(Resource(
            kind="plugin", name=p.get("instance_name") or p.get("name") or "?",
            ext_id=ext, namespace=ws or None,
            labels={"plugin": p.get("name") or "", "enabled": str(p.get("enabled", True)).lower()},
            raw=p,
        ))
        # The scoping triple (service/route/consumer, plus consumer_group) is how "auth is enforced
        # everywhere" is told apart from "auth is enforced on one route" — edge it so the graph shows
        # it. All null = global, which is edged to the node.
        for field, prefix in (("route", "kong-route-"), ("service", "kong-service-"),
                              ("consumer", "kong-consumer-")):
            if (ref := p.get(field)) and ref.get("id"):
                edges.append(Edge(src_ext_id=ext, dst_ext_id=f"{prefix}{ref['id']}",
                                  kind="scoped_to", labels={"scope": field}))
        if not any(p.get(f) for f in ("route", "service", "consumer", "consumer_group")):
            edges.append(Edge(src_ext_id=ext, dst_ext_id=node_ext,
                              kind="scoped_to", labels={"scope": "global"}))

    return Collected(resources=resources, edges=edges)
