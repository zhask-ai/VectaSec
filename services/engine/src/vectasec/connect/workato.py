"""Workato connector — read-only over the Workato API (recipes, connections, API clients, API
platform endpoints), authenticated with an API token.

Workato is an iPaaS whose whole job is to hold credentials for other systems and run automations
against them, and whose API Platform can publish those automations as HTTP endpoints. The posture
that matters: an API client (a machine credential) with admin rights and no IP allowlist, a
published endpoint with no access profile gating it, and a connection shared across the whole
workspace. All three are integration-layer facts with no third-party posture tool watching them.

What is read, and the discipline:

  GET /api/recipes        the automation inventory (+ which connections each uses).
  GET /api/connections    the stored third-party connections (NHI). The connection's secret is never
                          returned by the API and is never stored — only its existence + sharing.
  GET /api/api_clients    API clients (machine credentials): role + IP allowlist are the posture.
  GET /api/api_endpoints  API Platform endpoints and the access profiles that gate them.

The API token is a ConnectorField secret=True: it builds the client and is never copied into a
Resource. Kinds are DISTINCT (workato_recipe, workato_connection, workato_api_client,
workato_api_endpoint) so no other rulepack runs against a Workato resource by accident. The parse
layer is pure: Workato JSON in, Resources out; tests drive detectors against parse-layer output.
"""
import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

# Workato data centers → API host. `data_center` selects which control plane the token belongs to.
_DATA_CENTERS = {
    "us": "https://www.workato.com",
    "eu": "https://app.eu.workato.com",
    "jp": "https://app.jp.workato.com",
    "sg": "https://app.sg.workato.com",
    "au": "https://app.au.workato.com",
    "il": "https://app.il.workato.com",
}

# Role names that confer workspace-admin control on an API client. Matched case-insensitively.
_ADMIN_ROLE_MARKERS = ("admin", "owner", "full access")


def _is_admin_role(role) -> bool:
    r = str(role or "").lower()
    return any(m in r for m in _ADMIN_ROLE_MARKERS)


def _ip_allowlist(obj: dict) -> list:
    """The client's IP allowlist across the field names Workato has used. [] means no restriction."""
    for key in ("ip_allowlist", "ip_allow_list", "whitelisted_ips", "allowed_ips"):
        v = obj.get(key)
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str) and v.strip():
            return [p.strip() for p in v.split(",") if p.strip()]
    return []


# ── parse layer: Workato JSON → Resources (pure, no httpx) ────────────────────
def parse_recipe(obj: dict) -> tuple:
    """One recipe → (Resource, list[connection-id]). The connection ids link a recipe to the
    credentials it drives (the graph edge), never to a secret value."""
    conn_ids = []
    for c in obj.get("config") or []:
        cid = c.get("account_id") if isinstance(c, dict) else None
        if cid is not None:
            conn_ids.append(cid)
    res = Resource(
        kind="workato_recipe",
        name=str(obj.get("name") or obj.get("id") or "?"),
        ext_id=f"workato-recipe-{obj.get('id')}",
        labels={"running": "true" if obj.get("running") else "false"},
        raw={
            "id": obj.get("id"),
            "name": obj.get("name"),
            "running": bool(obj.get("running")),
            "connection_ids": conn_ids,
            "folder_id": obj.get("folder_id"),
        },
    )
    return res, conn_ids


def parse_connection(obj: dict) -> Resource:
    """One stored connection. `shared` / a null folder means it is visible workspace-wide. The
    connection's authorization state is recorded; its secret is never available from the API."""
    authorized = obj.get("authorized")
    if authorized is None:
        status = str(obj.get("authorization_status") or "").lower()
        authorized = status in ("success", "authorized", "") if status else None
    shared = obj.get("shared")
    if shared is None:
        shared = obj.get("folder_id") in (None, "", 0)   # no folder ⇒ workspace-root ⇒ shared
    return Resource(
        kind="workato_connection",
        name=str(obj.get("name") or obj.get("id") or "?"),
        ext_id=f"workato-connection-{obj.get('id')}",
        labels={"provider": str(obj.get("provider") or "?"),
                "shared": "true" if shared else "false"},
        raw={
            "id": obj.get("id"),
            "name": obj.get("name"),
            "provider": obj.get("provider"),
            "authorized": authorized,
            "shared_org_wide": bool(shared),
            "folder_id": obj.get("folder_id"),
        },
    )


def parse_api_client(obj: dict) -> Resource:
    """One API client (a machine credential for the Workato API Platform). role_name=None means the
    role could not be resolved — recorded so the rulepack answers not-assessable, never 'not admin'."""
    role = obj.get("role_name") if "role_name" in obj else obj.get("role")
    allowlist = _ip_allowlist(obj)
    return Resource(
        kind="workato_api_client",
        name=str(obj.get("name") or obj.get("id") or "?"),
        ext_id=f"workato-apiclient-{obj.get('id')}",
        labels={"role": str(role) if role is not None else "unknown",
                "ip_restricted": "true" if allowlist else "false"},
        raw={
            "id": obj.get("id"),
            "name": obj.get("name"),
            "role_name": role,
            "role_readable": role is not None,
            "is_admin": _is_admin_role(role) if role is not None else None,
            "ip_allowlist": allowlist,
        },
    )


def parse_api_endpoint(obj: dict) -> Resource:
    """One API Platform endpoint. access_profile_ids empty on an active endpoint = ungated."""
    profiles = obj.get("access_profile_ids")
    if profiles is None:
        profiles = obj.get("access_profiles") or []
    profiles = list(profiles)
    active = obj.get("active")
    if active is None:
        active = str(obj.get("status") or "").lower() in ("active", "enabled", "")
    return Resource(
        kind="workato_api_endpoint",
        name=str(obj.get("name") or obj.get("path") or obj.get("id") or "?"),
        ext_id=f"workato-apiendpoint-{obj.get('id')}",
        labels={"active": "true" if active else "false",
                "profile_count": str(len(profiles))},
        raw={
            "id": obj.get("id"),
            "name": obj.get("name"),
            "path": obj.get("base_path") or obj.get("path"),
            "method": obj.get("method"),
            "active": bool(active),
            "access_profile_ids": profiles,
            "api_collection_id": obj.get("api_collection_id"),
        },
    )


# ── collection: httpx in, per-call isolation ──────────────────────────────────
def _paginate(client: httpx.Client, url: str, key=None) -> list:
    """Walk a page-numbered Workato list. Responses are either a bare list or {"<key>|items": [...]}.
    Pages until a short page (< per_page) is returned."""
    out, page, per_page = [], 1, 100
    while True:
        r = client.get(url, params={"page": page, "per_page": per_page})
        r.raise_for_status()
        body = r.json()
        if isinstance(body, list):
            rows = body
        else:
            rows = body.get(key) if key else None
            if rows is None:
                rows = body.get("result") or body.get("items") or body.get("data") or []
        out.extend(rows)
        if len(rows) < per_page:
            break
        page += 1
    return out


@connector("workato", fields=[
    ConnectorField("api_token", "API token", required=True, secret=True,
                   help="A Workato API token (sent as a Bearer token). Use a token scoped read-only "
                        "to recipes, connections, API clients, and API platform."),
    ConnectorField("data_center", "Data center", placeholder="us",
                   help="Workato data center the token belongs to: us, eu, jp, sg, au, or il."),
    ConnectorField("host", "API host override", placeholder="https://www.workato.com",
                   help="Explicit API host; overrides data_center (for a custom/embedded plane)."),
])
def collect(config: dict) -> Collected:
    token = (config.get("api_token") or "").strip()
    if not token:
        raise SystemExit("workato connector requires config['api_token']")
    dc = str(config.get("data_center") or "us").strip().lower()
    host = (config.get("host") or _DATA_CENTERS.get(dc) or _DATA_CENTERS["us"]).strip().rstrip("/")
    timeout = float(config.get("timeout") or 20)
    verify = config.get("verify", True)

    resources: list[Resource] = []
    edges: list[Edge] = []
    outcomes: dict = {}

    def _safe(path: str, key, parse, label: str):
        try:
            rows = _paginate(client, f"{host}{path}", key)
            outcomes[label] = {"outcome": "ok", "count": len(rows)}
            return [parse(row) for row in rows]
        except Exception as e:
            outcomes[label] = {"outcome": "error", "error": f"{type(e).__name__}: {e}"}
            return []

    with httpx.Client(timeout=timeout, verify=verify,
                      headers={"Authorization": f"Bearer {token}",
                               "Accept": "application/json"}, follow_redirects=False) as client:
        recipe_pairs = _safe("/api/recipes", "result", parse_recipe, "recipes")
        for res, conn_ids in recipe_pairs:
            resources.append(res)
            for cid in conn_ids:
                edges.append(Edge(src_ext_id=res.ext_id,
                                  dst_ext_id=f"workato-connection-{cid}", kind="uses_connection"))
        resources += _safe("/api/connections", "result", parse_connection, "connections")
        resources += _safe("/api/api_clients", "result", parse_api_client, "api_clients")
        resources += _safe("/api/api_endpoints", "result", parse_api_endpoint, "api_endpoints")

    workspace = Resource(
        kind="workato_workspace", name=host, ext_id=f"workato-workspace-{dc}",
        labels={"data_center": dc}, raw={"host": host, "data_center": dc, "collection": outcomes},
    )
    return Collected(resources=[workspace] + resources, edges=edges)


# ── NHI: API clients → machine identities, connections → integration credentials ──
@identity_extractor("workato")
def _from_workato(resources: list) -> tuple:
    """API clients are non-human machine identities (their API token is credential material, metadata
    only; their role is a grant, wildcard for admin). Connections are integration-credential
    material — existence recorded, value never."""
    out: list[Resource] = []
    edges: list[Edge] = []
    workspace_ext = next((r.ext_id for r in resources if r.kind == "workato_workspace"),
                         "workato-workspace")

    for r in resources:
        if r.kind != "workato_api_client":
            continue
        raw = r.raw or {}
        idr = _mk_identity("workato", "api_client", raw.get("name") or raw.get("id"), external=True,
                           source_ext=r.ext_id,
                           tags=(["no_ip_allowlist"] if not raw.get("ip_allowlist") else []),
                           extra={"role_name": raw.get("role_name"),
                                  "ip_restricted": bool(raw.get("ip_allowlist"))})
        out.append(idr)
        cred = _mk_credential("workato", idr.ext_id, "api_token",
                              name=f"{raw.get('name')}:api_token", hashing="n/a", present=True,
                              plaintext=False)
        out.append(cred)
        edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
        g = _mk_grant("workato", idr.ext_id, raw.get("role_name") or "api", "workspace",
                      wildcard=bool(raw.get("is_admin")), extra={"role_name": raw.get("role_name")})
        out.append(g)
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=workspace_ext, kind="grants_access"))

    for r in resources:
        if r.kind != "workato_connection":
            continue
        raw = r.raw or {}
        label = f"{raw.get('provider') or 'connection'}:{raw.get('name') or raw.get('id')}"
        idr = _mk_identity("workato", "integration_account", label, external=True, source_ext=r.ext_id,
                           extra={"provider": raw.get("provider")})
        out.append(idr)
        cred = _mk_credential("workato", idr.ext_id, "connection_secret",
                              name=f"{raw.get('name')}:secret", hashing="n/a", present=True,
                              plaintext=False,
                              extra={"shared_org_wide": bool(raw.get("shared_org_wide"))})
        out.append(cred)
        edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
    return out, edges
