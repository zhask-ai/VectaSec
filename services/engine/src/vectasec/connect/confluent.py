"""Confluent Cloud connector — read-only Confluent Cloud REST v2 over httpx.

One Cloud API key + secret authenticates to api.confluent.cloud and collects the org-level
control-plane posture: environments, service accounts, Cloud/resource API keys, RBAC
role-bindings and networking. Every call is a GET; nothing here mutates the org.

Three disciplines carried from the other connectors:

  * Secrets are used, never persisted. The Cloud API secret is a ConnectorField secret=True; it
    builds the httpx Basic-auth client inside collect() and is never copied into a Resource. The
    /iam/v2/api-keys LIST endpoint never returns the per-key *secret* (Confluent shows it once at
    creation only), so API-key resources record metadata — id, owner, scope, created_at — and no
    secret material ever exists to leak.
  * Per-endpoint error isolation. A key that can list service-accounts but is denied
    role-bindings records {"outcome": "..."} on that surface instead of voiding the whole scan;
    detect/confluent.py turns an unread surface into a not-assessable coverage gap, never a pass.
  * The parse layer (parse_service_account, parse_api_key, parse_role_binding, …) is PURE:
    Confluent JSON dicts in, Resources out. Tests exercise detectors against parse-layer output
    from golden fixtures, so httpx and a live Confluent org stay out of the test suite.

Kinds are DISTINCT (confluent_org, confluent_environment, confluent_service_account,
confluent_api_key, confluent_role_binding, confluent_network) so no other rulepack runs against a
Confluent resource by accident.
"""
from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

_BASE = "https://api.confluent.cloud"


# ── parse layer: Confluent REST dicts → Resources (pure, no httpx) ────────────
def parse_org(org: dict) -> Resource:
    oid = org.get("id") or "org"
    return Resource(
        kind="confluent_org",
        name=str(org.get("display_name") or oid),
        ext_id=f"confluent-org-{oid}",
        labels={"service": "confluent"},
        raw={"org_id": oid, "display_name": org.get("display_name")},
    )


def parse_environment(env: dict) -> Resource:
    eid = env.get("id") or "env"
    return Resource(
        kind="confluent_environment",
        name=str(env.get("display_name") or eid),
        ext_id=f"confluent-env-{eid}",
        labels={"service": "confluent"},
        raw={"environment_id": eid, "display_name": env.get("display_name")},
    )


def parse_service_account(sa: dict) -> Resource:
    sid = sa.get("id") or "sa"
    return Resource(
        kind="confluent_service_account",
        name=str(sa.get("display_name") or sid),
        ext_id=f"confluent-sa-{sid}",
        labels={"service": "confluent", "account_type": "service_account"},
        raw={
            "service_account_id": sid,
            "display_name": sa.get("display_name"),
            "description": sa.get("description"),
            "created_at": (sa.get("metadata") or {}).get("created_at"),
        },
    )


def parse_api_key(key: dict) -> Resource:
    """One /iam/v2/api-keys entry. `spec.resource` is null for a Cloud (org-scoped) key — the most
    powerful kind — and a {id, kind} object for a resource-scoped key (a specific Kafka cluster,
    Schema Registry, ksqlDB…). The per-key SECRET is never present in the LIST response and is
    never stored."""
    kid = key.get("id") or "key"
    spec = key.get("spec") or {}
    owner = spec.get("owner") or {}
    resource = spec.get("resource")   # None => Cloud/org-scoped key
    return Resource(
        kind="confluent_api_key",
        name=str(spec.get("display_name") or kid),
        ext_id=f"confluent-apikey-{kid}",
        labels={"service": "confluent",
                "owner_kind": str(owner.get("kind") or "unknown"),
                "scope": "cloud" if resource is None else "resource"},
        raw={
            "api_key_id": kid,
            "display_name": spec.get("display_name"),
            "owner_id": owner.get("id"),
            "owner_kind": owner.get("kind"),          # ServiceAccount | User
            "resource_id": (resource or {}).get("id"),
            "resource_kind": (resource or {}).get("kind"),
            "cloud_scoped": resource is None,          # org-wide when there is no bound resource
            "created_at": (key.get("metadata") or {}).get("created_at"),
        },
    )


def parse_role_binding(rb: dict) -> Resource:
    """One /iam/v2/role-bindings entry: principal (User:sa-… or User:u-…) holds role_name over
    crn_pattern. The principal is a service-account or user id — no secret material."""
    rid = rb.get("id") or "rb"
    principal = rb.get("principal") or ""
    return Resource(
        kind="confluent_role_binding",
        name=f"{rb.get('role_name')} → {principal}",
        ext_id=f"confluent-rb-{rid}",
        labels={"service": "confluent", "role": str(rb.get("role_name") or "")},
        raw={
            "role_binding_id": rid,
            "principal": principal,
            "role_name": rb.get("role_name"),
            "crn_pattern": rb.get("crn_pattern"),
        },
    )


def parse_network(net: dict) -> Resource:
    """One /networking/v1/networks entry. `spec.connection_types` lists how the network is
    reached: PUBLIC exposes the bootstrap over the internet, PRIVATELINK/PEERING/TRANSITGATEWAY
    keep it private."""
    nid = net.get("id") or "network"
    spec = net.get("spec") or {}
    conn = spec.get("connection_types") or []
    return Resource(
        kind="confluent_network",
        name=str(spec.get("display_name") or nid),
        ext_id=f"confluent-network-{nid}",
        labels={"service": "confluent", "cloud": str(spec.get("cloud") or "")},
        raw={
            "network_id": nid,
            "display_name": spec.get("display_name"),
            "cloud": spec.get("cloud"),
            "region": spec.get("region"),
            "connection_types": [str(c).upper() for c in conn],
            "environment_id": (spec.get("environment") or {}).get("id"),
        },
    )


# ── collection: httpx in, per-endpoint isolation ─────────────────────────────
def _paginate(client, path: str, params: dict | None = None) -> list:
    """Walk a Confluent v2 list endpoint to exhaustion. The cursor lives in
    metadata.next as an absolute URL; follow it until it is absent."""
    out: list = []
    url = path
    use_params = dict(params or {})
    while url:
        r = client.get(url, params=use_params)
        r.raise_for_status()
        body = r.json()
        out.extend(body.get("data") or [])
        url = ((body.get("metadata") or {}).get("next"))
        use_params = None   # the next URL already carries the cursor query
    return out


@connector("confluent", fields=[
    ConnectorField("api_key", "Cloud API key", required=True, placeholder="ABC123XYZ...",
                   help="A Confluent Cloud API key with the Cloud resource scope (owned by a "
                        "service account with at least OrganizationAdmin read or the "
                        "MetadataViewer/Operator roles). Read-only — every call is a GET."),
    ConnectorField("api_secret", "Cloud API secret", required=True, secret=True,
                   help="The secret half of the Cloud API key. Used to open the Basic-auth "
                        "session and never persisted into any resource."),
])
def collect(config: dict) -> Collected:
    import base64

    import httpx

    api_key = (config.get("api_key") or "").strip()
    api_secret = (config.get("api_secret") or "").strip()
    if not api_key or not api_secret:
        raise SystemExit("confluent connector requires config['api_key'] and config['api_secret']")
    timeout = float(config.get("timeout") or 20)

    token = base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()
    client = httpx.Client(base_url=_BASE, timeout=timeout,
                          headers={"Authorization": f"Basic {token}"})

    resources: list[Resource] = []
    edges: list[Edge] = []
    outcomes: dict[str, dict] = {}

    def _surface(name: str, fn):
        try:
            fn()
            outcomes[name] = {"outcome": "ok", "error": None}
        except Exception as e:   # noqa: BLE001 — one denied surface must not void the scan
            code = getattr(getattr(e, "response", None), "status_code", None)
            outcomes[name] = {"outcome": "access_denied" if code in (401, 403) else "error",
                              "error": f"{type(e).__name__}: {e}"}

    org_id = {"id": None}

    def _orgs():
        for o in _paginate(client, "/org/v2/organizations"):
            r = parse_org(o)
            resources.append(r)
            if org_id["id"] is None:
                org_id["id"] = r.raw["org_id"]
    _surface("organizations", _orgs)

    _surface("environments",
             lambda: resources.extend(parse_environment(e)
                                      for e in _paginate(client, "/org/v2/environments")))
    _surface("service_accounts",
             lambda: resources.extend(parse_service_account(s)
                                      for s in _paginate(client, "/iam/v2/service-accounts")))
    _surface("api_keys",
             lambda: resources.extend(parse_api_key(k)
                                      for k in _paginate(client, "/iam/v2/api-keys")))
    _surface("networks",
             lambda: resources.extend(parse_network(n)
                                      for n in _paginate(client, "/networking/v1/networks")))

    def _role_bindings():
        oid = org_id["id"]
        if not oid:
            return
        crn = f"crn://confluent.cloud/organization={oid}"
        for rb in _paginate(client, "/iam/v2/role-bindings", {"crn_pattern": crn}):
            resources.append(parse_role_binding(rb))
    _surface("role_bindings", _role_bindings)

    client.close()

    # The control-plane account resource: what we authenticated as + which surfaces were readable.
    resources.insert(0, Resource(
        kind="confluent_org_scan",
        name="confluent-cloud",
        ext_id="confluent-scan",
        labels={"service": "confluent"},
        raw={"org_id": org_id["id"], "collection": outcomes},
    ))
    return Collected(resources=resources, edges=edges)


# ── NHI: service accounts + API keys + role bindings ─────────────────────────
def _principal_identity(seen: dict, out: list, principal: str) -> Resource:
    """principal 'User:sa-abc' / 'User:u-xyz' → the identity it names, deduped. A `u-` id is a
    human user; anything else (sa-, pool-) is a workload principal."""
    pid = principal.split(":", 1)[-1] if ":" in principal else principal
    idr = seen.get(pid)
    if idr is None:
        itype = "user" if pid.startswith("u-") else "service_account"
        idr = _mk_identity("confluent", itype, principal, external=(itype == "user"))
        seen[pid] = idr
        out.append(idr)
    return idr


@identity_extractor("confluent")
def _from_confluent(resources: list) -> tuple:
    """Service accounts → identities; API keys → credential metadata owned by their principal;
    role bindings → grants. The API-key secret is never present in the collected data, so a
    credential records presence and scope only (plaintext=None)."""
    out: list[Resource] = []
    edges: list[Edge] = []
    seen: dict[str, Resource] = {}

    for r in resources:
        if r.kind != "confluent_service_account":
            continue
        sid = (r.raw or {}).get("service_account_id") or r.name
        idr = seen.get(sid)
        if idr is None:
            idr = _mk_identity("confluent", "service_account", sid, source_ext=r.ext_id,
                               extra={"display_name": (r.raw or {}).get("display_name")})
            seen[sid] = idr
            out.append(idr)

    for r in resources:
        if r.kind != "confluent_api_key":
            continue
        raw = r.raw or {}
        owner_id = raw.get("owner_id") or "unknown"
        idr = seen.get(owner_id)
        if idr is None:
            itype = "user" if str(owner_id).startswith("u-") else "service_account"
            idr = _mk_identity("confluent", itype, owner_id, external=(itype == "user"),
                               source_ext=r.ext_id)
            seen[owner_id] = idr
            out.append(idr)
        cred = _mk_credential(
            "confluent", idr.ext_id, "api_key", name=f"{raw.get('api_key_id')}:api_key",
            hashing="n/a", present=True, plaintext=None,
            extra={"api_key_id": raw.get("api_key_id"), "cloud_scoped": raw.get("cloud_scoped"),
                   "resource_kind": raw.get("resource_kind"), "created_at": raw.get("created_at")})
        out.append(cred)
        edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

    for r in resources:
        if r.kind != "confluent_role_binding":
            continue
        raw = r.raw or {}
        principal = raw.get("principal") or ""
        if not principal:
            continue
        idr = _principal_identity(seen, out, principal)
        role = raw.get("role_name") or ""
        g = _mk_grant("confluent", idr.ext_id, role.lower(), raw.get("crn_pattern") or "",
                      wildcard=role in ("OrganizationAdmin",),
                      extra={"role_name": role, "crn_pattern": raw.get("crn_pattern")})
        out.append(g)
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
