"""Boomi connector — read-only over the AtomSphere Platform API (api.boomi.com/api/rest/v1).

Boomi is the integration layer for the enterprises that run it: published APIs front internal
systems, Connection components hold the credentials those integrations use, and account Roles decide
who can change any of it. A published API with authentication None is an unauthenticated door into
whatever it fronts, and a Connection reused across prod and non-prod means one leaked secret spans
environments — both are integration-layer posture with no third-party tool watching them.

What is read, and the discipline:

  POST /{account}/SharedServerInformation/query    the inbound-gateway auth config per published API
                                                    (authType, ssl) — the posture facts.
  POST /{account}/Connection/query                  Connection components + the environments they are
                                                    extended into (blast-radius facts, never the value).
  POST /{account}/Role/query                        account roles + their privilege lists.
  POST /{account}/AccountUserRole/query             user↔role assignments (the NHI edges).

Auth is HTTP Basic with an API token (username = email or 'BOOMI_TOKEN.<email>', password = token);
the token is a ConnectorField secret=True, used only to build the client and never copied into a
Resource. Connection credential values are never fetched — the platform API does not return them and
neither does this connector.

Kinds are DISTINCT (boomi_api, boomi_connection, boomi_role, boomi_account_user) so no other rulepack
runs against a Boomi resource by accident. The parse layer is pure: AtomSphere JSON in, Resources
out; tests drive detectors against parse-layer output from golden fixtures.
"""
import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

# Authentication types Boomi's inbound gateway accepts, ranked. `none` is unauthenticated; `basic`
# is a shared username/password (weak vs a rotating key or token).
_STRONG_AUTH = {"apikey", "oauth", "oauth2", "clientcertificate", "custom"}
_WEAK_AUTH = {"basic"}
_NO_AUTH = {"none", ""}

# Role privilege tokens that confer account-wide administrative control. Matched case-insensitively.
_BROAD_PRIVILEGES = {
    "account_administration", "account_admin", "administration", "admin",
    "manage_account", "atom_management", "api_management_admin",
}


def _norm(s) -> str:
    return str(s or "").strip().lower()


# ── parse layer: AtomSphere JSON → Resources (pure, no httpx) ─────────────────
def parse_api(obj: dict) -> Resource:
    """One published API's inbound posture (from SharedServerInformation joined to the API
    component). authentication_type=None means the auth config could not be read — recorded so the
    rulepack answers not-assessable, never 'no auth' (which would false-FAIL an API that in fact
    authenticates)."""
    auth = obj.get("authenticationType")
    auth_norm = _norm(auth) if auth is not None else None
    url = str(obj.get("publicUrl") or obj.get("url") or "")
    https_required = obj.get("httpsRequired")
    if https_required is None and url:
        https_required = url.lower().startswith("https://")
    return Resource(
        kind="boomi_api",
        name=str(obj.get("name") or obj.get("id") or "?"),
        ext_id=f"boomi-api-{obj.get('id')}",
        namespace=obj.get("environmentName") or obj.get("environmentId"),
        labels={"environment": str(obj.get("environmentName") or obj.get("environmentId") or "?"),
                "auth": auth_norm or "unknown"},
        raw={
            "id": obj.get("id"),
            "name": obj.get("name"),
            "environment_id": obj.get("environmentId"),
            "environment_name": obj.get("environmentName"),
            "authentication_type": auth_norm,     # normalized, or None when unreadable
            "auth_readable": auth is not None,
            "public_url": url,
            "https_required": bool(https_required),
        },
    )


def parse_connection(obj: dict) -> Resource:
    """One Connection component + the environments it is deployed/extended into. The credential VALUE
    is never present in the platform API response; only its existence and reuse are recorded."""
    envs = obj.get("environments") or obj.get("environmentIds") or []
    envs = [str(e) for e in envs]
    return Resource(
        kind="boomi_connection",
        name=str(obj.get("name") or obj.get("id") or "?"),
        ext_id=f"boomi-connection-{obj.get('id')}",
        labels={"connector_type": str(obj.get("connectorType") or "?"),
                "environment_count": str(len(envs))},
        raw={
            "id": obj.get("id"),
            "name": obj.get("name"),
            "connector_type": obj.get("connectorType"),
            "environments": envs,
            "has_credential": obj.get("hasCredential", True),
        },
    )


def parse_role(obj: dict) -> Resource:
    privileges = [str(p) for p in (obj.get("privileges") or obj.get("Privileges") or [])]
    return Resource(
        kind="boomi_role",
        name=str(obj.get("name") or obj.get("id") or "?"),
        ext_id=f"boomi-role-{obj.get('id')}",
        labels={"privilege_count": str(len(privileges))},
        raw={"id": obj.get("id"), "name": obj.get("name"), "privileges": privileges},
    )


def parse_account_user(obj: dict) -> Resource:
    return Resource(
        kind="boomi_account_user",
        name=str(obj.get("userId") or obj.get("id") or "?"),
        ext_id=f"boomi-acctuser-{obj.get('userId')}-{obj.get('roleId')}",
        labels={"role": str(obj.get("roleName") or obj.get("roleId") or "?")},
        raw={
            "user_id": obj.get("userId"),
            "role_id": obj.get("roleId"),
            "role_name": obj.get("roleName"),
            "account_id": obj.get("accountId"),
        },
    )


def role_is_overprivileged(privileges: list) -> list:
    """The subset of a role's privileges that confer account-wide admin control."""
    return sorted({p for p in (privileges or [])
                   if any(m in _norm(p) for m in _BROAD_PRIVILEGES)})


# ── collection: httpx in, per-call isolation ──────────────────────────────────
_DEFAULT_HOST = "https://api.boomi.com"


def _query(client: httpx.Client, base: str, object_type: str) -> list:
    """One AtomSphere `POST /{object}/query`. Boomi returns {"result": [...], "queryToken": "..."};
    follow queryMore with the token until it is absent, so a large inventory is fully walked."""
    out = []
    r = client.post(f"{base}/{object_type}/query", json={})
    r.raise_for_status()
    body = r.json()
    out.extend(body.get("result") or [])
    token = body.get("queryToken")
    while token:
        r = client.post(f"{base}/{object_type}/queryMore", content=token,
                        headers={"Content-Type": "text/plain"})
        r.raise_for_status()
        body = r.json()
        out.extend(body.get("result") or [])
        token = body.get("queryToken")
    return out


@connector("boomi", fields=[
    ConnectorField("account_id", "Account ID", required=True, placeholder="myaccount-ABC123",
                   help="Boomi AtomSphere account id to scan."),
    ConnectorField("username", "Username / token username", required=True,
                   placeholder="BOOMI_TOKEN.name@example.com",
                   help="HTTP Basic username: your email, or 'BOOMI_TOKEN.<email>' for an API token."),
    ConnectorField("token", "API token / password", secret=True,
                   help="The API token (or password). Used only to authenticate; never persisted."),
    ConnectorField("host", "API host", placeholder="https://api.boomi.com",
                   help="AtomSphere API host (change only for a dedicated/partner cloud)."),
])
def collect(config: dict) -> Collected:
    account_id = (config.get("account_id") or "").strip()
    if not account_id:
        raise SystemExit("boomi connector requires config['account_id']")
    username = (config.get("username") or "").strip()
    token = config.get("token") or ""
    host = (config.get("host") or _DEFAULT_HOST).strip().rstrip("/")
    timeout = float(config.get("timeout") or 20)
    verify = config.get("verify", True)
    base = f"{host}/api/rest/v1/{account_id}"

    resources: list[Resource] = []
    edges: list[Edge] = []
    outcomes: dict = {}

    def _safe(object_type: str, parse, kind_label: str):
        try:
            rows = _query(client, base, object_type)
            outcomes[kind_label] = {"outcome": "ok", "count": len(rows)}
            return [parse(row) for row in rows]
        except Exception as e:
            outcomes[kind_label] = {"outcome": "error", "error": f"{type(e).__name__}: {e}"}
            return []

    with httpx.Client(timeout=timeout, verify=verify, auth=(username, token),
                      headers={"Accept": "application/json"}, follow_redirects=False) as client:
        resources += _safe("SharedServerInformation", parse_api, "apis")
        resources += _safe("Connection", parse_connection, "connections")
        resources += _safe("Role", parse_role, "roles")
        resources += _safe("AccountUserRole", parse_account_user, "account_users")

    account = Resource(
        kind="boomi_account", name=account_id, ext_id=f"boomi-account-{account_id}",
        labels={"host": host}, raw={"account_id": account_id, "host": host, "collection": outcomes},
    )
    return Collected(resources=[account] + resources, edges=edges)


# ── NHI: users→identities, roles→grants, connections→integration credentials ──
@identity_extractor("boomi")
def _from_boomi(resources: list) -> tuple:
    """Account users become identities; their role assignment becomes a grant (wildcard when the
    role carries account-admin privileges); Connection components become integration-credential
    material (metadata only — the credential value is never in the platform API)."""
    out: list[Resource] = []
    edges: list[Edge] = []

    role_privs = {r.raw.get("id"): (r.raw.get("privileges") or [])
                  for r in resources if r.kind == "boomi_role"}
    account_ext = next((r.ext_id for r in resources if r.kind == "boomi_account"), "boomi-account")

    id_by_user: dict[str, Resource] = {}
    for r in resources:
        if r.kind != "boomi_account_user":
            continue
        raw = r.raw or {}
        user = raw.get("user_id") or r.name
        idr = id_by_user.get(user)
        if idr is None:
            idr = _mk_identity("boomi", "user", user, source_ext=r.ext_id)
            id_by_user[user] = idr
            out.append(idr)
        privs = role_privs.get(raw.get("role_id")) or []
        broad = role_is_overprivileged(privs)
        g = _mk_grant("boomi", idr.ext_id, raw.get("role_name") or raw.get("role_id") or "role",
                      "account", wildcard=bool(broad),
                      extra={"role_id": raw.get("role_id"), "privileges": privs})
        out.append(g)
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=account_ext, kind="grants_access"))

    for r in resources:
        if r.kind != "boomi_connection":
            continue
        raw = r.raw or {}
        envs = raw.get("environments") or []
        label = f"{raw.get('connector_type') or 'connection'}:{raw.get('name') or raw.get('id')}"
        idr = _mk_identity("boomi", "integration_account", label, external=True, source_ext=r.ext_id,
                           extra={"connector_type": raw.get("connector_type")})
        out.append(idr)
        if raw.get("has_credential"):
            cred = _mk_credential("boomi", idr.ext_id, "connection_secret",
                                  name=f"{raw.get('name')}:secret", hashing="n/a", present=True,
                                  plaintext=False, count=max(len(envs), 1),
                                  extra={"environments": envs})
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
    return out, edges
