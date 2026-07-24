"""MuleSoft Anypoint connector — read-only over the Anypoint Platform APIs (API Manager + Access
Management), authenticated with a Connected App (client credentials) or a supplied access token.

Anypoint is the integration layer: every managed API instance sits behind API Manager, and the
policies applied to it (client-id enforcement, JWT/OAuth validation, rate limiting) ARE its security
posture — an API published with no auth policy is an unauthenticated endpoint on the internet. That
posture is exactly what this product exists to inventory, and no third-party tool does it.

What is read, and the discipline:

  POST /accounts/api/v2/oauth2/token       exchange the Connected App client_id+secret for a bearer
                                           token (client_credentials). The secret is a ConnectorField
                                           secret=True; it builds the token inside collect() and is
                                           never copied into any Resource.
  GET  /apimanager/api/v1/.../apis         the managed API instances per environment (paginated).
  GET  /apimanager/api/v1/.../apis/{id}/policies   the policies applied to each — the posture facts.
  GET  /accounts/api/connectedApplications the Connected Apps (NHI) and their granted scopes.

Policy config is authorization config, not a secret, so it is stored in Resource.raw and quoted by
detectors — the same stance connect/aws.py takes on resource policies. Kinds are DISTINCT
(mulesoft_api, mulesoft_app) so no other rulepack runs against an Anypoint resource by accident.

The parse layer (parse_api, parse_connected_app) is pure: Anypoint JSON in, Resources out. Tests
drive detectors against parse-layer output from golden fixtures, so httpx and a live org stay out of
the suite.
"""
from urllib.parse import urlsplit

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

# Policy assetIds that enforce caller IDENTITY (any one of these means the API authenticates).
# client-id-enforcement is the Anypoint baseline; the others are stronger token validations.
_AUTH_POLICY_ASSETS = {
    "client-id-enforcement", "jwt-validation", "openidconnect", "openid-connect-access-token-enforcement",
    "external-oauth2-token-validation", "oauth2-provider", "oauth2-token-enforcement",
    "basic-authentication-simple", "basic-authentication-ldap", "ldap-security-manager",
}
_CLIENT_ID_ENFORCEMENT = "client-id-enforcement"
# Policy assetIds that limit request VOLUME.
_RATE_POLICY_ASSETS = {"rate-limiting", "rate-limiting-sla", "spike-control"}

# Connected-App scope substrings that grant broad, tenant-wide power. Matched case-insensitively as
# substrings because Anypoint scope strings vary ('org-admin', 'Organization Administrator', …).
_BROAD_SCOPE_MARKERS = (
    "org-admin", "organization administrator", "account owner", "cs-admin", "delete:",
    "manage:full", "write:full", "read:full", "full-access", "everything",
)


def _policy_asset(p: dict) -> str:
    """The policy template assetId, across the shapes the API Manager has used over versions."""
    tmpl = p.get("template") or p.get("implementationAsset") or {}
    return str(p.get("assetId") or p.get("policyTemplateId") or tmpl.get("assetId")
               or tmpl.get("groupId") or "").lower()


def _policy_disabled(p: dict) -> bool:
    # `disabled: true` is a policy attached but not enforcing. Absent ⇒ enforcing.
    return bool(p.get("disabled"))


# ── parse layer: Anypoint JSON → Resources (pure, no httpx) ───────────────────
def parse_api(org_id: str, env: str, api: dict, policies, policies_readable: bool) -> Resource:
    """One managed API instance + its applied policies. `policies=None`/policies_readable=False means
    the per-API policies call failed — recorded so the rulepack answers not-assessable, never 'no
    policies' (which would false-FAIL every auth/rate-limit rule)."""
    endpoint = api.get("endpoint") or {}
    uri = str(endpoint.get("uri") or endpoint.get("proxyUri") or "")
    scheme = urlsplit(uri).scheme.lower() if uri else ""
    pols = [{"asset": _policy_asset(p), "disabled": _policy_disabled(p),
             "config": p.get("configurationData") or p.get("configuration")}
            for p in (policies or [])]
    api_id = api.get("id") or api.get("apiId")
    return Resource(
        kind="mulesoft_api",
        name=str(api.get("instanceLabel") or api.get("assetId") or api_id or "?"),
        ext_id=f"mulesoft-api-{org_id}-{env}-{api_id}",
        namespace=env,
        labels={"environment": env, "stage": str(api.get("stage") or "?"),
                "technology": str(api.get("technology") or "?")},
        raw={
            "api_id": api_id,
            "asset_id": api.get("assetId"),
            "instance_label": api.get("instanceLabel"),
            "environment": env,
            "org_id": org_id,
            "endpoint_uri": uri,
            "endpoint_scheme": scheme,
            "is_cloudhub": endpoint.get("isCloudHub"),
            "deprecated": bool(api.get("deprecated")),
            "technology": api.get("technology"),
            "policies": pols,
            "policies_readable": policies_readable,
        },
    )


def parse_connected_app(app: dict) -> Resource:
    """One Connected App (Access Management). Scopes are the app's granted authorizations (the NHI
    grants); the client secret is never returned by the list endpoint and is never stored."""
    scopes = app.get("scopes")
    if isinstance(scopes, str):
        scopes = [s.strip() for s in scopes.split() if s.strip()]
    scopes = [str(s) for s in (scopes or [])]
    cid = app.get("client_id") or app.get("clientId") or app.get("id")
    return Resource(
        kind="mulesoft_app",
        name=str(app.get("client_name") or app.get("name") or cid or "?"),
        ext_id=f"mulesoft-app-{cid}",
        labels={"grant_types": ",".join(app.get("grant_types") or app.get("grantTypes") or []),
                "scope_count": str(len(scopes))},
        raw={
            "client_id": cid,
            "name": app.get("client_name") or app.get("name"),
            "scopes": scopes,
            "grant_types": app.get("grant_types") or app.get("grantTypes") or [],
            "redirect_uris": app.get("redirect_uris") or app.get("redirectUris") or [],
            "enabled": app.get("enabled", True),
        },
    )


# ── policy classification helpers shared with the rulepack ────────────────────
def enforcing_assets(api_raw: dict) -> set:
    """The assetIds of policies that are attached AND enforcing (disabled ones do not count)."""
    return {p["asset"] for p in (api_raw.get("policies") or []) if not p["disabled"]}


# ── collection: httpx in, per-call isolation ──────────────────────────────────
_DEFAULT_HOST = "https://anypoint.mulesoft.com"


def _token(client: httpx.Client, host: str, config: dict) -> str:
    """Bearer token: a supplied access_token wins; otherwise client-credentials on the Connected
    App. The secret lives only in this exchange."""
    tok = (config.get("access_token") or "").strip()
    if tok:
        return tok
    cid = (config.get("client_id") or "").strip()
    secret = (config.get("client_secret") or "").strip()
    if not (cid and secret):
        raise SystemExit("mulesoft connector requires access_token, or client_id + client_secret")
    r = client.post(f"{host}/accounts/api/v2/oauth2/token",
                    json={"grant_type": "client_credentials", "client_id": cid,
                          "client_secret": secret})
    r.raise_for_status()
    return r.json()["access_token"]


def _paginate(client: httpx.Client, url: str, key: str, headers: dict) -> list:
    """Walk an offset-paginated Anypoint list. Anypoint returns {"total": N, "<key>": [...]}; page
    with offset/limit until the accumulated count reaches total."""
    out, offset, limit = [], 0, 200
    while True:
        r = client.get(url, params={"offset": offset, "limit": limit}, headers=headers)
        r.raise_for_status()
        body = r.json()
        rows = body.get(key) or []
        out.extend(rows)
        total = body.get("total")
        offset += len(rows)
        if not rows or (total is not None and offset >= total):
            break
    return out


@connector("mulesoft", fields=[
    ConnectorField("org_id", "Organization ID", required=True,
                   placeholder="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                   help="Anypoint business-group (organization) id to scan."),
    ConnectorField("environments", "Environments", placeholder="Production,Sandbox",
                   help="Comma-separated environment names (or ids) to scan. Empty = discover all."),
    ConnectorField("host", "Anypoint host", placeholder="https://anypoint.mulesoft.com",
                   help="Control-plane host; use https://eu1.anypoint.mulesoft.com for the EU plane."),
    ConnectorField("client_id", "Connected App client ID",
                   help="A Connected App with read-only API Manager + Access Management scopes."),
    ConnectorField("client_secret", "Connected App client secret", secret=True,
                   help="Used only to obtain a bearer token; never persisted into any resource."),
    ConnectorField("access_token", "Access token", secret=True,
                   help="A pre-obtained bearer token, used instead of client_id/secret."),
])
def collect(config: dict) -> Collected:
    org_id = (config.get("org_id") or "").strip()
    if not org_id:
        raise SystemExit("mulesoft connector requires config['org_id']")
    host = (config.get("host") or _DEFAULT_HOST).strip().rstrip("/")
    timeout = float(config.get("timeout") or 20)
    verify = config.get("verify", True)
    want_envs = [e.strip() for e in str(config.get("environments") or "").split(",") if e.strip()]

    resources: list[Resource] = []
    edges: list[Edge] = []
    outcomes: dict = {}

    with httpx.Client(timeout=timeout, verify=verify, follow_redirects=False) as client:
        token = _token(client, host, config)
        headers = {"Authorization": f"Bearer {token}"}

        # Environments: discover if not specified.
        envs = want_envs
        if not envs:
            try:
                r = client.get(f"{host}/accounts/api/organizations/{org_id}/environments",
                               headers=headers)
                r.raise_for_status()
                envs = [e.get("id") for e in (r.json().get("data") or []) if e.get("id")]
                outcomes["environments"] = {"outcome": "ok", "count": len(envs)}
            except Exception as e:
                outcomes["environments"] = {"outcome": "error", "error": f"{type(e).__name__}: {e}"}
                envs = []

        for env in envs:
            base = f"{host}/apimanager/api/v1/organizations/{org_id}/environments/{env}/apis"
            try:
                apis = _paginate(client, base, "apis", headers)
            except Exception as e:
                outcomes[f"apis:{env}"] = {"outcome": "error", "error": f"{type(e).__name__}: {e}"}
                continue
            outcomes[f"apis:{env}"] = {"outcome": "ok", "count": len(apis)}
            for api in apis:
                api_id = api.get("id") or api.get("apiId")
                policies, readable = None, False
                try:
                    r = client.get(f"{base}/{api_id}/policies", headers=headers)
                    r.raise_for_status()
                    body = r.json()
                    policies = body.get("policies") if isinstance(body, dict) else body
                    readable = True
                except Exception:
                    policies, readable = None, False   # recorded as coverage gap, not 'no policies'
                resources.append(parse_api(org_id, env, api, policies, readable))

        # Connected Apps (Access Management) — org-wide, not per environment.
        try:
            apps = _paginate(client, f"{host}/accounts/api/connectedApplications", "data", headers)
            outcomes["connected_apps"] = {"outcome": "ok", "count": len(apps)}
        except Exception as e:
            apps = []
            outcomes["connected_apps"] = {"outcome": "error", "error": f"{type(e).__name__}: {e}"}
        for app in apps:
            resources.append(parse_connected_app(app))

    org = Resource(
        kind="mulesoft_org", name=org_id, ext_id=f"mulesoft-org-{org_id}",
        labels={"host": urlsplit(host).hostname or host},
        raw={"org_id": org_id, "host": host, "environments": envs, "collection": outcomes},
    )
    return Collected(resources=[org] + resources, edges=edges)


# ── NHI: Connected Apps → OAuth client identities + secret metadata + scope grants ──
@identity_extractor("mulesoft")
def _from_mulesoft(resources: list) -> tuple:
    """Each Connected App is a non-human OAuth client identity; each scope it holds is a grant.
    Anypoint's list endpoint never returns the client secret, so the credential is recorded as
    present-metadata only (never a value)."""
    out: list[Resource] = []
    edges: list[Edge] = []
    for r in resources:
        if r.kind != "mulesoft_app":
            continue
        raw = r.raw or {}
        cid = raw.get("client_id")
        idr = _mk_identity("mulesoft", "oauth_client", raw.get("name") or cid, external=True,
                           source_ext=r.ext_id, extra={"client_id": cid})
        out.append(idr)
        cred = _mk_credential("mulesoft", idr.ext_id, "client_secret",
                              name=f"{raw.get('name') or cid}:secret", hashing="n/a", present=True,
                              plaintext=False)
        out.append(cred)
        edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
        for scope in raw.get("scopes") or []:
            broad = any(m in scope.lower() for m in _BROAD_SCOPE_MARKERS)
            g = _mk_grant("mulesoft", idr.ext_id, "scope", str(scope), wildcard=broad)
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
