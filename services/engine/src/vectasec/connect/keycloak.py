"""Keycloak connector — read-only posture of the identity broker at the centre of the fabric.

Keycloak (and identity brokers like it) is the middleware that mints the tokens every other
system trusts: a misconfigured client here — a wildcard redirect URI, a public client without
PKCE, an unsigned ID token — is an open-redirect / token-theft / forgery primitive against
everything downstream. Scanning it as a target means reading its realm and client
configuration and the realm's own OIDC discovery document. Only GETs are issued:

  GET {base}/realms/{realm}/.well-known/openid-configuration   the realm's advertised OIDC
                                                                metadata (unauthenticated)
  GET {base}/admin/realms/{realm}                              the realm representation
  GET {base}/admin/realms/{realm}/clients                      the realm's OAuth/OIDC clients

Structured like connect/mcp.py's OAuth-metadata reading: the discovery document is read
unauthenticated first (it is its own posture signal), then the admin API is read with an
admin token or a client-credentials token minted from a service-account client.

SEMI-TRUSTED OBSERVATIONS. clientId / redirectUris / webOrigins are strings an admin (or, in
a multi-tenant broker, a tenant) controls — the detectors quote them through a length cap so a
crafted value cannot pad the immutable ledger. NO SECRET VALUE crosses the boundary: the
clients endpoint returns confidential clients' `secret`, and the realm rep can carry an SMTP
password — the parse layer whitelists non-secret fields and never copies either. Presence of a
client secret is inferred structurally (confidential ⇒ has one), never read.

Kinds are DISTINCT (keycloak_realm, keycloak_client) so no other rulepack runs against a
Keycloak resource by accident. The parse layer (parse_realm, parse_client) is pure: admin-API
JSON in, Resources out — httpx stays out of the tests, which drive detectors against
parse-layer output from golden fixtures.
"""
from urllib.parse import urlsplit

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

# The only client attributes the rulepack and NHI extractor read — kept to a whitelist so an
# arbitrary attribute blob never rides into storage. These are the token-signing and PKCE knobs.
_CLIENT_ATTR_KEYS = (
    "pkce.code.challenge.method",
    "access.token.signed.response.alg",
    "id.token.signed.response.alg",
    "user.info.response.signature.alg",
    "request.object.signature.alg",
    "authorization.signed.response.alg",
)

# Realm fields worth keeping — non-secret posture knobs only (an SMTP password that may appear
# elsewhere in the rep is never in this set).
_REALM_KEYS = (
    "realm", "enabled", "sslRequired", "bruteForceProtected", "permanentLockout",
    "registrationAllowed", "registrationEmailAsUsername", "resetPasswordAllowed",
    "rememberMe", "verifyEmail", "loginWithEmailAllowed", "duplicateEmailsAllowed",
    "defaultSignatureAlgorithm", "passwordPolicy", "otpPolicyType", "failureFactor",
)


# ── parse layer: admin-API JSON → Resources (pure, no httpx) ───────────────────
def parse_client(realm: str, client: dict) -> Resource:
    """One client representation. Whitelists non-secret fields; the `secret` field is never
    read — a client secret's PRESENCE is inferred structurally (confidential clients have one)."""
    c = client or {}
    attrs = c.get("attributes") if isinstance(c.get("attributes"), dict) else {}
    kept_attrs = {k: attrs.get(k) for k in _CLIENT_ATTR_KEYS if k in attrs}
    public = bool(c.get("publicClient"))
    bearer_only = bool(c.get("bearerOnly"))
    client_id = str(c.get("clientId") or c.get("id") or "?")
    return Resource(
        kind="keycloak_client",
        name=client_id,
        ext_id=f"keycloak-client-{realm}-{client_id}",
        namespace=realm,
        labels={"realm": realm,
                "public": "true" if public else "false",
                "bearer_only": "true" if bearer_only else "false"},
        raw={
            "realm": realm,
            "client_id": client_id,
            "enabled": c.get("enabled"),
            "protocol": c.get("protocol"),
            "public_client": public,
            "bearer_only": bearer_only,
            "standard_flow_enabled": bool(c.get("standardFlowEnabled")),
            "implicit_flow_enabled": bool(c.get("implicitFlowEnabled")),
            "direct_access_grants_enabled": bool(c.get("directAccessGrantsEnabled")),
            "service_accounts_enabled": bool(c.get("serviceAccountsEnabled")),
            # confidential (non-public, non-bearer-only) clients authenticate with a secret;
            # we record only that one EXISTS, never its value.
            "has_client_secret": not public and not bearer_only,
            "redirect_uris": [str(u) for u in (c.get("redirectUris") or [])],
            "web_origins": [str(o) for o in (c.get("webOrigins") or [])],
            "attributes": kept_attrs,
            "default_client_scopes": [str(s) for s in (c.get("defaultClientScopes") or [])],
            "optional_client_scopes": [str(s) for s in (c.get("optionalClientScopes") or [])],
        },
    )


def parse_realm(base_url: str, realm: str, rep: dict, discovery: dict, collection: dict) -> Resource:
    """The keycloak_realm resource: whitelisted realm knobs plus the advertised OIDC metadata
    (issuer, the id-token signing algs the realm says it supports). `collection` records the
    per-endpoint outcome so a denied admin read is a coverage gap, not a clean pass."""
    r = rep or {}
    disc = discovery or {}
    kept = {k: r.get(k) for k in _REALM_KEYS if k in r}
    id_token_algs = disc.get("id_token_signing_alg_values_supported")
    return Resource(
        kind="keycloak_realm",
        name=realm,
        ext_id=f"keycloak-realm-{urlsplit(base_url).netloc}-{realm}",
        namespace=None,
        labels={"realm": realm,
                "ssl_required": str(r.get("sslRequired") or "?"),
                "is_master": "true" if realm == "master" else "false"},
        raw={
            "base_url": base_url,
            "realm": realm,
            "realm_readable": collection.get(f"admin/realms/{realm}", {}).get("outcome") == "ok",
            "discovery_readable": collection.get("oidc_discovery", {}).get("outcome") == "ok",
            "ssl_required": r.get("sslRequired"),
            "brute_force_protected": r.get("bruteForceProtected"),
            "permanent_lockout": r.get("permanentLockout"),
            "registration_allowed": r.get("registrationAllowed"),
            "default_signature_algorithm": r.get("defaultSignatureAlgorithm"),
            "password_policy": r.get("passwordPolicy"),
            "realm_fields": kept,
            # OIDC discovery — the realm advertising what token signing it will do.
            "issuer": disc.get("issuer"),
            "id_token_signing_alg_values_supported": (
                [str(a) for a in id_token_algs] if isinstance(id_token_algs, list) else None),
            "authorization_endpoint": disc.get("authorization_endpoint"),
            "token_endpoint": disc.get("token_endpoint"),
            "collection": collection,
        },
    )


# ── collection (httpx in, per-endpoint isolation) ─────────────────────────────
def _get_json(client, url, headers) -> tuple:
    """One GET → (json_or_{}, outcome). 401/403 → 'forbidden' so a rule declines to assess what
    the token could not read; other non-2xx or a non-JSON body → 'error'."""
    try:
        r = client.get(url, headers=headers)
    except Exception as e:
        return {}, {"outcome": "error", "error": f"{type(e).__name__}: {e}"}
    if r.status_code in (401, 403):
        return {}, {"outcome": "forbidden", "error": f"HTTP {r.status_code}"}
    if r.status_code >= 400:
        return {}, {"outcome": "error", "error": f"HTTP {r.status_code}"}
    try:
        return r.json(), {"outcome": "ok", "error": None}
    except ValueError:
        return {}, {"outcome": "error", "error": "non-JSON body"}


def _fetch_token(client, base: str, token_realm: str, client_id: str, client_secret: str) -> tuple:
    """Mint an admin token via the client-credentials grant against a service-account client.
    Returns (access_token_or_None, outcome). The secret is used to authenticate and is NEVER
    stored on any resource."""
    url = f"{base}/realms/{token_realm}/protocol/openid-connect/token"
    data = {"grant_type": "client_credentials", "client_id": client_id,
            "client_secret": client_secret}
    try:
        r = client.post(url, data=data, headers={"Accept": "application/json"})
    except Exception as e:
        return None, {"outcome": "error", "error": f"{type(e).__name__}: {e}"}
    if r.status_code >= 400:
        return None, {"outcome": "error", "error": f"HTTP {r.status_code}"}
    try:
        tok = r.json().get("access_token")
    except ValueError:
        tok = None
    return tok, {"outcome": "ok" if tok else "error", "error": None if tok else "no access_token"}


@connector("keycloak", fields=[
    ConnectorField("base_url", "Keycloak base URL", required=True,
                   placeholder="https://keycloak.example.com",
                   help="Base URL of the Keycloak server. Include the legacy '/auth' suffix "
                        "only if this deployment still serves it. Read-only: only the realm, "
                        "its clients, and its OIDC discovery document are fetched."),
    ConnectorField("realm", "Realm", required=True, placeholder="myrealm",
                   help="The realm to assess."),
    ConnectorField("token", "Admin bearer token", secret=True,
                   help="An admin access token with view-clients / view-realm. Alternatively "
                        "supply client_id + client_secret to mint one. Never stored."),
    ConnectorField("client_id", "Service-account client ID", placeholder="vectasec-scanner",
                   help="A confidential client with view permissions, used with client_secret "
                        "to obtain a token via the client-credentials grant."),
    ConnectorField("client_secret", "Service-account client secret", secret=True,
                   help="Secret for the client-credentials grant. Used to authenticate, never "
                        "stored on any resource."),
    ConnectorField("token_realm", "Token realm", placeholder="master",
                   help="Realm to authenticate the client-credentials grant against "
                        "(defaults to the scanned realm)."),
    ConnectorField("verify_tls", "Verify TLS", placeholder="true",
                   help="'false' to skip TLS verification for a self-signed dev server."),
])
def collect(config: dict) -> Collected:
    base = (config.get("base_url") or "").strip().rstrip("/")
    realm = (config.get("realm") or "").strip()
    if not base or not realm:
        raise SystemExit("keycloak connector requires config['base_url'] and config['realm']")
    timeout = float(config.get("timeout") or 15)
    verify = str(config.get("verify_tls", "true")).strip().lower() not in ("0", "false", "no", "off")

    collection: dict = {}
    resources: list[Resource] = []
    edges: list[Edge] = []

    with httpx.Client(timeout=timeout, verify=verify, follow_redirects=True) as client:
        # ── OIDC discovery (unauthenticated) ──
        disc, collection["oidc_discovery"] = _get_json(
            client, f"{base}/realms/{realm}/.well-known/openid-configuration",
            {"Accept": "application/json"})

        # ── obtain an admin token: explicit token wins, else client-credentials ──
        token = (config.get("token") or "").strip()
        cid = (config.get("client_id") or "").strip()
        csecret = (config.get("client_secret") or "").strip()
        if not token and cid and csecret:
            token_realm = (config.get("token_realm") or realm).strip() or realm
            token, collection["token_grant"] = _fetch_token(client, base, token_realm, cid, csecret)
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # ── realm representation ──
        rep, collection[f"admin/realms/{realm}"] = _get_json(
            client, f"{base}/admin/realms/{realm}", headers)

        realm_res = parse_realm(base, realm, rep, disc, collection)

        # ── clients ──
        clients, collection[f"admin/realms/{realm}/clients"] = _get_json(
            client, f"{base}/admin/realms/{realm}/clients", headers)

    resources.append(realm_res)
    for c in clients if isinstance(clients, list) else []:
        if not isinstance(c, dict):
            continue
        cr = parse_client(realm, c)
        resources.append(cr)
        edges.append(Edge(src_ext_id=realm_res.ext_id, dst_ext_id=cr.ext_id, kind="registers"))

    return Collected(resources=resources, edges=edges)


# ── NHI: clients + service accounts → identity/credential/grant ────────────────
@identity_extractor("keycloak")
def _from_keycloak(resources: list) -> tuple:
    """Keycloak's non-human identities in the normalized model:

      keycloak_client → identity (type "oauth_client"). A confidential client authenticates
                        with a client secret → a credential (metadata only; the value is never
                        collected). A serviceAccountsEnabled client also has a service-account
                        principal (`service-account-<clientId>`) — its own identity, holding the
                        same secret.
      default scopes  → one grant per scope the client may request (action "scope").

    Public clients hold no secret → a credential's ABSENCE, recorded by not emitting one."""
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "keycloak_client":
            continue
        raw = r.raw or {}
        cid = raw.get("client_id") or r.name
        realm = raw.get("realm") or ""
        idr = _mk_identity("keycloak", "oauth_client", f"{realm}/{cid}",
                           external=bool(raw.get("public_client")), source_ext=r.ext_id,
                           extra={"realm": realm, "public": raw.get("public_client"),
                                  "bearer_only": raw.get("bearer_only")})
        out.append(idr)

        if raw.get("has_client_secret"):
            cred = _mk_credential("keycloak", idr.ext_id, "client_secret",
                                  name=f"{realm}/{cid}:client_secret", hashing="n/a",
                                  present=True, plaintext=False)
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

        # A service-account client is itself a non-human principal Keycloak names
        # service-account-<clientId>; it authenticates with the same client secret.
        if raw.get("service_accounts_enabled"):
            sa = _mk_identity("keycloak", "service_account", f"{realm}/service-account-{cid}",
                              tags=["service_account"], source_ext=r.ext_id,
                              extra={"realm": realm, "for_client": cid})
            out.append(sa)
            if raw.get("has_client_secret"):
                sacred = _mk_credential("keycloak", sa.ext_id, "client_secret",
                                        name=f"{realm}/service-account-{cid}:client_secret",
                                        hashing="n/a", present=True, plaintext=False)
                out.append(sacred)
                edges.append(Edge(src_ext_id=sacred.ext_id, dst_ext_id=sa.ext_id,
                                  kind="credential_of"))

        for scope in raw.get("default_client_scopes") or []:
            g = _mk_grant("keycloak", idr.ext_id, "scope", str(scope),
                          wildcard=(str(scope) in ("*", "all")))
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
