"""Keycloak rulepack — config-time posture over what connect/keycloak.py collected.

Every rule reads REAL configuration evidence (a client's redirectUris, its publicClient/PKCE
combination, a token-signing algorithm attribute, the realm's sslRequired, the realm's OIDC
discovery algs) and cites it; none guesses from names. Rules run on the DISTINCT keycloak_*
kinds the connector emits.

Two disciplines:
  • Semi-trusted evidence. clientId / redirectUris / webOrigins are admin- (or tenant-)
    controlled strings; they are quoted through `_cap` so a crafted value cannot pad the
    ledger.
  • The third outcome. A realm or clients read the token could not perform (401/403) is a
    coverage gap surfaced as assessable=False, never a clean pass.

Severity conventions (house): high = token-theft / forgery primitive (wildcard redirect,
public client without PKCE, unsigned tokens, SSL never required); medium = weaker-flow /
CORS / no brute-force protection; low/info = hygiene and coverage notes.
"""
from ..contracts import Hit
from ..registry import detector


def _cap(s, n=96):
    """Quote an admin/tenant-controlled string for evidence: repr (control chars show) with a
    length cap so a hostile value cannot pad an observation into the immutable ledger."""
    s = str(s)
    return repr(s[:n] + "…") if len(s) > n else repr(s)


def _redirect_is_broad(uri) -> bool:
    """True when a redirect URI's wildcard reaches the scheme or host — the open-redirect /
    token-theft shapes ("*", "http://*", "https://*.evil style", "*://…"). A wildcard confined
    to the path ("https://app.example.com/*") is the common, low-risk form and is NOT flagged.

    Not urlsplit-based: "*" is not a legal scheme char, so urlsplit would misfile "*://host" as
    a path. This splits on the scheme/authority/path boundaries directly."""
    u = str(uri or "").strip()
    if not u:
        return False
    if u == "*":
        return True
    sep = u.find("://")
    if sep != -1:
        scheme, rest = u[:sep], u[sep + 3:]
        authority = rest.split("/", 1)[0]     # host[:port] before the first path slash
        return "*" in scheme or "*" in authority
    if u.startswith("/"):
        return False                          # path-relative pattern — never scheme/host
    return "*" in u.split("/", 1)[0]          # bare host-ish token carrying a wildcard


# ══ keycloak_client ═══════════════════════════════════════════════════════════
@detector(kinds=["keycloak_client"], rule_id="KEYCLOAK.CLIENT.WILDCARD_REDIRECT_URI",
          severity="high", title="OIDC client has a wildcard redirect URI")
def client_wildcard_redirect(r, ctx) -> list:
    raw = r.raw or {}
    broad = [u for u in raw.get("redirect_uris") or [] if _redirect_is_broad(u)]
    if not broad:
        return []
    return [Hit(
        observation=(f"client {_cap(raw.get('client_id'))} in realm {_cap(raw.get('realm'))} "
                     f"has redirect URI(s) {[u[:96] for u in broad]!r} whose wildcard covers the "
                     f"scheme or host — Keycloak matches the authorization-code redirect against "
                     f"these, so an attacker-controlled URL can receive the code/token"),
        remediation=("Replace host/scheme wildcards with exact redirect URIs (a trailing path "
                     "wildcard like https://app.example.com/callback/* is acceptable; "
                     "https://*, http://* and \"*\" are not). In the client's Settings → Valid "
                     "redirect URIs, list each concrete callback. Open redirect URIs are the "
                     "classic OAuth code/token-theft primitive."),
        detail=f"redirect_uris={raw.get('redirect_uris')}",
        source_ref={"api": "GET admin/realms/{realm}/clients", "field": "redirectUris"},
    )]


@detector(kinds=["keycloak_client"], rule_id="KEYCLOAK.CLIENT.PUBLIC_NO_PKCE", severity="high",
          title="Public client uses the auth-code flow without PKCE S256")
def client_public_no_pkce(r, ctx) -> list:
    raw = r.raw or {}
    if not (raw.get("public_client") and raw.get("standard_flow_enabled")):
        return []
    method = (raw.get("attributes") or {}).get("pkce.code.challenge.method")
    if str(method) == "S256":
        return []
    return [Hit(
        observation=(f"public client {_cap(raw.get('client_id'))} has standardFlowEnabled=true "
                     f"with pkce.code.challenge.method={_cap(method) if method else 'unset'} — a "
                     f"public (secret-less) client running the authorization-code flow without "
                     f"PKCE S256 is open to authorization-code interception"),
        remediation=("Require PKCE on the client: set 'Proof Key for Code Exchange Code "
                     "Challenge Method' = S256 in Advanced settings (attribute "
                     "pkce.code.challenge.method=S256). Public SPAs and native apps must use "
                     "PKCE; 'plain' or unset leaves the code exchange unprotected."),
        detail=f"public_client=True standard_flow=True pkce={method!r}",
        source_ref={"api": "GET admin/realms/{realm}/clients",
                    "field": "attributes.pkce.code.challenge.method"},
    )]


@detector(kinds=["keycloak_client"], rule_id="KEYCLOAK.CLIENT.DIRECT_ACCESS_GRANTS",
          severity="medium", title="Confidential client enables direct access grants (ROPC)")
def client_direct_access_grants(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("direct_access_grants_enabled"):
        return []
    if raw.get("public_client") or raw.get("bearer_only"):
        return []   # the task scopes this to confidential clients; public admin-cli is by design
    return [Hit(
        observation=(f"confidential client {_cap(raw.get('client_id'))} has "
                     f"directAccessGrantsEnabled=true — the Resource Owner Password Credentials "
                     f"grant is enabled, so end-user usernames and passwords flow through this "
                     f"client instead of the browser redirect, defeating MFA and federated login"),
        remediation=("Disable 'Direct access grants' on the client unless a legacy first-party "
                     "app genuinely needs ROPC. Move interactive logins to the authorization-"
                     "code flow. OAuth 2.1 removes the password grant for this reason."),
        detail="direct_access_grants_enabled=True public_client=False",
        source_ref={"api": "GET admin/realms/{realm}/clients",
                    "field": "directAccessGrantsEnabled"},
    )]


@detector(kinds=["keycloak_client"], rule_id="KEYCLOAK.CLIENT.IMPLICIT_FLOW", severity="medium",
          title="OIDC client enables the implicit flow")
def client_implicit_flow(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("implicit_flow_enabled"):
        return []
    return [Hit(
        observation=(f"client {_cap(raw.get('client_id'))} has implicitFlowEnabled=true — the "
                     f"implicit flow returns access/ID tokens directly in the URL fragment, "
                     f"where they leak via browser history, referrers, and logs; it is "
                     f"deprecated by OAuth 2.1"),
        remediation=("Disable 'Implicit flow' and use the authorization-code flow with PKCE "
                     "instead. No modern client needs implicit."),
        detail="implicit_flow_enabled=True",
        source_ref={"api": "GET admin/realms/{realm}/clients", "field": "implicitFlowEnabled"},
    )]


# alg values that mean 'no integrity protection' on a token/response.
_UNSIGNED_ALGS = {"none"}
_SIGN_ATTRS = {
    "access.token.signed.response.alg": "access token",
    "id.token.signed.response.alg": "ID token",
    "request.object.signature.alg": "request object",
    "authorization.signed.response.alg": "authorization response (JARM)",
}


@detector(kinds=["keycloak_client"], rule_id="KEYCLOAK.CLIENT.UNSIGNED_TOKENS", severity="high",
          title="OIDC client is configured to issue unsigned tokens")
def client_unsigned_tokens(r, ctx) -> list:
    raw = r.raw or {}
    attrs = raw.get("attributes") or {}
    hits = []
    for key, label in _SIGN_ATTRS.items():
        val = attrs.get(key)
        if val is None:
            continue
        low = str(val).strip().lower()
        # request.object.signature.alg = "any" also permits an unsigned request object.
        unsigned = low in _UNSIGNED_ALGS or (key == "request.object.signature.alg" and low == "any")
        if not unsigned:
            continue
        hits.append(Hit(
            observation=(f"client {_cap(raw.get('client_id'))} sets {key}={_cap(val)} — the "
                         f"{label} is issued/accepted WITHOUT a signature, so its integrity "
                         f"cannot be verified and its contents can be forged or tampered with"),
            remediation=(f"Set {key} to a signing algorithm (RS256 or better; ES256 preferred) "
                         f"in the client's Advanced settings. Never 'none'/'any' for a "
                         f"{label} — an unsigned token is trust without verification."),
            detail=f"{key}={val!r}",
            source_ref={"api": "GET admin/realms/{realm}/clients", "field": f"attributes.{key}"},
        ))
    return hits


@detector(kinds=["keycloak_client"], rule_id="KEYCLOAK.CLIENT.WEB_ORIGINS_WILDCARD",
          severity="medium", title="OIDC client allows all CORS origins")
def client_web_origins_wildcard(r, ctx) -> list:
    raw = r.raw or {}
    if "*" not in (raw.get("web_origins") or []):
        return []
    return [Hit(
        observation=(f"client {_cap(raw.get('client_id'))} has webOrigins containing \"*\" — "
                     f"CORS is allowed from ANY origin, so a malicious site can drive "
                     f"cross-origin token requests against this client"),
        remediation=("Replace \"*\" in Web origins with the exact origins that host this client, "
                     "or use \"+\" to mirror the registered redirect URIs. A wildcard CORS "
                     "origin on an OAuth client widens the token-request surface to the whole web."),
        detail=f"web_origins={raw.get('web_origins')}",
        source_ref={"api": "GET admin/realms/{realm}/clients", "field": "webOrigins"},
    )]


# ══ keycloak_realm ════════════════════════════════════════════════════════════
@detector(kinds=["keycloak_realm"], rule_id="KEYCLOAK.REALM.SSL_NOT_REQUIRED", severity="high",
          title="Realm does not require SSL for all requests")
def realm_ssl_not_required(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("realm_readable"):
        return _realm_gap(raw, "sslRequired")
    ssl = str(raw.get("ssl_required") or "").lower()
    if ssl in ("all", ""):     # '' = field absent; 'all' = required everywhere (best)
        return []
    if ssl == "none":
        return [Hit(
            observation=(f"realm {_cap(raw.get('realm'))} has sslRequired=none — Keycloak "
                         f"accepts logins and token requests over plaintext HTTP from any "
                         f"address, so credentials and tokens can cross the network unencrypted"),
            remediation=("Set the realm's 'Require SSL' to 'all requests' (sslRequired=all). "
                         "'none' should never be used outside a throwaway local dev realm."),
            detail="ssl_required=none",
            source_ref={"api": "GET admin/realms/{realm}", "field": "sslRequired"},
        )]
    # 'external' is the default: HTTPS enforced for external addresses, HTTP tolerated for
    # private/loopback ones. Honest low-severity note, not a critical.
    return [Hit(
        observation=(f"realm {_cap(raw.get('realm'))} has sslRequired=external — HTTPS is "
                     f"enforced for external clients but plaintext HTTP is still accepted from "
                     f"private/loopback addresses, which a flat or compromised internal network "
                     f"does not isolate"),
        severity="low",
        remediation=("For a zero-trust posture set sslRequired=all so even internal traffic to "
                     "Keycloak is TLS-only. 'external' is the default and acceptable when the "
                     "private network is genuinely trusted."),
        detail="ssl_required=external",
        source_ref={"api": "GET admin/realms/{realm}", "field": "sslRequired"},
    )]


@detector(kinds=["keycloak_realm"], rule_id="KEYCLOAK.REALM.BRUTE_FORCE_OFF", severity="medium",
          title="Realm has brute-force protection disabled")
def realm_brute_force_off(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("realm_readable"):
        return _realm_gap(raw, "bruteForceProtected")
    if raw.get("brute_force_protected"):
        return []
    return [Hit(
        observation=(f"realm {_cap(raw.get('realm'))} has bruteForceProtected=false — Keycloak "
                     f"applies no lockout or backoff on repeated failed logins, so password "
                     f"guessing and credential-stuffing against realm accounts is unthrottled"),
        remediation=("Enable Realm settings → Security defenses → Brute force detection "
                     "(bruteForceProtected=true) with a sensible failureFactor and lockout. "
                     "Pair it with strong password policy and MFA."),
        detail="brute_force_protected=False",
        source_ref={"api": "GET admin/realms/{realm}", "field": "bruteForceProtected"},
    )]


@detector(kinds=["keycloak_realm"], rule_id="KEYCLOAK.REALM.OIDC_UNSIGNED_ID_TOKEN",
          severity="medium", title="Realm advertises unsigned ID tokens in OIDC discovery")
def realm_oidc_unsigned(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("discovery_readable"):
        return []   # discovery unreadable is covered by the realm coverage-gap rule
    algs = raw.get("id_token_signing_alg_values_supported") or []
    if "none" not in [str(a).lower() for a in algs]:
        return []
    return [Hit(
        observation=(f"realm {_cap(raw.get('realm'))} OIDC discovery lists "
                     f"id_token_signing_alg_values_supported including 'none' (issuer "
                     f"{_cap(raw.get('issuer'))}) — the realm advertises it can issue UNSIGNED "
                     f"ID tokens, which a relying party that accepts alg=none will trust without "
                     f"verification"),
        remediation=("Remove 'none' from the realm's supported ID-token signing algorithms and "
                     "ensure no client sets id.token.signed.response.alg=none. Relying parties "
                     "must reject alg=none regardless."),
        detail=f"id_token_signing_alg_values_supported={algs}",
        source_ref={"api": "GET .well-known/openid-configuration",
                    "field": "id_token_signing_alg_values_supported"},
    )]


@detector(kinds=["keycloak_realm"], rule_id="KEYCLOAK.REALM.USER_REGISTRATION_OPEN",
          severity="low", title="Realm allows open self-registration")
def realm_registration_open(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("realm_readable"):
        return []
    if not raw.get("registration_allowed"):
        return []
    return [Hit(
        observation=(f"realm {_cap(raw.get('realm'))} has registrationAllowed=true — anyone who "
                     f"can reach the login page can create an account in this realm, expanding "
                     f"the set of principals the downstream applications will trust"),
        remediation=("Disable self-registration (registrationAllowed=false) unless this realm is "
                     "intentionally an open sign-up tenant; if it is, gate it with email "
                     "verification, a CAPTCHA, and least-privilege default roles."),
        detail="registration_allowed=True",
        source_ref={"api": "GET admin/realms/{realm}", "field": "registrationAllowed"},
    )]


@detector(kinds=["keycloak_realm"], rule_id="KEYCLOAK.REALM.MASTER_REALM_IN_USE",
          severity="info", title="The Keycloak master realm is in use")
def realm_master_in_use(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("realm") != "master":
        return []
    return [Hit(
        observation=("this connection targets the 'master' realm — the realm that holds "
                     "Keycloak's super-administrators and governs every other realm; it is "
                     "intended for bootstrap and administration, not for application logins"),
        remediation=("Host applications in their own realms, not master. Lock the master realm "
                     "down: remove the default 'admin' account or give it a strong unique "
                     "password, require MFA on master admins, and restrict its access. NOTE: "
                     "whether the default admin credentials are still in place cannot be "
                     "confirmed remotely by this read-only scan — verify it directly."),
        detail="realm=master",
        assessable=False,
        assessment_reason="default-admin-credential state is not remotely observable read-only",
        source_ref={"api": "GET admin/realms/{realm}", "field": "realm"},
    )]


@detector(kinds=["keycloak_realm"], rule_id="KEYCLOAK.REALM.NOT_ASSESSED", severity="info",
          title="A Keycloak endpoint could not be read with the supplied credentials")
def realm_not_assessed(r, ctx) -> list:
    """The third honest outcome at realm scope: an admin endpoint that answered 401/403 (or a
    failed token grant) is a COVERAGE GAP, surfaced as not-assessable rather than letting the
    missing data read as 'nothing wrong'."""
    raw = r.raw or {}
    hits = []
    for endpoint, rec in sorted((raw.get("collection") or {}).items()):
        if (rec or {}).get("outcome") in ("ok", None):
            continue
        hits.append(Hit(
            observation=(f"reading {endpoint} returned {rec.get('error')} "
                         f"({rec.get('outcome')}), so what it enumerates was not assessed"),
            remediation=(f"Grant the scan credential permission for {endpoint} (view-realm / "
                         f"view-clients, or a working client-credentials grant). Until then "
                         f"this surface is unknown, not clean."),
            detail=f"endpoint={endpoint} outcome={rec.get('outcome')} error={rec.get('error')}",
            assessable=False,
            assessment_reason=f"{endpoint} returned {rec.get('outcome')}",
            source_ref={"api": f"GET {endpoint}"},
        ))
    return hits


def _realm_gap(raw: dict, field: str) -> list:
    """Shared not-assessable Hit for a realm-scoped rule whose realm rep was unreadable."""
    return [Hit(
        observation=(f"the realm representation was not readable "
                     f"({(raw.get('collection') or {}).get('admin/realms/' + str(raw.get('realm')), {}).get('error')}), "
                     f"so realm field '{field}' could not be assessed"),
        remediation="Grant the scan credential view-realm on this realm so its settings can be "
                    "read.",
        detail=f"realm_readable=False field={field}",
        assessable=False,
        assessment_reason="realm representation returned forbidden/error",
        source_ref={"api": "GET admin/realms/{realm}", "field": field},
    )]
