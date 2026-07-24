"""Boomi rulepack — read-only inference over what connect/boomi.py collected.

The highest-signal facts are on the published API's inbound gateway (is it authenticated, is it
TLS) and on the reuse of Connection credentials across environments. Every rule reads a fact the
connector recorded; when the inbound auth config could not be read, the auth rules DECLINE to assess
(BOOMI.API.AUTH_UNREADABLE) rather than reading absence as 'no auth'.
"""
from ..contracts import Hit
from ..registry import detector
from ..connect.boomi import _NO_AUTH, _STRONG_AUTH, _WEAK_AUTH, role_is_overprivileged


# ══ BOOMI.API.AUTH_UNREADABLE ═════════════════════════════════════════════
@detector(kinds=["boomi_api"], rule_id="BOOMI.API.AUTH_UNREADABLE", severity="info",
          title="Boomi published-API authentication config could not be read")
def auth_unreadable(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("auth_readable"):
        return []
    return [Hit(
        observation=(f"Published API '{raw.get('name')}' (id {raw.get('id')}, env "
                     f"{raw.get('environment_name')}) — the SharedServerInformation authentication "
                     f"type could not be read, so whether the API requires authentication was not "
                     f"determined."),
        remediation="Grant the API token read access to SharedServerInformation and re-scan so the "
                    "inbound authentication posture can be evaluated.",
        detail=f"api_id={raw.get('id')} auth_readable=False",
        assessable=False,
        assessment_reason="SharedServerInformation authentication type unreadable",
        source_ref={"api": "POST /SharedServerInformation/query"},
    )]


# ══ BOOMI.API.NO_AUTHENTICATION ═══════════════════════════════════════════
@detector(kinds=["boomi_api"], rule_id="BOOMI.API.NO_AUTHENTICATION", severity="high",
          title="Boomi published API requires no authentication")
def no_authentication(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("auth_readable"):
        return []                                   # AUTH_UNREADABLE owns this case
    if raw.get("authentication_type") not in _NO_AUTH:
        return []
    return [Hit(
        observation=(
            f"Published API '{raw.get('name')}' (id {raw.get('id')}, env "
            f"{raw.get('environment_name')}) has SharedServerInformation authenticationType='none', "
            f"so its gateway URL {raw.get('public_url')!r} accepts requests with no credential."),
        remediation=("Set the API's inbound authentication to API Key, OAuth 2.0, or client "
                     "certificate on the shared server / gateway. An authType of none is an "
                     "unauthenticated endpoint into whatever the process fronts."),
        detail=f"authentication_type=none env={raw.get('environment_name')}",
        source_ref={"api": "POST /SharedServerInformation/query", "config_key": "authType"},
    )]


# ══ BOOMI.API.WEAK_AUTH ═══════════════════════════════════════════════════
@detector(kinds=["boomi_api"], rule_id="BOOMI.API.WEAK_AUTH", severity="medium",
          title="Boomi published API uses only HTTP Basic authentication")
def weak_auth(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("auth_readable"):
        return []
    if raw.get("authentication_type") not in _WEAK_AUTH:
        return []
    return [Hit(
        observation=(
            f"Published API '{raw.get('name')}' (id {raw.get('id')}, env "
            f"{raw.get('environment_name')}) has SharedServerInformation authenticationType='basic', "
            f"a shared static username/password rather than a rotatable API key or OAuth token."),
        remediation=(f"Prefer API Key or OAuth 2.0 over HTTP Basic on the shared server "
                     f"(stronger options: {sorted(_STRONG_AUTH)!r}). If Basic must be used, ensure "
                     f"the credential is rotated and the endpoint is TLS-only."),
        detail=f"authentication_type=basic env={raw.get('environment_name')}",
        source_ref={"api": "POST /SharedServerInformation/query", "config_key": "authType"},
    )]


# ══ BOOMI.API.NO_TLS ══════════════════════════════════════════════════════
@detector(kinds=["boomi_api"], rule_id="BOOMI.API.NO_TLS", severity="high",
          title="Boomi published API does not require HTTPS")
def no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("https_required"):
        return []
    return [Hit(
        observation=(
            f"Published API '{raw.get('name')}' (id {raw.get('id')}, env "
            f"{raw.get('environment_name')}) does not require HTTPS on its shared server "
            f"(url {raw.get('public_url')!r}), so requests and any credentials cross the network in "
            f"cleartext."),
        remediation=("Require HTTPS on the shared server / API gateway and disable the plaintext "
                     "listener. Combined with Basic or API-key auth, a plaintext endpoint leaks the "
                     "credential on every call."),
        detail=f"https_required=False url={raw.get('public_url')}",
        source_ref={"api": "POST /SharedServerInformation/query", "config_key": "sslCertId/url"},
    )]


# ══ BOOMI.CONNECTION.REUSED_ACROSS_ENVIRONMENTS ═══════════════════════════
@detector(kinds=["boomi_connection"], rule_id="BOOMI.CONNECTION.REUSED_ACROSS_ENVIRONMENTS",
          severity="medium",
          title="Boomi connection credential is reused across environments")
def connection_reused(r, ctx) -> list:
    raw = r.raw or {}
    envs = raw.get("environments") or []
    if len(envs) < 2:
        return []
    return [Hit(
        observation=(
            f"Connection '{raw.get('name')}' (id {raw.get('id')}, type {raw.get('connector_type')}) "
            f"is deployed into {len(envs)} environments {envs!r}, so the same connection credential "
            f"spans them: a leak in any one environment exposes the others, and non-prod and prod "
            f"are not isolated."),
        remediation=("Use environment extensions to give each environment its own connection "
                     "credential, so a compromise in a lower environment cannot reach production."),
        detail=f"environments={envs}",
        source_ref={"api": "POST /Connection/query", "config_key": "environments"},
    )]


# ══ BOOMI.ROLE.OVER_PRIVILEGED ════════════════════════════════════════════
@detector(kinds=["boomi_role"], rule_id="BOOMI.ROLE.OVER_PRIVILEGED", severity="high",
          title="Boomi account role carries account-wide administrative privileges")
def role_overprivileged(r, ctx) -> list:
    raw = r.raw or {}
    broad = role_is_overprivileged(raw.get("privileges") or [])
    if not broad:
        return []
    return [Hit(
        observation=(
            f"Account role '{raw.get('name')}' (id {raw.get('id')}) carries account-wide "
            f"administrative privilege(s) {broad!r} out of {len(raw.get('privileges') or [])} total, "
            f"so any user or API token bound to this role can administer the whole account."),
        remediation=("Split administrative privileges out of roles granted to integrations and "
                     "day-to-day users; reserve account-administration for a small, audited set of "
                     "human owners."),
        detail=f"broad_privileges={broad}",
        source_ref={"api": "POST /Role/query", "config_key": "privileges"},
    )]
