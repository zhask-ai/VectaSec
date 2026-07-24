"""MuleSoft Anypoint rulepack — read-only inference over what connect/mulesoft.py collected.

The core question for a managed API is "who is allowed to call it, and how much". API Manager answers
it entirely through the applied-policy list, so these rules read that list (excluding DISABLED
policies, which are attached but not enforcing) and never re-query Anypoint. When the policies list
could not be read, the policy-based rules DECLINE to assess rather than reading absence as 'no
policy' — that not-assessable path is MULE.API.POLICIES_UNREADABLE.
"""
from ..contracts import Hit
from ..registry import detector
from ..connect.mulesoft import (
    _AUTH_POLICY_ASSETS, _BROAD_SCOPE_MARKERS, _CLIENT_ID_ENFORCEMENT, _RATE_POLICY_ASSETS,
    enforcing_assets,
)


def _policies_readable(raw: dict) -> bool:
    return bool(raw.get("policies_readable"))


# ══ MULE.API.POLICIES_UNREADABLE ══════════════════════════════════════════
@detector(kinds=["mulesoft_api"], rule_id="MULESOFT.API.POLICIES_UNREADABLE", severity="info",
          title="MuleSoft API policies could not be read")
def policies_unreadable(r, ctx) -> list:
    raw = r.raw or {}
    if _policies_readable(raw):
        return []
    return [Hit(
        observation=(f"API instance '{raw.get('instance_label')}' (id {raw.get('api_id')}, env "
                     f"{raw.get('environment')}) — GET .../apis/{raw.get('api_id')}/policies did not "
                     f"return a readable policy list, so the applied-policy posture (authentication, "
                     f"rate limiting) could not be assessed."),
        remediation="Grant the Connected App the API Manager read scope for this environment and "
                    "re-scan so policy coverage can be evaluated.",
        detail=f"env={raw.get('environment')} api_id={raw.get('api_id')}",
        assessable=False,
        assessment_reason="policies list unreadable for this API instance",
        source_ref={"api": "GET /apimanager/api/v1/.../apis/{id}/policies"},
    )]


# ══ MULE.API.NO_AUTH_POLICY ═══════════════════════════════════════════════
@detector(kinds=["mulesoft_api"], rule_id="MULESOFT.API.NO_AUTH_POLICY", severity="high",
          title="MuleSoft managed API has no authentication policy applied")
def no_auth_policy(r, ctx) -> list:
    raw = r.raw or {}
    if not _policies_readable(raw):
        return []                                   # POLICIES_UNREADABLE owns this case
    if enforcing_assets(raw) & _AUTH_POLICY_ASSETS:
        return []
    return [Hit(
        observation=(
            f"API instance '{raw.get('instance_label')}' (id {raw.get('api_id')}, env "
            f"{raw.get('environment')}) has no enforcing authentication policy: its applied-policy "
            f"list contains none of {sorted(_AUTH_POLICY_ASSETS)!r}. The published endpoint "
            f"{raw.get('endpoint_uri')!r} accepts calls without any client identity being enforced."),
        remediation=("Apply an authentication policy in API Manager — at minimum "
                     "client-id-enforcement, or preferably JWT / OpenID Connect / OAuth 2.0 token "
                     "validation. An API with no auth policy is an unauthenticated endpoint."),
        detail=f"enforcing_policies={sorted(enforcing_assets(raw))}",
        source_ref={"api": "GET /apimanager/api/v1/.../apis/{id}/policies"},
    )]


# ══ MULE.API.NO_CLIENT_ID_ENFORCEMENT ═════════════════════════════════════
@detector(kinds=["mulesoft_api"], rule_id="MULESOFT.API.NO_CLIENT_ID_ENFORCEMENT", severity="medium",
          title="MuleSoft API authenticates but does not enforce client-id")
def no_client_id_enforcement(r, ctx) -> list:
    raw = r.raw or {}
    if not _policies_readable(raw):
        return []
    enforcing = enforcing_assets(raw)
    # Only fire when the API DOES authenticate some other way but client-id-enforcement specifically
    # is absent — an API with no auth at all is MULE.API.NO_AUTH_POLICY's finding, not this one.
    if not (enforcing & _AUTH_POLICY_ASSETS):
        return []
    if _CLIENT_ID_ENFORCEMENT in enforcing:
        return []
    return [Hit(
        observation=(
            f"API instance '{raw.get('instance_label')}' (env {raw.get('environment')}) enforces "
            f"authentication via {sorted(enforcing & _AUTH_POLICY_ASSETS)!r} but has no "
            f"client-id-enforcement policy, so calls are not tied to a registered client application "
            f"and per-application throttling/analytics/revocation are unavailable."),
        remediation=("Add a client-id-enforcement policy so each caller presents a registered "
                     "client_id (and, for contracts, a client_secret). This is defense-in-depth "
                     "alongside token validation, not a replacement for it."),
        detail=f"enforcing_policies={sorted(enforcing)}",
        source_ref={"api": "GET /apimanager/api/v1/.../apis/{id}/policies"},
    )]


# ══ MULE.API.NO_RATE_LIMITING ═════════════════════════════════════════════
@detector(kinds=["mulesoft_api"], rule_id="MULESOFT.API.NO_RATE_LIMITING", severity="medium",
          title="MuleSoft managed API has no rate-limiting or SLA policy")
def no_rate_limiting(r, ctx) -> list:
    raw = r.raw or {}
    if not _policies_readable(raw):
        return []
    if enforcing_assets(raw) & _RATE_POLICY_ASSETS:
        return []
    return [Hit(
        observation=(
            f"API instance '{raw.get('instance_label')}' (env {raw.get('environment')}) has no "
            f"enforcing rate-limiting, rate-limiting-sla, or spike-control policy, so a single "
            f"caller can drive unlimited request volume at the upstream."),
        remediation=("Apply a rate-limiting or SLA-based rate-limiting policy in API Manager, or a "
                     "spike-control policy, sized to the upstream's capacity."),
        detail=f"enforcing_policies={sorted(enforcing_assets(raw))}",
        source_ref={"api": "GET /apimanager/api/v1/.../apis/{id}/policies"},
    )]


# ══ MULE.API.INSECURE_TRANSPORT ═══════════════════════════════════════════
@detector(kinds=["mulesoft_api"], rule_id="MULESOFT.API.INSECURE_TRANSPORT", severity="high",
          title="MuleSoft API endpoint is served over plaintext HTTP")
def insecure_transport(r, ctx) -> list:
    raw = r.raw or {}
    scheme = raw.get("endpoint_scheme")
    if scheme != "http":                            # https / https-mutual / unknown → not this rule
        return []
    return [Hit(
        observation=(
            f"API instance '{raw.get('instance_label')}' (env {raw.get('environment')}) has endpoint "
            f"{raw.get('endpoint_uri')!r}, an http:// (no TLS) scheme, so requests — including any "
            f"client_id/client_secret or bearer token — cross the network in cleartext."),
        remediation=("Serve the API over https with a TLS context (and require mutual TLS for "
                     "service-to-service APIs). Terminate TLS at or before the API instance, not "
                     "after it."),
        detail=f"endpoint_scheme=http uri={raw.get('endpoint_uri')}",
        source_ref={"api": "GET /apimanager/api/v1/.../apis", "config_key": "endpoint.uri"},
    )]


# ══ MULE.API.POLICY_DISABLED ══════════════════════════════════════════════
@detector(kinds=["mulesoft_api"], rule_id="MULESOFT.API.POLICY_DISABLED", severity="medium",
          title="MuleSoft security policy is attached but disabled")
def policy_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if not _policies_readable(raw):
        return []
    security = _AUTH_POLICY_ASSETS | _RATE_POLICY_ASSETS
    disabled = sorted({p["asset"] for p in (raw.get("policies") or [])
                       if p["disabled"] and p["asset"] in security})
    if not disabled:
        return []
    return [Hit(
        observation=(
            f"API instance '{raw.get('instance_label')}' (env {raw.get('environment')}) has "
            f"security policies {disabled!r} attached with disabled=true, so they are visible in API "
            f"Manager but not enforced on requests."),
        remediation=("Re-enable the policy, or remove it so the configuration does not misrepresent "
                     "the API's posture. A disabled auth or rate-limit policy protects nothing."),
        detail=f"disabled_security_policies={disabled}",
        source_ref={"api": "GET /apimanager/api/v1/.../apis/{id}/policies", "config_key": "disabled"},
    )]


# ══ MULE.API.DEPRECATED ═══════════════════════════════════════════════════
@detector(kinds=["mulesoft_api"], rule_id="MULESOFT.API.DEPRECATED", severity="low",
          title="MuleSoft API instance is marked deprecated")
def api_deprecated(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("deprecated"):
        return []
    return [Hit(
        observation=(f"API instance '{raw.get('instance_label')}' (env {raw.get('environment')}) is "
                     f"marked deprecated but is still registered in API Manager and may still receive "
                     f"traffic."),
        remediation=("Confirm the deprecated instance is decommissioned or migrated. A deprecated "
                     "API often stops receiving policy and version updates while remaining reachable."),
        detail=f"deprecated=True instance={raw.get('instance_label')}",
        source_ref={"api": "GET /apimanager/api/v1/.../apis", "config_key": "deprecated"},
    )]


# ══ MULE.APP.OVERPRIVILEGED_SCOPES ════════════════════════════════════════
@detector(kinds=["mulesoft_app"], rule_id="MULESOFT.APP.OVERPRIVILEGED_SCOPES", severity="high",
          title="MuleSoft Connected App holds broad, tenant-wide scopes")
def app_overprivileged(r, ctx) -> list:
    raw = r.raw or {}
    scopes = raw.get("scopes") or []
    broad = sorted({s for s in scopes if any(m in s.lower() for m in _BROAD_SCOPE_MARKERS)})
    if not broad:
        return []
    return [Hit(
        observation=(
            f"Connected App '{raw.get('name')}' (client_id {raw.get('client_id')}) holds broad "
            f"scope(s) {broad!r} out of {len(scopes)} total, granting tenant-wide or "
            f"administrative access to a non-human OAuth client."),
        remediation=("Reduce the Connected App to the minimum scopes its integration needs; remove "
                     "organization-administrator and full-access scopes from machine credentials. A "
                     "leaked client_secret inherits every scope the app holds."),
        detail=f"broad_scopes={broad} total_scopes={len(scopes)}",
        source_ref={"api": "GET /accounts/api/connectedApplications", "config_key": "scopes"},
    )]
