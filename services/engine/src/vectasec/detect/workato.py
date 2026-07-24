"""Workato rulepack — read-only inference over what connect/workato.py collected.

Highest-signal facts: an API client that can administer the workspace with no IP allowlist (a
machine credential usable from anywhere), a published endpoint gated by no access profile, and a
connection shared workspace-wide. When an API client's role could not be resolved, the admin-scoped
rules DECLINE to assess (WORKATO.APICLIENT.ROLE_UNREADABLE) rather than guessing.
"""
from ..contracts import Hit
from ..registry import detector


# ══ WORKATO.APICLIENT.ROLE_UNREADABLE ═════════════════════════════════════
@detector(kinds=["workato_api_client"], rule_id="WORKATO.APICLIENT.ROLE_UNREADABLE", severity="info",
          title="Workato API client role could not be read")
def role_unreadable(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("role_readable"):
        return []
    return [Hit(
        observation=(f"API client '{raw.get('name')}' (id {raw.get('id')}) — the client's role could "
                     f"not be read, so whether it holds admin privileges was not determined. IP "
                     f"allowlist present: {bool(raw.get('ip_allowlist'))}."),
        remediation="Grant the scanning token permission to read API client roles and re-scan so "
                    "privilege exposure can be evaluated.",
        detail=f"api_client_id={raw.get('id')} role_readable=False",
        assessable=False,
        assessment_reason="API client role not readable",
        source_ref={"api": "GET /api/api_clients"},
    )]


# ══ WORKATO.APICLIENT.ADMIN_NO_IP_ALLOWLIST ═══════════════════════════════
@detector(kinds=["workato_api_client"], rule_id="WORKATO.APICLIENT.ADMIN_NO_IP_ALLOWLIST",
          severity="high",
          title="Workato admin API client has no IP allowlist")
def admin_no_ip_allowlist(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("role_readable") or not raw.get("is_admin"):
        return []
    if raw.get("ip_allowlist"):
        return []
    return [Hit(
        observation=(
            f"API client '{raw.get('name')}' (id {raw.get('id')}) has admin role "
            f"{raw.get('role_name')!r} and an empty IP allowlist, so its API token administers the "
            f"whole workspace from any source address."),
        remediation=("Add an IP allowlist restricting this client to the known caller ranges, and "
                     "reduce its role to the least privilege its integration needs. An admin token "
                     "with no IP restriction is a workspace takeover if it leaks."),
        detail=f"role={raw.get('role_name')} ip_allowlist=[]",
        source_ref={"api": "GET /api/api_clients", "config_key": "role_name, ip_allowlist"},
    )]


# ══ WORKATO.APICLIENT.NO_IP_ALLOWLIST ═════════════════════════════════════
@detector(kinds=["workato_api_client"], rule_id="WORKATO.APICLIENT.NO_IP_ALLOWLIST",
          severity="medium",
          title="Workato API client has no IP allowlist")
def no_ip_allowlist(r, ctx) -> list:
    raw = r.raw or {}
    # Admin clients are the higher-severity ADMIN_NO_IP_ALLOWLIST finding; do not double-report them.
    if raw.get("is_admin"):
        return []
    if raw.get("ip_allowlist"):
        return []
    return [Hit(
        observation=(
            f"API client '{raw.get('name')}' (id {raw.get('id')}, role {raw.get('role_name')!r}) has "
            f"an empty IP allowlist, so its API token is usable from any source address."),
        remediation=("Add an IP allowlist restricting this client to its known caller ranges. Even a "
                     "scoped token is safer bound to expected source IPs."),
        detail=f"role={raw.get('role_name')} ip_allowlist=[]",
        source_ref={"api": "GET /api/api_clients", "config_key": "ip_allowlist"},
    )]


# ══ WORKATO.ENDPOINT.NO_ACCESS_PROFILE ════════════════════════════════════
@detector(kinds=["workato_api_endpoint"], rule_id="WORKATO.ENDPOINT.NO_ACCESS_PROFILE",
          severity="high",
          title="Workato API endpoint has no access profile")
def endpoint_no_access_profile(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("active"):
        # An inactive endpoint is not served, so it cannot be called — real but inert.
        return []
    if raw.get("access_profile_ids"):
        return []
    return [Hit(
        observation=(
            f"API endpoint '{raw.get('name')}' (id {raw.get('id')}, path {raw.get('path')!r}) is "
            f"active with an empty access_profile list, so it is published on the API Platform with "
            f"no access profile (API key) gating it — callers need no credential."),
        remediation=("Attach an access profile (API key / JWT / OAuth) to the collection this "
                     "endpoint belongs to, so requests must present a credential. An active endpoint "
                     "with no access profile is an unauthenticated API."),
        detail=f"active=True access_profile_ids=[] path={raw.get('path')}",
        source_ref={"api": "GET /api/api_endpoints", "config_key": "access_profile_ids"},
    )]


# ══ WORKATO.CONNECTION.SHARED_ORG_WIDE ════════════════════════════════════
@detector(kinds=["workato_connection"], rule_id="WORKATO.CONNECTION.SHARED_ORG_WIDE",
          severity="medium",
          title="Workato connection is shared workspace-wide")
def connection_shared(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("shared_org_wide"):
        return []
    return [Hit(
        observation=(
            f"Connection '{raw.get('name')}' (id {raw.get('id')}, provider {raw.get('provider')}) is "
            f"shared workspace-wide (no owning folder), so every recipe and collaborator in the "
            f"workspace can use this credential against {raw.get('provider')}."),
        remediation=("Move the connection into a folder scoped to the recipes that need it, so its "
                     "reach matches its purpose rather than the whole workspace."),
        detail=f"shared_org_wide=True folder_id={raw.get('folder_id')}",
        source_ref={"api": "GET /api/connections", "config_key": "folder_id"},
    )]


# ══ WORKATO.CONNECTION.UNAUTHORIZED ═══════════════════════════════════════
@detector(kinds=["workato_connection"], rule_id="WORKATO.CONNECTION.UNAUTHORIZED", severity="low",
          title="Workato connection is not in an authorized state")
def connection_unauthorized(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("authorized") is not False:          # True or None (unknown) → not this rule
        return []
    return [Hit(
        observation=(f"Connection '{raw.get('name')}' (id {raw.get('id')}, provider "
                     f"{raw.get('provider')}) is in an unauthorized state, indicating an expired or "
                     f"revoked credential still present in the workspace."),
        remediation=("Re-authorize the connection if it is still needed, or delete it. A dormant "
                     "unauthorized connection is stale credential configuration that clutters access "
                     "review."),
        detail=f"authorized=False provider={raw.get('provider')}",
        source_ref={"api": "GET /api/connections", "config_key": "authorization_status"},
    )]
