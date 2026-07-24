"""n8n rulepack — config-time posture over what connect/n8n.py already collected.

Highest-signal facts, in order: the two n8n RCE CVEs read off the instance version, an unclaimed
instance (no owner account), and unauthenticated webhook triggers — the last being the exact class
the Ni8mare CVE weaponizes. Every rule reads a fact the connector recorded; none re-queries the
instance. Rules run on the DISTINCT n8n_* kinds so they never collide with another pack.

Both CVE ranges were verified against the GitHub Security Advisories (GHSA-v98v-ff95-f3cp and
GHSA-v4pr-fm98-w9pg) before being anchored here — the affected/fixed versions below are the
advisories', not a guess.
"""
from ..contracts import Hit
from ..registry import detector


def _parse_version(v):
    """'1.120.4' → (1, 120, 4); None when unparseable (→ the rule answers not-assessable, never a
    clean pass). Pre-release / build suffixes are dropped before the numeric split."""
    if not isinstance(v, str):
        return None
    core = v.strip().lstrip("vV").split("-")[0].split("+")[0]
    parts = core.split(".")
    try:
        nums = [int(p) for p in parts[:3]]
    except (ValueError, TypeError):
        return None
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def _in_range(v, low, high) -> bool:
    """low (inclusive) <= v < high (exclusive), on parsed 3-tuples."""
    return low <= v < high


# ══ N8N.VERSION.CVE_2026_21858_WEBHOOK_RCE ════════════════════════════════
@detector(kinds=["n8n_instance"], rule_id="N8N.VERSION.CVE_2026_21858_WEBHOOK_RCE",
          severity="critical",
          title="n8n version affected by the Ni8mare unauthenticated webhook RCE (CVE-2026-21858)")
def cve_2026_21858(r, ctx) -> list:
    version = (r.raw or {}).get("version")
    v = _parse_version(version)
    if v is None:
        return [Hit(
            observation=(f"n8n instance reports version {version!r} via /rest/settings.versionCli, "
                         f"which this scanner could not parse to a numeric version, so exposure to "
                         f"CVE-2026-21858 (Ni8mare) was not determined"),
            remediation="Confirm the running version and ensure it is at or above the fixed release "
                        "1.121.0 for CVE-2026-21858.",
            detail=f"version={version}",
            assessable=False,
            assessment_reason="version string not parseable to a numeric n8n release",
            source_ref={"api": "GET /rest/settings", "cve": "CVE-2026-21858"},
        )]
    # Verified affected range (GHSA-v4pr-fm98-w9pg): >= 1.65.0 and < 1.121.0. Fixed in 1.121.0.
    if not _in_range(v, (1, 65, 0), (1, 121, 0)):
        return []
    return [Hit(
        observation=(
            f"n8n reports version {version} (via /rest/settings.versionCli), which is in the "
            f"CVE-2026-21858 affected range >=1.65.0,<1.121.0. The n8n advisory (GHSA-v4pr-fm98-w9pg, "
            f"CVSS 10.0) scopes this as UNAUTHENTICATED arbitrary file access via improper webhook "
            f"request handling: a request that misstates its Content-Type lets parseBody() overwrite "
            f"req.body.files with attacker-controlled data. Security researchers ('Ni8mare') chained "
            f"that read primitive to session forgery and full unauthenticated remote code execution / "
            f"instance takeover. A form/webhook trigger workflow is the precondition."),
        remediation=("Upgrade to n8n 1.121.0 or later — the single fixed release for CVE-2026-21858. "
                     "Until patched, put the webhook endpoints behind an authenticating reverse proxy "
                     "and disable any internet-exposed Form Trigger workflows."),
        detail=f"version={version} affected_range=[1.65.0,1.121.0) fixed=1.121.0",
        source_ref={"api": "GET /rest/settings.versionCli", "cve": "CVE-2026-21858",
                    "advisory": "GHSA-v4pr-fm98-w9pg"},
    )]


# ══ N8N.VERSION.CVE_2025_68613_EXPRESSION_RCE ═════════════════════════════
_68613_RANGES = (((0, 211, 0), (1, 120, 4)), ((1, 121, 0), (1, 121, 1)))


@detector(kinds=["n8n_instance"], rule_id="N8N.VERSION.CVE_2025_68613_EXPRESSION_RCE",
          severity="high",
          title="n8n version affected by the authenticated expression-injection RCE (CVE-2025-68613)")
def cve_2025_68613(r, ctx) -> list:
    version = (r.raw or {}).get("version")
    v = _parse_version(version)
    if v is None:
        return [Hit(
            observation=(f"n8n instance reports version {version!r} via /rest/settings.versionCli, "
                         f"which this scanner could not parse, so exposure to CVE-2025-68613 was not "
                         f"determined"),
            remediation="Confirm the running version and patch to 1.120.4, 1.121.1, or 1.122.0+ "
                        "for CVE-2025-68613.",
            detail=f"version={version}",
            assessable=False,
            assessment_reason="version string not parseable to a numeric n8n release",
            source_ref={"api": "GET /rest/settings", "cve": "CVE-2025-68613"},
        )]
    # Verified affected ranges (GHSA-v98v-ff95-f3cp): >=0.211.0,<1.120.4 and >=1.121.0,<1.121.1.
    # Fixed in 1.120.4, 1.121.1 and 1.122.0.
    if not any(_in_range(v, low, high) for low, high in _68613_RANGES):
        return []
    return [Hit(
        observation=(
            f"n8n reports version {version} (via /rest/settings.versionCli), which is in the "
            f"CVE-2025-68613 affected ranges >=0.211.0,<1.120.4 or >=1.121.0,<1.121.1. Per the "
            f"advisory (GHSA-v98v-ff95-f3cp, CVSS 9.9, PR:L) an AUTHENTICATED user with only "
            f"workflow-create/edit rights can supply an expression that is evaluated outside the "
            f"sandbox, achieving remote code execution on the host. Exploitation requires a valid "
            f"low-privilege login (unlike CVE-2026-21858, which needs none)."),
        remediation=("Upgrade to a fixed n8n release: 1.120.4, 1.121.1, or 1.122.0 or later. Until "
                     "patched, restrict who can create or edit workflows and review existing "
                     "workflows for injected expressions."),
        detail=f"version={version} fixed=1.120.4/1.121.1/1.122.0",
        source_ref={"api": "GET /rest/settings.versionCli", "cve": "CVE-2025-68613",
                    "advisory": "GHSA-v98v-ff95-f3cp"},
    )]


# ══ N8N.INSTANCE.OWNER_NOT_CONFIGURED ═════════════════════════════════════
@detector(kinds=["n8n_instance"], rule_id="N8N.INSTANCE.OWNER_NOT_CONFIGURED", severity="critical",
          title="n8n instance has no owner account (setup not completed)")
def owner_not_configured(r, ctx) -> list:
    raw = r.raw or {}
    pending = raw.get("owner_setup_pending")
    if pending is not True:
        # False (owner exists) or None (probe did not return the flag) — do not assert.
        return []
    remote = raw.get("origin") == "remote"
    return [Hit(
        observation=(
            f"Unauthenticated GET {raw.get('base_url')}/rest/settings returned "
            f".userManagement.showSetupOnFirstLoad=true, so no owner account has been created on "
            f"this n8n instance. The first visitor to /setup can claim the owner (full admin) "
            f"account. Probe origin: {raw.get('origin')}."),
        severity="critical" if remote else "high",
        remediation=("Complete the owner setup immediately (create the owner account at /setup) and "
                     "put the instance behind authentication. An unclaimed n8n instance is a "
                     "one-request full takeover for anyone who can reach it."),
        detail=f"showSetupOnFirstLoad=true origin={raw.get('origin')}",
        source_ref={"api": "GET /rest/settings (unauthenticated)",
                    "config_key": "userManagement.showSetupOnFirstLoad"},
    )]


# ══ N8N.INSTANCE.OUTDATED ═════════════════════════════════════════════════
@detector(kinds=["n8n_instance"], rule_id="N8N.INSTANCE.OUTDATED", severity="medium",
          title="n8n instance is behind the latest release with security fixes pending")
def instance_outdated(r, ctx) -> list:
    outdated = ((r.raw or {}).get("audit") or {}).get("outdated")
    if not outdated:
        return []                                   # audit did not flag it, or was unreadable
    nexts = outdated.get("next_versions") or []
    security = [nv for nv in nexts
                if isinstance(nv, dict) and (nv.get("hasSecurityFix") or nv.get("hasSecurityIssue"))]
    if not nexts:
        return []
    return [Hit(
        observation=(
            f"n8n's own security audit (POST /api/v1/audit, Instance Risk Report) reports this "
            f"instance at version {outdated.get('current_version')!r} with {len(nexts)} newer "
            f"release(s) available, {len(security)} of which n8n flags as carrying security fixes."),
        severity="high" if security else "medium",
        remediation=("Upgrade to the latest n8n release. n8n's audit flags pending versions with "
                     "security fixes; treat those as the priority."),
        detail=f"current={outdated.get('current_version')} pending={len(nexts)} security={len(security)}",
        source_ref={"api": "POST /api/v1/audit", "section": "Instance Risk Report / Outdated"},
    )]


# ══ N8N.INSTANCE.ENCRYPTION_KEY_UNVERIFIABLE ══════════════════════════════
@detector(kinds=["n8n_instance"], rule_id="N8N.INSTANCE.ENCRYPTION_KEY_UNVERIFIABLE",
          severity="info",
          title="n8n credential encryption-key management not observable via the API")
def encryption_key_unverifiable(r, ctx) -> list:
    # Fire only when there are stored credentials to protect — no credentials, no coverage gap.
    if not ctx.of_kind("n8n_credential"):
        return []
    n = len(ctx.of_kind("n8n_credential"))
    return [Hit(
        observation=(
            f"This instance stores {n} credential(s). n8n always encrypts credential data at rest "
            f"with N8N_ENCRYPTION_KEY, but whether that key is supplied by an external secrets "
            f"manager (recommended) or was auto-generated and written to the host filesystem "
            f"(~/.n8n/config) is NOT exposed by the public API, so this control could not be "
            f"assessed."),
        remediation=("Out of band, confirm N8N_ENCRYPTION_KEY is set to a value from a secrets "
                     "manager rather than left to auto-generate on disk — an on-disk key means a "
                     "leaked config file or database backup is decryptable."),
        detail=f"stored_credentials={n}",
        assessable=False,
        assessment_reason="encryption-key provenance is not exposed by the n8n API",
        source_ref={"config_key": "N8N_ENCRYPTION_KEY"},
    )]


# ══ N8N.WORKFLOW.UNAUTHENTICATED_WEBHOOK ══════════════════════════════════
@detector(kinds=["n8n_workflow"], rule_id="N8N.WORKFLOW.UNAUTHENTICATED_WEBHOOK", severity="high",
          title="n8n workflow exposes an unauthenticated webhook trigger")
def unauthenticated_webhook(r, ctx) -> list:
    raw = r.raw or {}
    unauth = [t for t in (raw.get("webhook_triggers") or [])
              if t.get("authentication") in ("none", "", None)]
    if not unauth:
        return []
    active = raw.get("active")
    exec_nodes = raw.get("execution_node_types") or []
    # An inactive workflow's webhook is not registered, so it cannot be triggered — real but inert.
    if not active:
        severity = "info"
    elif exec_nodes:
        severity = "critical"                       # reaches command/code execution from anonymous input
    else:
        severity = "high"
    paths = [t.get("path") or t.get("webhook_id") or t.get("node") for t in unauth]
    return [Hit(
        observation=(
            f"Workflow '{raw.get('name')}' (id {raw.get('id')}, active={active}) has "
            f"{len(unauth)} webhook trigger node(s) with authentication='none' "
            f"(nodes/paths {paths!r}), so any client that can reach the webhook URL can trigger it "
            f"without a credential."
            + (f" The workflow also contains execution-capable node(s) {exec_nodes!r} reachable "
               f"from that anonymous entry point." if exec_nodes else "")),
        severity=severity,
        remediation=("Set the webhook node's Authentication to Header Auth, Basic Auth, or JWT Auth "
                     "(with a credential), or front the webhook with an authenticating proxy. Do not "
                     "rely on the random URL path as a secret — it leaks in exports and logs."),
        detail=f"active={active} unauth_webhooks={len(unauth)} execution_nodes={exec_nodes}",
        source_ref={"api": "GET /api/v1/workflows",
                    "config_key": "nodes[].parameters.authentication"},
    )]


# ══ N8N.CREDENTIAL.REACHABLE_VIA_UNAUTH_WEBHOOK ═══════════════════════════
@detector(kinds=["n8n_credential"], rule_id="N8N.CREDENTIAL.REACHABLE_VIA_UNAUTH_WEBHOOK",
          severity="high",
          title="n8n stored credential is reachable from an unauthenticated webhook workflow")
def credential_reachable_unauth(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("used_by_unauthenticated_webhook_workflow"):
        return []
    return [Hit(
        observation=(
            f"Credential '{raw.get('name')}' (id {raw.get('id')}, type {raw.get('credential_type')}) "
            f"is referenced by a workflow that is active AND exposes an unauthenticated webhook "
            f"trigger, so an anonymous caller can drive n8n to use this credential against its "
            f"upstream system. Used by {len(raw.get('used_by_workflows') or [])} workflow(s)."),
        remediation=("Authenticate the webhook trigger of the workflow(s) using this credential, or "
                     "move the credential's actions behind an authenticated step. An anonymous "
                     "trigger plus a stored credential is a confused-deputy path into the upstream."),
        detail=f"credential_type={raw.get('credential_type')} "
               f"used_by={raw.get('used_by_workflows')}",
        source_ref={"api": "GET /api/v1/workflows", "config_key": "nodes[].credentials"},
    )]


# ══ N8N.CREDENTIAL.SHARED_ACROSS_WORKFLOWS ════════════════════════════════
_SHARE_THRESHOLD = 3


@detector(kinds=["n8n_credential"], rule_id="N8N.CREDENTIAL.SHARED_ACROSS_WORKFLOWS",
          severity="low",
          title="n8n credential is reused across many workflows")
def credential_shared(r, ctx) -> list:
    raw = r.raw or {}
    used_by = raw.get("used_by_workflows") or []
    if len(used_by) < _SHARE_THRESHOLD:
        return []
    return [Hit(
        observation=(
            f"Credential '{raw.get('name')}' (id {raw.get('id')}, type {raw.get('credential_type')}) "
            f"is referenced by {len(used_by)} workflows, so its blast radius spans all of them: a "
            f"compromise of any one, or of the credential itself, exposes every workflow that shares "
            f"it."),
        remediation=("Review whether every workflow genuinely needs this credential; split into "
                     "narrower-scoped credentials where possible so no single secret gates this much "
                     "of the automation surface."),
        detail=f"used_by_count={len(used_by)} threshold={_SHARE_THRESHOLD}",
        source_ref={"api": "GET /api/v1/workflows", "config_key": "nodes[].credentials"},
    )]


# ══ N8N.USER.MFA_DISABLED ═════════════════════════════════════════════════
@detector(kinds=["n8n_user"], rule_id="N8N.USER.MFA_DISABLED", severity="medium",
          title="n8n user does not have two-factor authentication enabled")
def user_mfa_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("is_pending"):
        return []                                   # not yet an active login — covered by PENDING_INVITE
    mfa = raw.get("mfa_enabled")
    if mfa is True:
        return []
    if mfa is None:
        return [Hit(
            observation=(f"n8n user '{raw.get('email')}' (role {raw.get('role')!r}) — the public API "
                         f"response for this instance did not include an MFA/2FA field, so whether "
                         f"two-factor is enabled could not be determined"),
            remediation="Confirm 2FA status in the n8n UI (Settings > Users) and enforce 2FA for "
                        "owner and admin accounts.",
            detail=f"role={raw.get('role')} mfa_enabled=absent",
            assessable=False,
            assessment_reason="MFA status not exposed by the public API for this n8n version",
            source_ref={"api": "GET /api/v1/users"},
        )]
    # mfa is False
    return [Hit(
        observation=(f"n8n user '{raw.get('email')}' (role {raw.get('role')!r}) has "
                     f"mfaEnabled=false — the account is protected by a password alone."),
        severity="high" if raw.get("is_admin") else "medium",
        remediation=("Enable two-factor authentication for this account. Enforce 2FA for all owner "
                     "and admin users — an admin without 2FA is a single phished password from full "
                     "control of every workflow and credential."),
        detail=f"role={raw.get('role')} is_admin={raw.get('is_admin')} mfa_enabled=False",
        source_ref={"api": "GET /api/v1/users", "config_key": "mfaEnabled"},
    )]


# ══ N8N.USER.PENDING_INVITE ═══════════════════════════════════════════════
@detector(kinds=["n8n_user"], rule_id="N8N.USER.PENDING_INVITE", severity="low",
          title="n8n user invitation is still pending")
def user_pending_invite(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("is_pending"):
        return []
    return [Hit(
        observation=(f"n8n user '{raw.get('email')}' (role {raw.get('role')!r}) has isPending=true — "
                     f"an invitation was issued but never accepted, leaving a dormant account with a "
                     f"live invite link."),
        remediation=("Complete or revoke the invitation. Stale pending invites are accounts with an "
                     "outstanding activation link that never lands in an access review."),
        detail=f"role={raw.get('role')} is_pending=True",
        source_ref={"api": "GET /api/v1/users", "config_key": "isPending"},
    )]
