"""Apache Solr rulepack — config-time posture over what connect/solr.py collected.

Every rule reads REAL evidence (the presence/absence of an authentication or authorization
plugin in security.json, the status of an unauthenticated admin request, the reported Solr
version) and cites it. Rules run on the DISTINCT `solr_server` kind, so they never collide with
the other packs.

The version→CVE rule maps ONLY the two ranges the Apache advisory states for CVE-2024-45216
(verified against the ASF advisory / NVD): affected 5.3.0 ≤ v < 8.11.4 and 9.0.0 ≤ v < 9.7.0,
fixed in 8.11.4 and 9.7.0. A version outside those mapped ranges — including a series this
scanner has no floor for, or an unparseable string — is returned as not-assessable, never a
silent pass and never a fabricated failure.
"""
from ..connect.solr import _parse_version
from ..contracts import Hit
from ..registry import detector


def _authbypass_vulnerable(version):
    """CVE-2024-45216 (PKIAuthenticationPlugin auth bypass, CVSS 9.8). True/False when the
    version falls in/out of the advisory's stated ranges; None when the string is unparseable."""
    parsed = _parse_version(version)
    if parsed is None:
        return None
    # affected: [5.3.0, 8.11.4) and [9.0.0, 9.7.0)
    if (5, 3, 0) <= parsed < (8, 11, 4):
        return True
    if (9, 0, 0) <= parsed < (9, 7, 0):
        return True
    return False


@detector(kinds=["solr_server"], rule_id="SOLR.AUTH.NO_PLUGIN", severity="critical",
          title="No authentication plugin is configured")
def no_authentication_plugin(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("authentication_readable"):
        return [Hit(
            observation=("the Solr authentication config (GET /solr/admin/authentication) could "
                         "not be read, so whether an authentication plugin is configured was not "
                         "determined"),
            remediation="Grant the scan credential read access to the security config endpoints.",
            detail="authentication_readable=False",
            assessable=False,
            assessment_reason="GET /solr/admin/authentication was not readable",
            source_ref={"api": "GET /solr/admin/authentication"},
        )]
    if raw.get("auth_plugin_class"):
        return []
    return [Hit(
        observation=("Solr's security.json has no authentication `class` — no authentication "
                     "plugin is configured, so every admin, collection, and Config API request "
                     "is served unauthenticated"),
        remediation=("Configure an authentication plugin in security.json (BasicAuthPlugin, or "
                     "JWTAuthPlugin for SSO) with `blockUnknown: true`, then pair it with an "
                     "authorization plugin. Unauthenticated Solr allows config/configset changes "
                     "that lead to remote code execution."),
        detail="auth_plugin_class=None",
        source_ref={"api": "GET /solr/admin/authentication", "field": "authentication.class"},
    )]


@detector(kinds=["solr_server"], rule_id="SOLR.AUTHZ.NO_PLUGIN", severity="high",
          title="No authorization plugin is configured")
def no_authorization_plugin(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("authorization_readable"):
        return [Hit(
            observation=("the Solr authorization config (GET /solr/admin/authorization) could "
                         "not be read, so whether an authorization plugin is configured was not "
                         "determined"),
            remediation="Grant the scan credential read access to the security config endpoints.",
            detail="authorization_readable=False",
            assessable=False,
            assessment_reason="GET /solr/admin/authorization was not readable",
            source_ref={"api": "GET /solr/admin/authorization"},
        )]
    if raw.get("authz_plugin_class"):
        return []
    return [Hit(
        observation=("Solr's security.json has no authorization `class` — no authorization "
                     "plugin is configured, so any authenticated user has unrestricted access to "
                     "every collection and admin action (no role or permission checks apply)"),
        remediation=("Configure the RuleBasedAuthorizationPlugin in security.json with explicit "
                     "user-role mappings and least-privilege permissions, so authenticated "
                     "identities are still bounded to what they need."),
        detail="authz_plugin_class=None",
        source_ref={"api": "GET /solr/admin/authorization", "field": "authorization.class"},
    )]


@detector(kinds=["solr_server"], rule_id="SOLR.ADMIN.UNAUTHENTICATED", severity="high",
          title="Admin API answers unauthenticated requests")
def admin_unauthenticated(r, ctx) -> list:
    raw = r.raw or {}
    status = raw.get("anon_admin_status")
    if status == 200:
        return [Hit(
            observation=("an unauthenticated GET /solr/admin/info/system returned HTTP 200 — the "
                         "Solr Admin API (and the UI it backs) answers requests with no "
                         "credential, exposing system, JVM, and cluster information and the admin "
                         "action surface"),
            remediation=("Put Solr behind an authentication plugin with `blockUnknown: true` and "
                         "restrict network access to the admin port; the Admin UI is a thin "
                         "client over these same endpoints, so securing the API secures the UI."),
            detail=f"anon_admin_status={status}",
            source_ref={"probe": "unauthenticated GET /solr/admin/info/system"},
        )]
    if status in (401, 403):
        return []
    return [Hit(
        observation=(f"the unauthenticated admin probe did not complete (status={status}), so "
                     f"whether the Admin API answers anonymous requests was not determined"),
        remediation="Confirm the Solr admin endpoint is reachable from the engine and re-run.",
        detail=f"anon_admin_status={status}",
        assessable=False,
        assessment_reason="the anonymous admin probe returned no HTTP status",
        source_ref={"probe": "unauthenticated GET /solr/admin/info/system"},
    )]


@detector(kinds=["solr_server"], rule_id="SOLR.AUTH.BLOCK_UNKNOWN_FALSE", severity="high",
          title="Authentication plugin does not block unknown users")
def block_unknown_false(r, ctx) -> list:
    raw = r.raw or {}
    # Only relevant when a plugin IS configured; with no plugin, SOLR.AUTH.NO_PLUGIN is the finding.
    if not raw.get("auth_plugin_class"):
        return []
    if raw.get("block_unknown") is not False:
        return []
    return [Hit(
        observation=(f"the authentication plugin '{raw.get('auth_plugin_class')}' has "
                     f"`blockUnknown: false` — unauthenticated requests are passed through "
                     f"instead of rejected, so any endpoint not explicitly protected by an "
                     f"authorization rule is reachable with no credential"),
        remediation=("Set `blockUnknown: true` in the authentication section of security.json so "
                     "every request must authenticate, then use the authorization plugin to "
                     "grant access rather than relying on selective protection."),
        detail=f"auth_plugin_class={raw.get('auth_plugin_class')} block_unknown=False",
        source_ref={"api": "GET /solr/admin/authentication", "field": "authentication.blockUnknown"},
    )]


@detector(kinds=["solr_server"], rule_id="SOLR.NETWORK.NO_TLS", severity="medium",
          title="Solr is reached over plaintext HTTP")
def no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("scheme") != "http":
        return []
    return [Hit(
        observation=("Solr was reached over plaintext http:// — admin credentials (Basic auth) "
                     "and every query and result cross the network unencrypted"),
        remediation=("Enable TLS on Solr (SOLR_SSL_ENABLED=true with a keystore) and connect over "
                     "https://. Rotate any Basic-auth credentials sent over the plaintext hop."),
        detail="scheme=http",
        source_ref={"probe": "connection scheme"},
    )]


@detector(kinds=["solr_server"], rule_id="SOLR.VERSION.AUTH_BYPASS_CVE", severity="critical",
          title="Solr version is affected by the PKIAuthenticationPlugin auth bypass (CVE-2024-45216)")
def version_auth_bypass(r, ctx) -> list:
    raw = r.raw or {}
    version = raw.get("version")
    vulnerable = _authbypass_vulnerable(version)
    if vulnerable is False:
        return []
    if vulnerable is None:
        return [Hit(
            observation=(f"Solr reports version '{version}', which this scanner cannot place "
                         f"against the CVE-2024-45216 advisory ranges (5.3.0–8.11.4, 9.0.0–9.7.0), "
                         f"so exposure to the PKIAuthenticationPlugin auth bypass was not "
                         f"determined"),
            remediation=("Confirm the running version against the Apache advisory for "
                         "CVE-2024-45216 and upgrade to 8.11.4 or 9.7.0 (or later) if within the "
                         "affected range."),
            detail=f"version={version}",
            assessable=False,
            assessment_reason="version string is unparseable or outside the mapped CVE ranges",
            source_ref={"api": "GET /solr/admin/info/system", "cve": "CVE-2024-45216"},
        )]
    return [Hit(
        observation=(f"Solr version {version} is in the range affected by CVE-2024-45216 "
                     f"(CVSS 9.8) — a fake trailing path segment makes the PKIAuthenticationPlugin "
                     f"skip authentication, letting an unauthenticated attacker reach protected "
                     f"admin API endpoints"),
        remediation=("Upgrade to Solr 8.11.4 or 9.7.0 (or later), which fix the "
                     "PKIAuthenticationPlugin path-normalization flaw. PKIAuthenticationPlugin is "
                     "enabled by default, so the bypass applies even to inter-node auth."),
        detail=f"version={version}",
        source_ref={"api": "GET /solr/admin/info/system", "cve": "CVE-2024-45216"},
    )]
