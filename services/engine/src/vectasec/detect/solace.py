"""Solace PubSub+ rulepack — config-time posture over what connect/solace.py collected.

Every rule reads REAL evidence: the msgVpn authentication/transport booleans and the ACL-profile
default actions as SEMP returned them. None guesses from names. Rules run on the DISTINCT
solace_broker / solace_vpn / solace_client_username kinds, so they never collide with the
Kafka/Kong/RabbitMQ/Redis packs.

A finding is fingerprinted on (tenant, rule_id, ext_id), so each detector returns at most ONE Hit
per resource; rules that can match many ACL profiles aggregate into a single Hit that lists every
match.

House severities:
  critical  a Message VPN with basic auth set to 'none' (password accepted but never checked)
  high      built-in 'default' username enabled, ACL default-allow, plaintext messaging, open ACL
  medium    SEMP over plaintext, basic auth with no client-cert option, TLS downgrade, endpoint override
"""
from ..contracts import Hit
from ..registry import detector


def _true(v) -> bool:
    return v is True or str(v).strip().lower() == "true"


def _false(v) -> bool:
    return v is False or str(v).strip().lower() == "false"


# ── Broker / SEMP management plane ──────────────────────────────────────────────
@detector(kinds=["solace_broker"], rule_id="SOLACE.MGMT.SEMP_PLAINTEXT", severity="medium",
          title="SEMP management API is served over plaintext HTTP")
def semp_plaintext(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("semp_plaintext") or raw.get("semp_tls_verified"):
        return []
    return [Hit(
        observation=(f"the SEMP management API was reached at {raw.get('semp_url')!r} over "
                     f"plaintext HTTP — SEMP authenticates with HTTP Basic, so the management "
                     f"admin credential is sent base64-encoded and is sniffable on the wire"),
        remediation=("Serve SEMP over TLS (the 1943 secure SEMP port) with a broker certificate, "
                     "and disable or firewall the plaintext SEMP port. Management credentials over "
                     "plaintext are recoverable by anyone on-path."),
        detail=f"semp_scheme={raw.get('semp_scheme')}",
        source_ref={"api": "/SEMP/v2/config"},
    )]


# ── Message VPN authentication ──────────────────────────────────────────────────
@detector(kinds=["solace_vpn"], rule_id="SOLACE.VPN.BASIC_AUTH_TYPE_NONE", severity="critical",
          title="Message VPN basic authentication is set to 'none'")
def vpn_basic_auth_none(r, ctx) -> list:
    raw = r.raw or {}
    if not _true(raw.get("authentication_basic_enabled")):
        return []
    if str(raw.get("authentication_basic_type") or "").lower() != "none":
        return []
    return [Hit(
        observation=(f"Message VPN {raw.get('msg_vpn_name')!r} has authenticationBasicEnabled=true "
                     f"with authenticationBasicType=\"none\" — basic authentication accepts a "
                     f"client's username with NO password validation, so any client can connect as "
                     f"any username the ACLs permit"),
        remediation=("Set authenticationBasicType to `internal` (broker-managed passwords), `ldap` "
                     "or `radius` so credentials are actually verified, or disable basic auth and "
                     "require client certificates. 'none' authenticates by username string alone."),
        detail="authenticationBasicType=none",
        source_ref={"api": "/SEMP/v2/config/msgVpns", "attribute": "authenticationBasicType"},
    )]


@detector(kinds=["solace_vpn"], rule_id="SOLACE.VPN.BASIC_AUTH_NO_CLIENT_CERT", severity="medium",
          title="Message VPN relies on password auth with no client-certificate option")
def vpn_basic_auth_no_client_cert(r, ctx) -> list:
    raw = r.raw or {}
    basic_type = str(raw.get("authentication_basic_type") or "").lower()
    if not _true(raw.get("authentication_basic_enabled")) or basic_type == "none":
        return []   # 'none' is owned by BASIC_AUTH_TYPE_NONE; disabled basic is not this finding
    if _true(raw.get("authentication_client_cert_enabled")):
        return []
    return [Hit(
        observation=(f"Message VPN {raw.get('msg_vpn_name')!r} has authenticationBasicEnabled=true "
                     f"(type={basic_type!r}) and authenticationClientCertEnabled=false — clients "
                     f"authenticate with a password only; there is no client-certificate option, "
                     f"so credential theft or reuse is the whole authentication story"),
        remediation=("Enable client-certificate authentication "
                     "(authenticationClientCertEnabled=true) with a trusted CA so services can "
                     "present certificates instead of shared passwords, especially for "
                     "machine-to-machine connections."),
        detail=f"authentication_basic_type={basic_type} client_cert_enabled="
               f"{raw.get('authentication_client_cert_enabled')}",
        source_ref={"api": "/SEMP/v2/config/msgVpns",
                    "attribute": "authenticationClientCertEnabled"},
    )]


# ── Message VPN transport ────────────────────────────────────────────────────────
@detector(kinds=["solace_vpn"], rule_id="SOLACE.VPN.PLAINTEXT_MESSAGING", severity="high",
          title="Message VPN accepts plaintext SMF messaging with no TLS")
def vpn_plaintext_messaging(r, ctx) -> list:
    raw = r.raw or {}
    if not _true(raw.get("service_smf_plain_text_enabled")):
        return []
    if _true(raw.get("service_smf_tls_enabled")):
        return []   # a TLS service is available alongside; PLAINTEXT_MESSAGING wants no-TLS
    return [Hit(
        observation=(f"Message VPN {raw.get('msg_vpn_name')!r} has serviceSmfPlainTextEnabled=true "
                     f"and serviceSmfTlsEnabled=false — SMF clients connect in plaintext with no "
                     f"TLS service offered, so basic-auth credentials and every message payload "
                     f"cross the network unencrypted"),
        remediation=("Enable the TLS SMF service (serviceSmfTlsEnabled=true) with a broker "
                     "certificate and disable the plaintext SMF service "
                     "(serviceSmfPlainTextEnabled=false), or restrict plaintext to a trusted "
                     "internal segment only."),
        detail="service_smf_plain_text_enabled=true service_smf_tls_enabled=false",
        source_ref={"api": "/SEMP/v2/config/msgVpns", "attribute": "serviceSmfTlsEnabled"},
    )]


@detector(kinds=["solace_vpn"], rule_id="SOLACE.VPN.TLS_DOWNGRADE_ALLOWED", severity="medium",
          title="Message VPN allows TLS connections to downgrade to plaintext")
def vpn_tls_downgrade_allowed(r, ctx) -> list:
    raw = r.raw or {}
    if not _true(raw.get("tls_allow_downgrade_to_plain_text_enabled")):
        return []
    return [Hit(
        observation=(f"Message VPN {raw.get('msg_vpn_name')!r} has "
                     f"tlsAllowDowngradeToPlainTextEnabled=true — a client that negotiated a TLS "
                     f"connection can be downgraded to plaintext mid-session, defeating the "
                     f"confidentiality TLS was meant to provide and enabling on-path downgrade "
                     f"attacks"),
        remediation=("Set tlsAllowDowngradeToPlainTextEnabled=false so TLS sessions stay "
                     "encrypted end to end. The downgrade option exists only for legacy "
                     "compression/edge cases and should not be on for normal messaging."),
        detail="tls_allow_downgrade_to_plain_text_enabled=true",
        source_ref={"api": "/SEMP/v2/config/msgVpns",
                    "attribute": "tlsAllowDowngradeToPlainTextEnabled"},
    )]


# ── ACL profiles (aggregated onto the VPN) ───────────────────────────────────────
@detector(kinds=["solace_vpn"], rule_id="SOLACE.VPN.ACL_DEFAULT_ALLOW", severity="high",
          title="ACL profile uses a default action of 'allow'")
def vpn_acl_default_allow(r, ctx) -> list:
    raw = r.raw or {}
    offenders = []
    for p in raw.get("acl_profiles") or []:
        allow_dims = [dim for dim, val in (
            ("clientConnect", p.get("client_connect_default_action")),
            ("publishTopic", p.get("publish_topic_default_action")),
            ("subscribeTopic", p.get("subscribe_topic_default_action")),
        ) if str(val or "").lower() == "allow"]
        if allow_dims:
            offenders.append((p.get("name"), allow_dims))
    if not offenders:
        return []
    quoted = "; ".join(f"{name!r} allows by default on {dims}" for name, dims in sorted(offenders))
    return [Hit(
        observation=(f"Message VPN {raw.get('msg_vpn_name')!r} has ACL profile(s) with a default "
                     f"action of allow: {quoted} — clients matched to such a profile are permitted "
                     f"to connect/publish/subscribe on anything not explicitly denied, i.e. an "
                     f"allowlist that in fact defaults open"),
        remediation=("Set the default actions to `disallow` (clientConnectDefaultAction, "
                     "publishTopicDefaultAction, subscribeTopicDefaultAction) and add explicit "
                     "allow exceptions for the topics each application actually uses. Default-deny "
                     "is the only ACL posture that fails closed."),
        detail=f"default_allow_profiles={[name for name, _ in offenders]}",
        source_ref={"api": "/SEMP/v2/config/msgVpns/*/aclProfiles"},
    )]


# ── Client usernames ─────────────────────────────────────────────────────────────
@detector(kinds=["solace_client_username"], rule_id="SOLACE.CLIENT_USERNAME.DEFAULT_ENABLED",
          severity="high", title="Built-in 'default' client username is enabled")
def default_username_enabled(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("client_username") != "default" or not _true(raw.get("enabled")):
        return []
    return [Hit(
        observation=(f"the built-in `default` clientUsername in Message VPN "
                     f"{raw.get('msg_vpn_name')!r} is enabled — Solace ships this catch-all "
                     f"username, and while it is enabled any client whose username has no "
                     f"dedicated clientUsername object is authorized through `default` and its ACL "
                     f"profile {raw.get('acl_profile_name')!r}"),
        remediation=("Disable the `default` clientUsername (SEMP: set enabled=false) and create a "
                     "dedicated clientUsername per application with its own password/certificate "
                     "and a scoped ACL profile. The default username is a shared, unmanaged "
                     "identity."),
        detail=f"client_username=default enabled=true acl_profile={raw.get('acl_profile_name')}",
        source_ref={"api": "/SEMP/v2/config/msgVpns/*/clientUsernames"},
    )]


@detector(kinds=["solace_client_username"], rule_id="SOLACE.CLIENT_USERNAME.OPEN_ACL",
          severity="high", title="Enabled client username maps to a default-allow ACL profile")
def username_open_acl(r, ctx) -> list:
    raw = r.raw or {}
    if not _true(raw.get("enabled")):
        return []
    if raw.get("acl_profile_is_default_allow") is not True:
        return []   # None (profile unreadable) or False are not this finding
    return [Hit(
        observation=(f"clientUsername {raw.get('client_username')!r} in Message VPN "
                     f"{raw.get('msg_vpn_name')!r} is enabled and references ACL profile "
                     f"{raw.get('acl_profile_name')!r}, which has a publish or subscribe default "
                     f"action of allow — this identity can publish and/or subscribe to any topic "
                     f"not explicitly denied by that profile"),
        remediation=("Point the username at an ACL profile whose publishTopicDefaultAction and "
                     "subscribeTopicDefaultAction are `disallow`, with explicit allow exceptions "
                     "for the topics this application needs. Default-allow gives the identity "
                     "effectively unrestricted topic access."),
        detail=f"acl_profile={raw.get('acl_profile_name')} default_allow=true",
        source_ref={"api": "/SEMP/v2/config/msgVpns/*/clientUsernames"},
    )]


@detector(kinds=["solace_client_username"], rule_id="SOLACE.CLIENT_USERNAME.ENDPOINT_OVERRIDE",
          severity="medium", title="Client username can override endpoint permissions")
def username_endpoint_override(r, ctx) -> list:
    raw = r.raw or {}
    if not _true(raw.get("enabled")):
        return []
    if not _true(raw.get("guaranteed_endpoint_permission_override_enabled")):
        return []
    return [Hit(
        observation=(f"clientUsername {raw.get('client_username')!r} in Message VPN "
                     f"{raw.get('msg_vpn_name')!r} has "
                     f"guaranteedEndpointPermissionOverrideEnabled=true — it can access any queue "
                     f"or topic-endpoint regardless of that endpoint's own configured "
                     f"permissions, bypassing per-endpoint access control"),
        remediation=("Set guaranteedEndpointPermissionOverrideEnabled=false for application "
                     "identities, reserving the override strictly for a named administrative "
                     "identity if it is needed at all. The override defeats per-endpoint "
                     "permissions across the whole VPN."),
        detail="guaranteed_endpoint_permission_override_enabled=true",
        source_ref={"api": "/SEMP/v2/config/msgVpns/*/clientUsernames",
                    "attribute": "guaranteedEndpointPermissionOverrideEnabled"},
    )]
