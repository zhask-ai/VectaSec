"""Solace PubSub+ connector — read-only SEMP v2 config API (httpx, HTTP Basic).

Solace PubSub+ is an enterprise event broker sitting squarely in the integration layer, so its
posture belongs in an integration-security tool. This connector issues only GETs against the SEMP
v2 *config* API and writes nothing:

  /SEMP/v2/config/about/api                          the SEMP/broker version.
  /SEMP/v2/config/msgVpns                             each Message VPN, with its authentication and
                                                     transport posture verbatim: authenticationBasic
                                                     Enabled/Type, authenticationClientCertEnabled,
                                                     serviceSmfPlainTextEnabled / serviceSmfTls
                                                     Enabled, tlsAllowDowngradeToPlainTextEnabled.
  .../msgVpns/{vpn}/clientUsernames                   the client usernames (the NHI principals) and
                                                     which ACL/client profile each references.
  .../msgVpns/{vpn}/aclProfiles                       ACL profiles and their default actions
                                                     (clientConnect / publishTopic / subscribeTopic).

Credential discipline: SEMP marks a clientUsername's `password` write-only and never returns it,
so no password value is ever available to store — the connector records only the identity and its
ACL/client-profile references (absence of credential material recorded honestly, like Kafka). The
admin password used to authenticate to SEMP is a ConnectorField secret and never enters a Resource.

The parse layer (build_resources) is pure: SEMP list payloads in, Resources out — httpx and a live
broker stay out of the test suite. Kinds are DISTINCT (solace_broker, solace_vpn,
solace_client_username) so no other rulepack runs against a Solace resource by accident.
"""
from urllib.parse import urlparse

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector


def _acl_default_allow(profile: dict) -> bool:
    """A profile is 'default-allow' on the data plane when it publishes or subscribes to topics by
    default — the anti-pattern of an allowlist ACL that in fact permits everything not denied."""
    return (str(profile.get("publishTopicDefaultAction") or "").lower() == "allow"
            or str(profile.get("subscribeTopicDefaultAction") or "").lower() == "allow")


def build_resources(*, about: dict | None, vpns: list, usernames_by_vpn: dict,
                    acls_by_vpn: dict, base_url: str, scheme: str, tls_verified: bool,
                    outcomes: dict | None = None) -> Collected:
    """Pure normalisation: SEMP list payloads → Collected. No httpx here."""
    host = urlparse(base_url).hostname or base_url
    broker_ext = f"solace-{host}"
    resources: list[Resource] = [Resource(
        kind="solace_broker",
        name=host,
        ext_id=broker_ext,
        labels={"semp_version": str((about or {}).get("sempVersion") or "?")},
        raw={
            "semp_version": (about or {}).get("sempVersion"),
            "platform": (about or {}).get("platform"),
            "semp_url": base_url,
            "semp_scheme": scheme,
            "semp_tls_verified": tls_verified,
            # HTTP Basic over plaintext exposes the admin credential; https+verified suppresses it.
            "semp_plaintext": scheme != "https",
            "msg_vpn_count": len(vpns or []),
            # {"about": 200, "msgVpns": 200,
            #  "per_vpn": {"<vpn>": {"clientUsernames": 403, "aclProfiles": 403}}}
            # Every SEMP read this scan attempted, with the status it answered. This is the
            # broker's coverage record: a rule that finds an empty list has to be able to tell
            # "the broker has none" from "we were not allowed to look".
            "outcomes": outcomes or {},
        },
    )]
    edges: list[Edge] = []

    for vpn in vpns or []:
        vpn_name = vpn.get("msgVpnName")
        vpn_ext = f"{broker_ext}-vpn-{vpn_name}"
        acl_profiles = acls_by_vpn.get(vpn_name) or []
        acl_index = {p.get("aclProfileName"): p for p in acl_profiles}
        resources.append(Resource(
            kind="solace_vpn",
            name=str(vpn_name),
            ext_id=vpn_ext,
            namespace=str(vpn_name),
            labels={"enabled": str(vpn.get("enabled"))},
            raw={
                "msg_vpn_name": vpn_name,
                "enabled": vpn.get("enabled"),
                "authentication_basic_enabled": vpn.get("authenticationBasicEnabled"),
                "authentication_basic_type": vpn.get("authenticationBasicType"),
                "authentication_client_cert_enabled": vpn.get("authenticationClientCertEnabled"),
                "service_smf_plain_text_enabled": vpn.get("serviceSmfPlainTextEnabled"),
                "service_smf_tls_enabled": vpn.get("serviceSmfTlsEnabled"),
                "tls_allow_downgrade_to_plain_text_enabled":
                    vpn.get("tlsAllowDowngradeToPlainTextEnabled"),
                "acl_profiles": [{
                    "name": p.get("aclProfileName"),
                    "client_connect_default_action": p.get("clientConnectDefaultAction"),
                    "publish_topic_default_action": p.get("publishTopicDefaultAction"),
                    "subscribe_topic_default_action": p.get("subscribeTopicDefaultAction"),
                } for p in acl_profiles],
                "broker_ext": broker_ext,
            },
        ))
        edges.append(Edge(src_ext_id=broker_ext, dst_ext_id=vpn_ext, kind="hosts"))

        for cu in usernames_by_vpn.get(vpn_name) or []:
            uname = cu.get("clientUsername")
            acl_name = cu.get("aclProfileName")
            profile = acl_index.get(acl_name)
            cu_ext = f"{vpn_ext}-cu-{uname}"
            resources.append(Resource(
                kind="solace_client_username",
                name=f"{vpn_name}/{uname}",
                ext_id=cu_ext,
                namespace=str(vpn_name),
                labels={"enabled": str(cu.get("enabled")),
                        "is_default": "true" if uname == "default" else "false"},
                raw={
                    "client_username": uname,
                    "msg_vpn_name": vpn_name,
                    "enabled": cu.get("enabled"),
                    "acl_profile_name": acl_name,
                    "client_profile_name": cu.get("clientProfileName"),
                    "guaranteed_endpoint_permission_override_enabled":
                        cu.get("guaranteedEndpointPermissionOverrideEnabled"),
                    # Resolved here so the detector cites a fact, not a second lookup. None when the
                    # referenced profile was not readable (→ 'unknown', never 'restricted').
                    "acl_profile_is_default_allow":
                        _acl_default_allow(profile) if profile is not None else None,
                    "vpn_ext": vpn_ext,
                },
            ))
            edges.append(Edge(src_ext_id=vpn_ext, dst_ext_id=cu_ext, kind="hosts"))

    return Collected(resources=resources, edges=edges)


def _get(client: httpx.Client, path: str, auth):
    """One SEMP config read → an envelope. SEMP wraps list results in {"data": [...]}; a non-200
    stays distinguishable from an empty data array so a rule cannot silently pass on a 401."""
    try:
        r = client.get(path, auth=auth)
    except httpx.HTTPError as e:
        return {"ok": False, "status": None, "error": f"{type(e).__name__}: {e}"}
    if r.status_code != 200:
        return {"ok": False, "status": r.status_code, "error": f"http_{r.status_code}"}
    try:
        body = r.json()
    except ValueError:
        return {"ok": False, "status": 200, "error": "non_json_body"}
    return {"ok": True, "status": 200, "data": body.get("data") if isinstance(body, dict) else body}


@connector("solace", fields=[
    ConnectorField("semp_url", "SEMP URL", required=True, placeholder="https://localhost:1943",
                   help="Solace SEMP base URL (the SEMP service port; 1943 for TLS, 8080 for "
                        "plaintext). The connector appends /SEMP/v2/config. GETs only."),
    ConnectorField("username", "Admin username", required=True,
                   help="A management user with read access to the config API."),
    ConnectorField("password", "Admin password", required=True, secret=True,
                   help="Used to open the SEMP request via HTTP Basic, never stored in any "
                        "resource."),
])
def collect(config: dict) -> Collected:
    base = (config.get("semp_url") or "").rstrip("/")
    if not base:
        raise SystemExit("solace connector requires config['semp_url'] "
                         "(e.g. https://localhost:1943)")
    auth = (config.get("username") or "", config.get("password") or "")
    verify = config.get("verify_tls", True)
    timeout = float(config.get("timeout") or 10)
    scheme = urlparse(base).scheme or "http"
    cfg_base = f"{base}/SEMP/v2/config"

    outcomes: dict = {}
    with httpx.Client(base_url=cfg_base, timeout=timeout, verify=bool(verify),
                      follow_redirects=False, auth=None) as client:
        about_res = _get(client, "/about/api", auth)
        outcomes["about"] = about_res.get("status")
        vpns_res = _get(client, "/msgVpns?count=100", auth)
        outcomes["msgVpns"] = vpns_res.get("status")
        vpns = vpns_res.get("data") if vpns_res.get("ok") and isinstance(vpns_res.get("data"), list) else []

        usernames_by_vpn: dict = {}
        acls_by_vpn: dict = {}
        # Per-VPN reads are recorded PER VPN, not folded into one broker-wide number: a management
        # user is routinely scoped per Message VPN, so /clientUsernames can answer 200 on one VPN
        # and 403 on the next. A denied read leaves the list empty, which is indistinguishable from
        # a VPN that genuinely has no usernames or no ACL profiles — so the status is what
        # SOLACE.BROKER.VPN_READS_DENIED reads to name which VPN was not covered.
        per_vpn: dict = {}
        for vpn in vpns:
            name = vpn.get("msgVpnName")
            cu_res = _get(client, f"/msgVpns/{name}/clientUsernames?count=100", auth)
            usernames_by_vpn[name] = cu_res.get("data") if cu_res.get("ok") and isinstance(
                cu_res.get("data"), list) else []
            acl_res = _get(client, f"/msgVpns/{name}/aclProfiles?count=100", auth)
            acls_by_vpn[name] = acl_res.get("data") if acl_res.get("ok") and isinstance(
                acl_res.get("data"), list) else []
            per_vpn[str(name)] = {"clientUsernames": cu_res.get("status"),
                                  "aclProfiles": acl_res.get("status")}
        outcomes["per_vpn"] = per_vpn

    return build_resources(
        about=about_res.get("data") if about_res.get("ok") and isinstance(about_res.get("data"), dict) else None,
        vpns=vpns,
        usernames_by_vpn=usernames_by_vpn,
        acls_by_vpn=acls_by_vpn,
        base_url=base,
        scheme=scheme,
        tls_verified=(scheme == "https" and verify is True and about_res.get("status") is not None),
        outcomes=outcomes,
    )


# ── NHI: Solace client usernames + their ACL profiles → identity / grant ──────
@identity_extractor("solace")
def _from_solace(resources: list) -> tuple:
    """Each clientUsername → identity (service_account), named "<vpn>/<username>", tagged
    'builtin_default' when it is the shipped `default` username. Its ACL-profile reference becomes
    a grant, flagged wildcard when the profile is default-allow. SEMP never returns the username's
    password, so no credential material is emitted — absence recorded, not silence."""
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "solace_client_username":
            continue
        raw = r.raw or {}
        name = raw.get("client_username")
        vpn = raw.get("msg_vpn_name")
        is_default = name == "default"
        idr = _mk_identity("solace", "service_account", f"{vpn}/{name}",
                           tags=(["builtin_default"] if is_default else []),
                           source_ext=r.ext_id,
                           extra={"vpn": vpn, "enabled": raw.get("enabled")})
        out.append(idr)

        acl = raw.get("acl_profile_name")
        if acl:
            wildcard = bool(raw.get("acl_profile_is_default_allow"))
            g = _mk_grant("solace", idr.ext_id, "acl-profile", str(acl), wildcard=wildcard,
                          scope=str(vpn or ""),
                          extra={"vpn": vpn, "default_allow": raw.get("acl_profile_is_default_allow")})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
