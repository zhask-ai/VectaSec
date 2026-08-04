"""Solace PubSub+ connector + rulepack tests. Offline: httpx is never constructed, no broker is
touched. Detectors run against the pure build_resources() output from the golden SEMP config
fixture, so a shape drift between connector and rulepack fails here first.

Every detector is exercised firing and not-firing; the not-assessable path (a per-VPN SEMP read
the credential was refused) is checked explicitly, including that the coverage finding carries
assessable=False — a coverage rule that omits it scores as a PASSED info finding, which is the
exact failure it exists to prevent. The NHI extractor runs on exactly what the connector emits.
"""
import json
import pathlib

from vectasec.connect.solace import build_resources
from vectasec.contracts import Collected, Resource, ScanContext
from vectasec.detect import solace as sd
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS

FIX = json.loads((pathlib.Path(__file__).parent / "fixtures" / "solace_semp.json").read_text())


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def collected(variant, outcomes=None) -> Collected:
    v = FIX[variant]
    https = v["scheme"] == "https"
    return build_resources(
        about=v["about"], vpns=v["vpns"], usernames_by_vpn=v["usernames"],
        acls_by_vpn=v["acls"],
        base_url="https://sol:1943" if https else "http://sol:8080",
        scheme=v["scheme"], tls_verified=https, outcomes=outcomes)


def all_read(variant) -> dict:
    """The outcomes record connect/solace.py writes when every SEMP read answered 200."""
    return {"about": 200, "msgVpns": 200,
            "per_vpn": {v["msgVpnName"]: {"clientUsernames": 200, "aclProfiles": 200}
                        for v in FIX[variant]["vpns"]}}


def denied_per_vpn(*names, status=403) -> Collected:
    """The reproduction: a credential that can list Message VPNs and is refused every per-VPN
    read. SEMP authorises per VPN, so /clientUsernames and /aclProfiles 403 while /msgVpns is
    fine — and both per-VPN lists then arrive empty, exactly as the connector builds them."""
    v = FIX["insecure"]
    per_vpn = {}
    for vpn in v["vpns"]:
        name = vpn["msgVpnName"]
        refused = name in names
        per_vpn[name] = {"clientUsernames": status if refused else 200,
                         "aclProfiles": status if refused else 200}
    return build_resources(
        about=v["about"],
        vpns=v["vpns"],
        usernames_by_vpn={k: [] if k in names else vals for k, vals in v["usernames"].items()},
        acls_by_vpn={k: [] if k in names else vals for k, vals in v["acls"].items()},
        base_url="http://sol:8080", scheme="http", tls_verified=False,
        outcomes={"about": 200, "msgVpns": 200, "per_vpn": per_vpn})


def broker(col: Collected) -> Resource:
    return next(r for r in col.resources if r.kind == "solace_broker")


def vpn(col: Collected, name: str) -> Resource:
    return next(r for r in col.resources if r.kind == "solace_vpn" and r.raw["msg_vpn_name"] == name)


def username(col: Collected, vpn_name: str, uname: str) -> Resource:
    return next(r for r in col.resources if r.kind == "solace_client_username"
               and r.raw["msg_vpn_name"] == vpn_name and r.raw["client_username"] == uname)


# ── registration ────────────────────────────────────────────────────────────────
def test_connector_and_extractor_registered():
    assert "solace" in CONNECTORS and "solace" in IDENTITY_EXTRACTORS


def test_only_password_field_is_secret():
    fields = {f.key: f for f in CONNECTOR_FIELDS["solace"]}
    assert fields["password"].secret is True
    assert fields["semp_url"].required and fields["username"].required
    assert not fields["username"].secret


# ── parse layer ──────────────────────────────────────────────────────────────────
def test_parse_builds_distinct_kinds_and_resolves_default_allow():
    col = collected("insecure")
    kinds = {r.kind for r in col.resources}
    assert {"solace_broker", "solace_vpn", "solace_client_username"} <= kinds
    # the 'app' username references the 'open' profile → resolved to default-allow at parse time
    assert username(col, "prod", "app").raw["acl_profile_is_default_allow"] is True
    assert username(col, "prod", "default").raw["acl_profile_is_default_allow"] is False


# ── SOLACE.MGMT.SEMP_PLAINTEXT ───────────────────────────────────────────────────
def test_semp_plaintext_fires_on_http_and_passes_on_https():
    assert sd.semp_plaintext(broker(collected("insecure")), _ctx([]))
    assert sd.semp_plaintext(broker(collected("hardened")), _ctx([])) == []


# ── SOLACE.BROKER.VPN_READS_DENIED ───────────────────────────────────────────────
def test_denied_per_vpn_reads_file_one_coverage_finding_naming_the_vpn_and_the_rules():
    # A credential that lists VPNs but is refused /clientUsernames and /aclProfiles leaves four
    # rules with nothing to read. Their silence must not be the only trace of that refusal.
    col = denied_per_vpn("prod", "legacy")
    hits = sd.vpn_reads_denied(broker(col), _ctx(col.resources))
    assert len(hits) == 1                       # ONE per broker, not one per read or per rule
    h = hits[0]
    assert "/msgVpns/prod/clientUsernames → HTTP 403" in h.observation
    assert "/msgVpns/legacy/aclProfiles → HTTP 403" in h.observation
    for rule_id in ("SOLACE.VPN.ACL_DEFAULT_ALLOW", "SOLACE.CLIENT_USERNAME.DEFAULT_ENABLED",
                    "SOLACE.CLIENT_USERNAME.OPEN_ACL",
                    "SOLACE.CLIENT_USERNAME.ENDPOINT_OVERRIDE"):
        assert rule_id in h.observation


def test_the_coverage_finding_is_not_assessable_and_says_why():
    # A coverage rule that omits assessable=False scores as a PASSED info finding — the sibling
    # bug this rule exists to avoid.
    h = sd.vpn_reads_denied(broker(denied_per_vpn("prod")), _ctx([]))[0]
    assert h.assessable is False
    assert "refused" in h.assessment_reason


def test_the_rules_the_denied_reads_gated_are_genuinely_silent():
    # The other half of the reproduction: on this input the four rules return nothing at all, so
    # the coverage finding is the only thing standing between a 403 and a clean bill of health.
    col = denied_per_vpn("prod", "legacy")
    ctx = _ctx(col.resources)
    assert sd.vpn_acl_default_allow(vpn(col, "prod"), ctx) == []
    assert [r for r in col.resources if r.kind == "solace_client_username"] == []


def test_only_the_vpn_that_was_refused_is_named():
    col = denied_per_vpn("legacy")
    h = sd.vpn_reads_denied(broker(col), _ctx(col.resources))[0]
    assert "/msgVpns/legacy/clientUsernames" in h.observation
    assert "/msgVpns/prod/" not in h.observation
    # the readable VPN is still assessed normally — a gap elsewhere changes nothing here
    assert sd.vpn_acl_default_allow(vpn(col, "prod"), _ctx(col.resources))


def test_no_coverage_finding_when_every_read_answered_200():
    for variant in ("insecure", "hardened"):
        col = collected(variant, outcomes=all_read(variant))
        assert sd.vpn_reads_denied(broker(col), _ctx(col.resources)) == []


def test_no_coverage_finding_when_no_outcomes_were_recorded():
    # Absence of the coverage record is not evidence of a refusal.
    col = collected("insecure")
    assert broker(col).raw["outcomes"] == {}
    assert sd.vpn_reads_denied(broker(col), _ctx(col.resources)) == []


def test_a_denied_msgvpns_list_names_every_vpn_rule_as_unevaluated():
    # The whole per-VPN layer is invisible when /msgVpns itself is refused.
    col = build_resources(about=None, vpns=[], usernames_by_vpn={}, acls_by_vpn={},
                          base_url="http://sol:8080", scheme="http", tls_verified=False,
                          outcomes={"about": 200, "msgVpns": 401, "per_vpn": {}})
    h = sd.vpn_reads_denied(broker(col), _ctx(col.resources))[0]
    assert "/msgVpns → HTTP 401" in h.observation
    assert "SOLACE.VPN.BASIC_AUTH_TYPE_NONE" in h.observation
    assert h.assessable is False


def test_a_transport_error_is_reported_as_no_response_not_as_a_status():
    col = denied_per_vpn("prod", status=None)
    h = sd.vpn_reads_denied(broker(col), _ctx(col.resources))[0]
    assert "/msgVpns/prod/clientUsernames → no response" in h.observation


def test_a_read_the_pack_does_not_depend_on_is_still_reported_as_a_gap():
    # /about only supplies the version label; the finding must say so rather than claim rules
    # were lost.
    col = collected("insecure", outcomes={**all_read("insecure"), "about": 403})
    h = sd.vpn_reads_denied(broker(col), _ctx(col.resources))[0]
    assert "/about/api → HTTP 403" in h.observation
    assert "no rule in this pack is gated on that read" in h.observation


# ── SOLACE.VPN.BASIC_AUTH_TYPE_NONE ──────────────────────────────────────────────
def test_basic_auth_type_none_fires_and_passes():
    col = collected("insecure")
    hits = sd.vpn_basic_auth_none(vpn(col, "prod"), _ctx([]))
    assert hits and hits[0].severity is None    # decorator default 'critical'
    assert sd.vpn_basic_auth_none(vpn(col, "legacy"), _ctx([])) == []      # type internal
    assert sd.vpn_basic_auth_none(vpn(collected("hardened"), "prod"), _ctx([])) == []


# ── SOLACE.VPN.BASIC_AUTH_NO_CLIENT_CERT ─────────────────────────────────────────
def test_basic_auth_no_client_cert_fires_on_internal_without_cert():
    col = collected("insecure")
    assert sd.vpn_basic_auth_no_client_cert(vpn(col, "legacy"), _ctx([]))
    # 'none' type is owned by BASIC_AUTH_TYPE_NONE, not double-reported here
    assert sd.vpn_basic_auth_no_client_cert(vpn(col, "prod"), _ctx([])) == []
    # hardened has client cert enabled → passes
    assert sd.vpn_basic_auth_no_client_cert(vpn(collected("hardened"), "prod"), _ctx([])) == []


# ── SOLACE.VPN.PLAINTEXT_MESSAGING ───────────────────────────────────────────────
def test_plaintext_messaging_fires_and_passes():
    col = collected("insecure")
    assert sd.vpn_plaintext_messaging(vpn(col, "prod"), _ctx([]))
    assert sd.vpn_plaintext_messaging(vpn(col, "legacy"), _ctx([])) == []   # smf plaintext off
    assert sd.vpn_plaintext_messaging(vpn(collected("hardened"), "prod"), _ctx([])) == []


# ── SOLACE.VPN.TLS_DOWNGRADE_ALLOWED ─────────────────────────────────────────────
def test_tls_downgrade_allowed_fires_and_passes():
    col = collected("insecure")
    assert sd.vpn_tls_downgrade_allowed(vpn(col, "prod"), _ctx([]))
    assert sd.vpn_tls_downgrade_allowed(vpn(col, "legacy"), _ctx([])) == []


# ── SOLACE.VPN.ACL_DEFAULT_ALLOW ─────────────────────────────────────────────────
def test_acl_default_allow_fires_and_lists_dimensions():
    col = collected("insecure")
    hits = sd.vpn_acl_default_allow(vpn(col, "prod"), _ctx([]))
    assert hits and "open" in hits[0].observation
    # legacy has no acl profiles; hardened profiles are all default-deny
    assert sd.vpn_acl_default_allow(vpn(col, "legacy"), _ctx([])) == []
    assert sd.vpn_acl_default_allow(vpn(collected("hardened"), "prod"), _ctx([])) == []


# ── SOLACE.CLIENT_USERNAME.DEFAULT_ENABLED ───────────────────────────────────────
def test_default_username_enabled_fires_only_when_enabled():
    assert sd.default_username_enabled(username(collected("insecure"), "prod", "default"), _ctx([]))
    # hardened disables the default username
    assert sd.default_username_enabled(username(collected("hardened"), "prod", "default"), _ctx([])) == []


# ── SOLACE.CLIENT_USERNAME.OPEN_ACL ──────────────────────────────────────────────
def test_username_open_acl_fires_on_default_allow_profile():
    col = collected("insecure")
    assert sd.username_open_acl(username(col, "prod", "app"), _ctx([]))       # 'open' profile
    assert sd.username_open_acl(username(col, "prod", "default"), _ctx([])) == []   # 'default' deny
    # A username whose ACL profile was unreadable is 'unknown', never a fire — and the silence is
    # accounted for: the refused read is filed once, at broker scope, by VPN_READS_DENIED.
    unknown = Resource(kind="solace_client_username", name="x", ext_id="x",
                       raw={"client_username": "x", "msg_vpn_name": "v", "enabled": True,
                            "acl_profile_name": "missing", "acl_profile_is_default_allow": None})
    assert sd.username_open_acl(unknown, _ctx([unknown])) == []


# ── SOLACE.CLIENT_USERNAME.ENDPOINT_OVERRIDE ─────────────────────────────────────
def test_endpoint_override_fires_and_passes():
    col = collected("insecure")
    assert sd.username_endpoint_override(username(col, "prod", "app"), _ctx([]))
    assert sd.username_endpoint_override(username(col, "prod", "default"), _ctx([])) == []


# ── NHI ──────────────────────────────────────────────────────────────────────────
def _derived():
    return derive_identities("solace", collected("insecure"))


def test_client_usernames_become_identities_default_tagged():
    col = _derived()
    by_name = {r.name: r for r in col.resources if r.kind == "identity"}
    assert set(by_name) == {"prod/default", "prod/app"}
    assert "builtin_default" in by_name["prod/default"].raw["tags"]
    assert "builtin_default" not in by_name["prod/app"].raw["tags"]


def test_acl_profile_grants_wildcard_on_default_allow_and_edges_resolve():
    col = _derived()
    grants = {g.raw["identity_ext_id"]: g for g in col.resources if g.kind == "grant"}
    app_id = next(i.ext_id for i in col.resources if i.kind == "identity" and i.name == "prod/app")
    assert grants[app_id].raw["action"] == "acl-profile" and grants[app_id].raw["wildcard"] is True
    default_id = next(i.ext_id for i in col.resources if i.kind == "identity" and i.name == "prod/default")
    assert grants[default_id].raw["wildcard"] is False
    granted_to = {(e.src_ext_id, e.dst_ext_id) for e in col.edges if e.kind == "granted_to"}
    for g in grants.values():
        assert (g.ext_id, g.raw["identity_ext_id"]) in granted_to


def test_no_credentials_emitted_semp_never_returns_passwords():
    col = _derived()
    assert not [r for r in col.resources if r.kind == "credential"]
