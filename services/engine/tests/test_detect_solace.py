"""Solace PubSub+ connector + rulepack tests. Offline: httpx is never constructed, no broker is
touched. Detectors run against the pure build_resources() output from the golden SEMP config
fixture, so a shape drift between connector and rulepack fails here first.

Every detector is exercised firing and not-firing; the not-assessable path (an ACL profile that
could not be read) is checked explicitly. The NHI extractor runs on exactly what the connector
emits.
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


def collected(variant) -> Collected:
    v = FIX[variant]
    https = v["scheme"] == "https"
    return build_resources(
        about=v["about"], vpns=v["vpns"], usernames_by_vpn=v["usernames"],
        acls_by_vpn=v["acls"],
        base_url="https://sol:1943" if https else "http://sol:8080",
        scheme=v["scheme"], tls_verified=https)


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
    # a username whose ACL profile was unreadable is 'unknown', never a fire
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
