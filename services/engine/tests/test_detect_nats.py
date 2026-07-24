"""NATS / JetStream connector + rulepack tests. Offline: httpx is never constructed, no server is
touched. Detectors run against the pure build_resources() output from the golden /varz + config
fixture, so a shape drift between connector and rulepack fails here first.

Every detector is exercised firing, not-firing, and (where it has one) reporting a not-assessable
coverage gap. The NHI extractor is checked on exactly what the connector emits.
"""
import json
import pathlib

from vectasec.connect.nats import build_resources
from vectasec.contracts import Collected, Resource, ScanContext
from vectasec.detect import nats as nd
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS

FIX = json.loads((pathlib.Path(__file__).parent / "fixtures" / "nats_varz.json").read_text())


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def collected(variant, **over):
    kwargs = dict(
        varz=FIX["varz"][variant], jsz=FIX["jsz"], connz=FIX["connz"],
        base_url="http://localhost:8222", scheme="http", tls_verified=False,
        monitoring_unauthenticated=True, config=FIX["config"][variant],
    )
    kwargs.update(over)
    return build_resources(**kwargs)


def server(col: Collected) -> Resource:
    return next(r for r in col.resources if r.kind == "nats_server")


def account(col: Collected, name: str) -> Resource:
    return next(r for r in col.resources if r.kind == "nats_account" and r.raw["name"] == name)


# ── registration ────────────────────────────────────────────────────────────────
def test_connector_and_extractor_registered():
    assert "nats" in CONNECTORS and "nats" in IDENTITY_EXTRACTORS


def test_only_password_field_is_secret():
    fields = {f.key: f for f in CONNECTOR_FIELDS["nats"]}
    assert fields["password"].secret is True
    assert fields["monitoring_url"].required is True
    assert not fields["config_json"].secret and not fields["monitoring_url"].secret


# ── parse layer ──────────────────────────────────────────────────────────────────
def test_parse_builds_server_and_accounts_with_distinct_kinds():
    col = collected("insecure")
    s = server(col)
    assert s.kind == "nats_server" and s.raw["auth_required"] is False
    assert s.raw["no_auth_user"] == "sysadmin"
    assert s.raw["no_auth_user_account"] == "SYS" and s.raw["no_auth_user_is_system"] is True
    accounts = {r.raw["name"] for r in col.resources if r.kind == "nats_account"}
    assert accounts == {"SYS", "APP"}
    # credential values never enter the resource — only presence booleans
    dump = json.dumps([r.raw for r in col.resources])
    assert "REDACTED" not in dump
    app = account(col, "APP")
    flags = {u["user"]: u for u in app.raw["users"]}
    assert flags["app"]["has_credential"] is True and flags["nocred"]["has_credential"] is False


# ── NATS.AUTH.NOT_REQUIRED ───────────────────────────────────────────────────────
def test_auth_not_required_fires_and_passes():
    assert nd.auth_not_required(server(collected("insecure")), _ctx([]))
    assert nd.auth_not_required(server(collected("hardened")), _ctx([])) == []
    # varz unreadable → silent (the monitoring gap is filed elsewhere), never a fabricated pass
    blind = server(collected("insecure", varz=None))
    assert nd.auth_not_required(blind, _ctx([])) == []


# ── NATS.AUTH.NO_AUTH_USER ───────────────────────────────────────────────────────
def test_no_auth_user_system_account_is_critical():
    hits = nd.no_auth_user_mapped(server(collected("insecure")), _ctx([]))
    assert hits and hits[0].severity == "critical"
    assert "SYSTEM" in hits[0].observation


def test_no_auth_user_absent_passes_and_missing_config_is_not_assessable():
    assert nd.no_auth_user_mapped(server(collected("hardened")), _ctx([])) == []
    blind = server(collected("insecure", config={}))
    hits = nd.no_auth_user_mapped(blind, _ctx([]))
    assert hits and hits[0].assessable is False and hits[0].assessment_reason


def test_no_auth_user_non_system_account_is_high_not_critical():
    col = collected("insecure", config={
        "system_account": "SYS", "no_auth_user": "app",
        "accounts": {"SYS": {"users": [{"user": "sysadmin", "password": "x"}]},
                     "APP": {"users": [{"user": "app", "password": "y"}]}}})
    hits = nd.no_auth_user_mapped(server(col), _ctx([]))
    assert hits and hits[0].severity is None   # decorator default 'high', no escalation


# ── NATS.TLS.NOT_REQUIRED ────────────────────────────────────────────────────────
def test_tls_not_required_fires_and_passes():
    assert nd.tls_not_required(server(collected("insecure")), _ctx([]))
    assert nd.tls_not_required(server(collected("hardened")), _ctx([])) == []


# ── NATS.LEAFNODE / GATEWAY NO_TLS ───────────────────────────────────────────────
def test_leafnode_and_gateway_no_tls_fire_only_without_tls():
    ins = server(collected("insecure"))
    assert nd.leafnode_no_tls(ins, _ctx([])) and nd.gateway_no_tls(ins, _ctx([]))
    hard = server(collected("hardened"))
    assert nd.leafnode_no_tls(hard, _ctx([])) == [] and nd.gateway_no_tls(hard, _ctx([])) == []


def test_leafnode_gateway_skip_when_no_config_provided():
    blind = server(collected("insecure", config={}))
    assert nd.leafnode_no_tls(blind, _ctx([])) == []
    assert nd.gateway_no_tls(blind, _ctx([])) == []


# ── NATS.MONITORING.UNAUTHENTICATED ──────────────────────────────────────────────
def test_monitoring_unauthenticated_fires_and_passes():
    assert nd.monitoring_unauthenticated(server(collected("insecure")), _ctx([]))
    authed = server(collected("insecure", monitoring_unauthenticated=False))
    assert nd.monitoring_unauthenticated(authed, _ctx([])) == []


# ── NATS.SYSTEM_ACCOUNT.NOT_CONFIGURED ───────────────────────────────────────────
def test_system_account_not_configured_fires_and_passes():
    none_cfg = collected("insecure", varz={"version": "2.11.2", "auth_required": True,
                                            "tls_required": True, "system_account": None},
                         config={"accounts": {"APP": {"users": [{"user": "a", "password": "x"}]}}})
    assert nd.system_account_not_configured(server(none_cfg), _ctx([]))
    assert nd.system_account_not_configured(server(collected("hardened")), _ctx([])) == []


# ── NATS.ACCOUNT.USER_NO_CREDENTIAL ──────────────────────────────────────────────
def test_account_user_no_credential_fires_on_app_not_sys():
    col = collected("insecure")
    assert nd.account_user_no_credential(account(col, "APP"), _ctx([]))     # nocred user
    assert nd.account_user_no_credential(account(col, "SYS"), _ctx([])) == []


def test_account_user_no_credential_escalates_in_system_account():
    r = Resource(kind="nats_account", name="SYS", ext_id="x",
                 raw={"name": "SYS", "is_system_account": True,
                      "users": [{"user": "ghost", "has_credential": False}]})
    hits = nd.account_user_no_credential(r, _ctx([r]))
    assert hits and hits[0].severity == "high"


# ── NATS.VERSION.JETSTREAM_AUTHZ_CVE ─────────────────────────────────────────────
def test_jetstream_authz_cve_version_boundaries():
    # 2.10.7 < 2.10.27 floor → vulnerable; 2.11.2 >= 2.11.1 floor → patched
    assert nd.jetstream_authz_cve(server(collected("insecure")), _ctx([]))
    assert nd.jetstream_authz_cve(server(collected("hardened")), _ctx([])) == []
    patched = server(collected("insecure", varz={**FIX["varz"]["insecure"], "version": "2.10.27"}))
    assert nd.jetstream_authz_cve(patched, _ctx([])) == []
    future = server(collected("insecure", varz={**FIX["varz"]["insecure"], "version": "2.12.0"}))
    assert nd.jetstream_authz_cve(future, _ctx([])) == []


def test_jetstream_authz_cve_unparseable_is_not_assessable():
    unk = server(collected("insecure", varz={**FIX["varz"]["insecure"], "version": "nightly"}))
    hits = nd.jetstream_authz_cve(unk, _ctx([]))
    assert hits and hits[0].assessable is False


# ── NHI ──────────────────────────────────────────────────────────────────────────
def _derived():
    return derive_identities("nats", collected("insecure"))


def test_users_become_identities_tagged_system_and_anonymous():
    col = _derived()
    by_name = {r.name: r for r in col.resources if r.kind == "identity"}
    assert set(by_name) == {"SYS/sysadmin", "APP/app", "APP/nocred"}
    sysadmin = by_name["SYS/sysadmin"]
    assert "system_account" in sysadmin.raw["tags"]        # in SYS
    assert "anonymous_mapped" in sysadmin.raw["tags"]      # no_auth_user points at it


def test_credentials_present_only_for_users_with_secrets():
    col = _derived()
    creds = {c.labels["owner"]: c for c in col.resources if c.kind == "credential"}
    owners = {c.raw["owner_ext_id"] for c in col.resources if c.kind == "credential"}
    # app + sysadmin have creds; nocred does not
    assert any(o.endswith("app") for o in owners)
    assert "identity:nats:app-nocred" not in owners
    # no secret value leaked into the credential metadata
    assert "REDACTED" not in json.dumps([c.raw for c in col.resources])


def test_grants_wildcard_flag_and_no_permission_block_is_full_access():
    col = _derived()
    grants = [g for g in col.resources if g.kind == "grant"]
    # app: publish orders.> (wildcard, ends with >) + subscribe _INBOX.>
    app_id = next(i.ext_id for i in col.resources if i.name == "APP/app")
    app_grants = [g for g in grants if g.raw["identity_ext_id"] == app_id]
    assert any(g.raw["action"] == "publish" and g.raw["wildcard"] for g in app_grants)
    # nocred + sysadmin have no permissions block → one wildcard "all → >" grant each
    nocred_id = next(i.ext_id for i in col.resources if i.name == "APP/nocred")
    nocred_grants = [g for g in grants if g.raw["identity_ext_id"] == nocred_id]
    assert len(nocred_grants) == 1 and nocred_grants[0].raw["action"] == "all"
    assert nocred_grants[0].raw["wildcard"] is True
    # every grant resolves a granted_to edge
    edge_pairs = {(e.src_ext_id, e.dst_ext_id) for e in col.edges if e.kind == "granted_to"}
    for g in grants:
        assert (g.ext_id, g.raw["identity_ext_id"]) in edge_pairs
