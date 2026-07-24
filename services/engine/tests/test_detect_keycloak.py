"""Unit tests for the Keycloak connector parse layer, rulepack, and NHI extraction.

Offline: no httpx client is ever constructed, no Keycloak is touched. The baseline is the
golden fixture in fixtures/keycloak_responses.json — realm/client representations and an OIDC
discovery document shaped as the admin API returns them. Resources are built through the
connector's OWN parse layer. Every rule gets a FIRE, a DOES-NOT-FIRE, and (where it has one) a
NOT-ASSESSABLE case; the negative cases carry the weight (a redirect wildcard confined to the
path, sslRequired=external, a PKCE-protected public client) so the rules do not just always fire.
"""
import json
import pathlib

from vectasec.contracts import Collected, Resource, ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS, DETECTORS
import vectasec.detect.keycloak  # noqa: F401 — import registers the rulepack
from vectasec.connect.keycloak import parse_client, parse_realm
from vectasec.detect.keycloak import _redirect_is_broad

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "keycloak_responses.json").read_text()
)
BASE = "https://kc.example.com"

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("KEYCLOAK.")}

EXPECTED_RULES = {
    "KEYCLOAK.CLIENT.WILDCARD_REDIRECT_URI",
    "KEYCLOAK.CLIENT.PUBLIC_NO_PKCE",
    "KEYCLOAK.CLIENT.DIRECT_ACCESS_GRANTS",
    "KEYCLOAK.CLIENT.IMPLICIT_FLOW",
    "KEYCLOAK.CLIENT.UNSIGNED_TOKENS",
    "KEYCLOAK.CLIENT.WEB_ORIGINS_WILDCARD",
    "KEYCLOAK.REALM.SSL_NOT_REQUIRED",
    "KEYCLOAK.REALM.BRUTE_FORCE_OFF",
    "KEYCLOAK.REALM.OIDC_UNSIGNED_ID_TOKEN",
    "KEYCLOAK.REALM.USER_REGISTRATION_OPEN",
    "KEYCLOAK.REALM.MASTER_REALM_IN_USE",
    "KEYCLOAK.REALM.NOT_ASSESSED",
}

_OK = {"outcome": "ok", "error": None}
_FORBIDDEN = {"outcome": "forbidden", "error": "HTTP 403"}


# ── builders ──────────────────────────────────────────────────────────────────
_CLIENTS = {c["clientId"]: c for c in FIX["clients"]}


def client(client_id: str, realm: str = "myrealm") -> Resource:
    return parse_client(realm, _CLIENTS[client_id])


def realm(rep="realm_weak", disc="discovery_unsigned", collection=None,
          rep_data=None) -> Resource:
    rname = (rep_data if rep_data is not None else FIX[rep]).get("realm", "myrealm")
    col = {"oidc_discovery": _OK, f"admin/realms/{rname}": _OK,
           f"admin/realms/{rname}/clients": _OK}
    col.update(collection or {})
    data = rep_data if rep_data is not None else FIX[rep]
    return parse_realm(BASE, rname, data, FIX[disc] if disc else {}, col)


def scan(*resources) -> ScanContext:
    return ScanContext(connection_id="c1", tenant_id="t1", resources=list(resources))


def fire(rule_id, resource, ctx=None) -> list:
    d = RULES[rule_id]
    assert resource.kind in d.kinds, f"{rule_id} does not apply to kind={resource.kind}"
    return d.fn(resource, ctx or scan(resource)) or []


def sev(hits, rule_id) -> list:
    base = RULES[rule_id].severity
    return [h.severity or base for h in hits]


# ── pack + registration shape ──────────────────────────────────────────────────
def test_expected_rules_all_registered():
    assert set(RULES) == EXPECTED_RULES


def test_rules_only_run_on_keycloak_kinds():
    for d in RULES.values():
        assert all(k.startswith("keycloak_") for k in d.kinds), d.rule_id


def test_connector_registered_and_secrets_marked():
    assert "keycloak" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["keycloak"]}
    assert fields["token"].secret and fields["client_secret"].secret
    assert fields["base_url"].required and fields["realm"].required
    assert not fields["client_id"].secret


# ── secret discipline ──────────────────────────────────────────────────────────
def test_client_secret_value_is_never_stored():
    for cid in ("open-redirect", "legacy-ropc", "hardened-app"):
        c = client(cid)
        assert "SHOULD-NEVER-BE-STORED" not in json.dumps(c.raw)
        assert c.raw["has_client_secret"] is True          # confidential → presence inferred
    assert client("spa-app").raw["has_client_secret"] is False   # public → no secret


# ── KEYCLOAK.CLIENT.WILDCARD_REDIRECT_URI ───────────────────────────────────────
def test_wildcard_redirect_fires_on_host_scheme_wildcard():
    hits = fire("KEYCLOAK.CLIENT.WILDCARD_REDIRECT_URI", client("open-redirect"))
    assert len(hits) == 1 and sev(hits, "KEYCLOAK.CLIENT.WILDCARD_REDIRECT_URI") == ["high"]


def test_wildcard_redirect_quiet_on_path_wildcard_and_exact():
    # a trailing PATH wildcard is the common, low-risk form → must not fire
    assert fire("KEYCLOAK.CLIENT.WILDCARD_REDIRECT_URI", client("spa-app")) == []
    assert fire("KEYCLOAK.CLIENT.WILDCARD_REDIRECT_URI", client("hardened-app")) == []


def test_redirect_classifier():
    assert _redirect_is_broad("*")
    assert _redirect_is_broad("https://*")
    assert _redirect_is_broad("http://*.evil.example")
    assert _redirect_is_broad("*://app.example.com")
    assert not _redirect_is_broad("https://app.example.com/*")
    assert not _redirect_is_broad("https://app.example.com/callback")
    assert not _redirect_is_broad("")


# ── KEYCLOAK.CLIENT.PUBLIC_NO_PKCE ──────────────────────────────────────────────
def test_public_no_pkce_fires_and_pkce_or_confidential_pass():
    hits = fire("KEYCLOAK.CLIENT.PUBLIC_NO_PKCE", client("spa-app"))
    assert len(hits) == 1 and "PKCE" in hits[0].observation
    # confidential client (even without pkce) is a different threat model → not this rule
    assert fire("KEYCLOAK.CLIENT.PUBLIC_NO_PKCE", client("hardened-app")) == []
    # public client but NOT running the auth-code flow → nothing to protect with PKCE here
    assert fire("KEYCLOAK.CLIENT.PUBLIC_NO_PKCE", client("implicit-app")) == []
    # public + standard flow + S256 set → passes
    c = client("spa-app")
    c.raw["attributes"] = {"pkce.code.challenge.method": "S256"}
    assert fire("KEYCLOAK.CLIENT.PUBLIC_NO_PKCE", c) == []


# ── KEYCLOAK.CLIENT.DIRECT_ACCESS_GRANTS ────────────────────────────────────────
def test_direct_access_grants_fires_on_confidential_only():
    hits = fire("KEYCLOAK.CLIENT.DIRECT_ACCESS_GRANTS", client("legacy-ropc"))
    assert len(hits) == 1 and "Resource Owner Password" in hits[0].observation
    assert fire("KEYCLOAK.CLIENT.DIRECT_ACCESS_GRANTS", client("hardened-app")) == []
    # a public client with direct grants is by-design (e.g. admin-cli) → excluded per scope
    pub = client("spa-app")
    pub.raw["direct_access_grants_enabled"] = True
    assert fire("KEYCLOAK.CLIENT.DIRECT_ACCESS_GRANTS", pub) == []


# ── KEYCLOAK.CLIENT.IMPLICIT_FLOW ───────────────────────────────────────────────
def test_implicit_flow_fire_and_pass():
    assert len(fire("KEYCLOAK.CLIENT.IMPLICIT_FLOW", client("implicit-app"))) == 1
    assert fire("KEYCLOAK.CLIENT.IMPLICIT_FLOW", client("hardened-app")) == []


# ── KEYCLOAK.CLIENT.UNSIGNED_TOKENS ─────────────────────────────────────────────
def test_unsigned_tokens_fires_on_none_and_any():
    hits = fire("KEYCLOAK.CLIENT.UNSIGNED_TOKENS", client("legacy-ropc"))
    assert len(hits) == 1 and "ID token" in hits[0].observation
    # request-object alg "any" also permits an unsigned request object
    c = client("hardened-app")
    c.raw["attributes"] = {"request.object.signature.alg": "any"}
    anyhit = fire("KEYCLOAK.CLIENT.UNSIGNED_TOKENS", c)
    assert len(anyhit) == 1 and "request object" in anyhit[0].observation
    # RS256 everywhere → quiet
    assert fire("KEYCLOAK.CLIENT.UNSIGNED_TOKENS", client("hardened-app")) == []


# ── KEYCLOAK.CLIENT.WEB_ORIGINS_WILDCARD ────────────────────────────────────────
def test_web_origins_wildcard_fire_and_pass():
    assert len(fire("KEYCLOAK.CLIENT.WEB_ORIGINS_WILDCARD", client("open-redirect"))) == 1
    # "+" (mirror registered redirects) is NOT the "*" wildcard
    assert fire("KEYCLOAK.CLIENT.WEB_ORIGINS_WILDCARD", client("spa-app")) == []
    assert fire("KEYCLOAK.CLIENT.WEB_ORIGINS_WILDCARD", client("hardened-app")) == []


# ── KEYCLOAK.REALM.SSL_NOT_REQUIRED ─────────────────────────────────────────────
def test_ssl_not_required_high_none_low_external_pass_all():
    high = fire("KEYCLOAK.REALM.SSL_NOT_REQUIRED", realm(rep="realm_weak"))
    assert len(high) == 1 and sev(high, "KEYCLOAK.REALM.SSL_NOT_REQUIRED") == ["high"]
    low = fire("KEYCLOAK.REALM.SSL_NOT_REQUIRED", realm(rep="realm_external"))
    assert len(low) == 1 and sev(low, "KEYCLOAK.REALM.SSL_NOT_REQUIRED") == ["low"]
    assert fire("KEYCLOAK.REALM.SSL_NOT_REQUIRED", realm(rep="realm_hardened")) == []


def test_ssl_not_required_not_assessable_when_realm_denied():
    r = realm(rep_data={"realm": "myrealm"},
              collection={"admin/realms/myrealm": _FORBIDDEN})
    hits = fire("KEYCLOAK.REALM.SSL_NOT_REQUIRED", r)
    assert len(hits) == 1 and hits[0].assessable is False


# ── KEYCLOAK.REALM.BRUTE_FORCE_OFF ──────────────────────────────────────────────
def test_brute_force_off_fire_and_pass():
    assert len(fire("KEYCLOAK.REALM.BRUTE_FORCE_OFF", realm(rep="realm_weak"))) == 1
    assert fire("KEYCLOAK.REALM.BRUTE_FORCE_OFF", realm(rep="realm_hardened")) == []


# ── KEYCLOAK.REALM.OIDC_UNSIGNED_ID_TOKEN ───────────────────────────────────────
def test_oidc_unsigned_id_token_fire_and_pass():
    hits = fire("KEYCLOAK.REALM.OIDC_UNSIGNED_ID_TOKEN", realm(disc="discovery_unsigned"))
    assert len(hits) == 1 and "'none'" in hits[0].observation
    assert fire("KEYCLOAK.REALM.OIDC_UNSIGNED_ID_TOKEN", realm(disc="discovery_signed")) == []
    # discovery unreadable → this rule stays quiet (the coverage-gap rule reports it instead)
    unreadable = realm(disc="discovery_unsigned",
                       collection={"oidc_discovery": _FORBIDDEN})
    assert fire("KEYCLOAK.REALM.OIDC_UNSIGNED_ID_TOKEN", unreadable) == []


# ── KEYCLOAK.REALM.USER_REGISTRATION_OPEN ───────────────────────────────────────
def test_registration_open_fire_and_pass():
    assert len(fire("KEYCLOAK.REALM.USER_REGISTRATION_OPEN", realm(rep="realm_weak"))) == 1
    assert fire("KEYCLOAK.REALM.USER_REGISTRATION_OPEN", realm(rep="realm_hardened")) == []


# ── KEYCLOAK.REALM.MASTER_REALM_IN_USE ──────────────────────────────────────────
def test_master_realm_in_use_fire_and_pass():
    hits = fire("KEYCLOAK.REALM.MASTER_REALM_IN_USE", realm(rep="realm_master"))
    assert len(hits) == 1 and hits[0].assessable is False   # default-cred state unobservable
    assert fire("KEYCLOAK.REALM.MASTER_REALM_IN_USE", realm(rep="realm_weak")) == []


# ── KEYCLOAK.REALM.NOT_ASSESSED ─────────────────────────────────────────────────
def test_not_assessed_reports_denied_endpoints():
    r = realm(collection={"admin/realms/myrealm/clients": _FORBIDDEN})
    hits = fire("KEYCLOAK.REALM.NOT_ASSESSED", r)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "clients" in hits[0].observation


def test_not_assessed_quiet_when_all_ok():
    assert fire("KEYCLOAK.REALM.NOT_ASSESSED", realm()) == []


# ── NHI extraction ──────────────────────────────────────────────────────────────
def _kinds(resources) -> dict:
    out: dict = {}
    for r in resources:
        out[r.kind] = out.get(r.kind, 0) + 1
    return out


def _derived() -> Collected:
    base = [client("spa-app"), client("legacy-ropc"), client("hardened-app")]
    return derive_identities("keycloak", Collected(resources=list(base)))


def test_keycloak_has_an_extractor():
    assert "keycloak" in IDENTITY_EXTRACTORS


def test_public_client_has_no_credential_confidential_does():
    col = _derived()
    creds = [r for r in col.resources if r.kind == "credential"]
    owners = {c.raw["owner_ext_id"] for c in creds}
    spa = next(r for r in col.resources
               if r.kind == "identity" and r.name == "myrealm/spa-app")
    ropc = next(r for r in col.resources
                if r.kind == "identity" and r.raw.get("identity_type") == "oauth_client"
                and r.name == "myrealm/legacy-ropc")
    assert spa.ext_id not in owners        # public client → no client_secret (absence)
    assert ropc.ext_id in owners           # confidential client → a client_secret credential
    assert all(c.raw["plaintext"] is False for c in creds)
    # no secret value leaked into any NHI resource
    assert "SHOULD-NEVER-BE-STORED" not in json.dumps([r.raw for r in col.resources])


def test_service_account_is_its_own_identity():
    col = _derived()
    sas = [r for r in col.resources if r.kind == "identity"
           and r.labels.get("identity_type") == "service_account"]
    assert len(sas) == 1
    assert sas[0].name == "myrealm/service-account-legacy-ropc"


def test_default_scopes_become_grants_linked_to_the_client():
    col = _derived()
    ropc = next(r for r in col.resources
                if r.kind == "identity" and r.name == "myrealm/legacy-ropc")
    grants = [g for g in col.resources
              if g.kind == "grant" and g.raw["identity_ext_id"] == ropc.ext_id]
    assert {"profile", "email", "roles"} == {g.raw["target"] for g in grants}
    edge_kinds = {(e.src_ext_id, e.kind, e.dst_ext_id) for e in col.edges}
    for g in grants:
        assert (g.ext_id, "granted_to", ropc.ext_id) in edge_kinds
